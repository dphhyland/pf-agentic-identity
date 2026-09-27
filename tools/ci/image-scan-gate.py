#!/usr/bin/env python3
"""Fail on a HIGH or CRITICAL vulnerability that this repository's layers bring into the image; report the rest.

  tools/ci/image-scan-gate.py --image IMAGE.json --base BASE.json [--label NAME] [--summary FILE]

Both files are grype's JSON output (`grype sbom:<syft json> -o json`): IMAGE for the image the Dockerfile's
capability target built, BASE for the pingidentity/pingfederate image build/pf-version.env pins, scanned the
same way with the same configuration (.github/grype.yaml). A finding is PingFederate's when the base image's scan
has the same vulnerability in the same package at the same version - its jars, which the assembled war carries
as well, and its Go and Java runtimes. Everything else is ours: the jars stage-modules.sh stages, anything the
assembler adds to the war, and the Alpine packages the Dockerfile's `apk add` installs. Ours at HIGH or CRITICAL
fails; PingFederate's are counted and listed without failing, because a PingFederate version bump is what fixes
them (build/pingfederate/README.md, "Scanning the image").

The base image ships without apk's installed database (/lib/apk/db/installed), so a scan of it sees no Alpine
package at all, and the Dockerfile's `apk add` reinstalls every package the base's world file names at the
versions Alpine publishes that day (F-0220). Those packages are therefore ours by this rule too - they are in a
layer the Dockerfile writes - and an unfixable finding in one is accepted in .github/grype.yaml, with its reason,
rather than passed by a rule written here.

A finding .github/grype.yaml accepts is not a match in grype's output: it is listed under ignoredMatches, with
the rule and its reason, and this reports each one so an accepted finding stays in view. A rule that matched
nothing in this image is reported as well, so one that has outlived its reason is noticed; it does not fail.

Exit status: 0 when nothing of ours is HIGH or CRITICAL, 1 when something is, 2 when a report cannot be read.
"""
import argparse
import json
import sys
from collections import Counter

FAILING = ("Critical", "High")
ORDER = ("Critical", "High", "Medium", "Low", "Negligible", "Unknown")


def load(path):
    """grype's JSON report at path, or a ValueError saying why it is not one."""
    try:
        with open(path, encoding="utf-8") as f:
            report = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"{path}: {e}") from e
    if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
        raise ValueError(f"{path}: not a grype JSON report (no matches list)")
    return report


def key(match):
    """What makes two findings the same one: the vulnerability, and the package it is in, by name, version and type."""
    a = match["artifact"]
    return (match["vulnerability"]["id"], a["name"], a["version"], a.get("type", ""))


def locations(match):
    return sorted({loc.get("path", "") for loc in match["artifact"].get("locations", []) if loc.get("path")})


def group(matches):
    """One row per finding, with every location it was found at; in severity order, then by id and package."""
    rows = {}
    for m in matches:
        k = key(m)
        row = rows.setdefault(k, {"id": k[0], "package": k[1], "version": k[2], "type": k[3],
                                  "severity": m["vulnerability"].get("severity") or "Unknown",
                                  "fix": ", ".join(m["vulnerability"].get("fix", {}).get("versions") or []),
                                  "locations": set()})
        row["locations"].update(locations(m))
    rank = {s: i for i, s in enumerate(ORDER)}
    return sorted(rows.values(), key=lambda r: (rank.get(r["severity"], len(ORDER)), r["id"], r["package"], r["version"]))


def classify(image, base):
    """(ours, pingfederate's) rows of image's matches, by whether base has the same finding."""
    theirs = {key(m) for m in base["matches"]} | {key(m) for m in base.get("ignoredMatches", [])}
    ours = [m for m in image["matches"] if key(m) not in theirs]
    pf = [m for m in image["matches"] if key(m) in theirs]
    return group(ours), group(pf)


def ignored(image):
    """Each accepted finding, with the reason its rule gives, and each rule that matched nothing."""
    rows = []
    used = set()
    for m in image.get("ignoredMatches", []):
        reasons = []
        for rule in m.get("appliedIgnoreRules", []):
            reasons.append(rule.get("reason") or "(no reason given)")
            used.add(_rule_key(rule))
        k = key(m)
        rows.append({"id": k[0], "package": k[1], "version": k[2], "severity": m["vulnerability"].get("severity") or "Unknown",
                     "locations": locations(m), "reason": "; ".join(sorted(set(reasons)))})
    configured = image.get("descriptor", {}).get("configuration", {}).get("ignore") or []
    # grype echoes each applied rule without some of its fields (a package's location, for one), so a rule is
    # known by the vulnerability and the package name and version it names. Only rules with a reason are this
    # repository's: grype adds its own defaults (kernel headers and the like), which give none.
    unused = [rule for rule in configured if rule.get("reason") and _rule_key(rule) not in used]
    dedup = {}
    for r in rows:
        d = dedup.setdefault((r["id"], r["package"], r["version"]), dict(r, locations=set()))
        d["locations"].update(r["locations"])
    return sorted(dedup.values(), key=lambda r: (r["id"], r["package"])), unused


def _rule_key(rule):
    pkg = rule.get("package") or {}
    return (rule.get("vulnerability") or "", pkg.get("name") or "", pkg.get("version") or "")


def counts(rows):
    c = Counter(r["severity"] for r in rows)
    return ", ".join(f"{c[s]} {s.lower()}" for s in ORDER if c[s]) or "none"


def table(rows, with_reason=False):
    head = "| Severity | Vulnerability | Package | Version | Fixed in | Where |" if not with_reason else \
        "| Severity | Vulnerability | Package | Version | Where | Reason |"
    lines = [head, "|" + "---|" * (6)]
    for r in rows:
        where = "<br>".join(f"`{p}`" for p in sorted(r["locations"])[:4])
        more = len(r["locations"]) - 4
        if more > 0:
            where += f"<br>and {more} more"
        last = r["reason"] if with_reason else (r.get("fix") or "not fixed")
        if with_reason:
            lines.append(f"| {r['severity']} | {r['id']} | {r['package']} | {r['version']} | {where} | {last} |")
        else:
            lines.append(f"| {r['severity']} | {r['id']} | {r['package']} | {r['version']} | {last} | {where} |")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--image", required=True, help="grype JSON report of the image built from the Dockerfile")
    ap.add_argument("--base", required=True, help="grype JSON report of the pinned base image")
    ap.add_argument("--label", default="image", help="what to call the image in the report")
    ap.add_argument("--summary", help="append the report, as Markdown, to this file (the job's step summary)")
    args = ap.parse_args(argv)
    try:
        image, base = load(args.image), load(args.base)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    ours, pf = classify(image, base)
    accepted, unused = ignored(image)
    failing = [r for r in ours if r["severity"] in FAILING]

    out = [f"## Vulnerabilities in {args.label}", ""]
    if failing:
        out.append(f"**Failed**: {len(failing)} HIGH or CRITICAL finding(s) in the layers this repository adds. "
                   "Fix them (a newer dependency, a rebuilt package), or accept one in .github/grype.yaml with its reason.")
    else:
        out.append("**Passed**: nothing HIGH or CRITICAL in the layers this repository adds.")
    out += ["", f"- ours (this repository's jars, the assembled war, the Alpine packages the Dockerfile installs): {counts(ours)}",
            f"- PingFederate's (the same finding in the pinned base image; reported, not failed - a PingFederate bump fixes them): {counts(pf)}",
            f"- accepted in .github/grype.yaml: {len(accepted)}", ""]
    if ours:
        out += ["### Ours", "", table(ours), ""]
    if accepted:
        out += ["### Accepted in .github/grype.yaml", "", table(accepted, with_reason=True), ""]
    for rule in unused:
        pkg = rule.get("package") or {}
        out.append(f"- note: the rule for {rule.get('vulnerability') or '(any)'} in {pkg.get('name') or '(any package)'} "
                   f"{pkg.get('version') or ''} matched nothing in this image; remove it if its reason no longer holds.")
    if unused:
        out.append("")
    if pf:
        out += ["<details><summary>PingFederate's findings</summary>", "", table(pf), "", "</details>", ""]
    text = "\n".join(out)
    print(text)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    return 1 if failing else 0


if __name__ == "__main__":
    sys.exit(main())
