#!/usr/bin/env python3
"""Rewrite build/pf-version.env from the Dockerfile's FROM line, after Dependabot bumped it.

  tools/pf-version-sync.py             # rewrite the env file; print what changed
  tools/pf-version-sync.py --dry-run   # print what would change, write nothing

The Dockerfile's FROM is the one literal the env file does not own, kept so that Dependabot can bump
the base image the way it bumps anything else. This is the other half of that arrangement: after a
bump, it reads `FROM pingidentity/pingfederate:<tag>@sha256:<digest>` and writes PF_IMAGE,
PF_IMAGE_DIGEST and the versions that follow from the tag - PF_VERSION (the leading major.minor.patch),
PF_SDK_MAVEN_VERSION (PF_VERSION.0, the SDK's Maven version convention) and
PF_TERRAFORM_PRODUCT_VERSION (major.minor) - back into the env file, changing only those values. The
file's comments and order stay as they are.

It does not touch the BOM, gm-api's pom or the Terraform default: tools/pf-version-check.py names
each of those when they disagree, and a version bump is a change to review, not to automate away.
The check is what a bump must then pass.

Exit status: 0 (with "unchanged" or the rewritten keys), 2 when the Dockerfile or env file cannot be
read or the FROM line is not tag@digest.
"""
import argparse
import os
import re
import sys

ENV_FILE = "build/pf-version.env"
DOCKERFILE = "build/pingfederate/Dockerfile"
FROM_RE = re.compile(r"^FROM\s+(pingidentity/pingfederate:([0-9]+\.[0-9]+\.[0-9]+)[A-Za-z0-9._-]*)@(sha256:[0-9a-f]{64})\s*$", re.M)


def values_from_dockerfile(text):
    """The env values the FROM line implies, or a ValueError saying why it cannot."""
    m = FROM_RE.search(text)
    if not m:
        raise ValueError("no `FROM pingidentity/pingfederate:<tag>@sha256:<digest>` line (the digest is required)")
    image, version, digest = m.group(1), m.group(2), m.group(3)
    major_minor = ".".join(version.split(".")[:2])
    return {
        "PF_VERSION": version,
        "PF_SDK_MAVEN_VERSION": version + ".0",
        "PF_IMAGE": image,
        "PF_IMAGE_DIGEST": digest,
        "PF_TERRAFORM_PRODUCT_VERSION": major_minor,
    }


def rewrite(env_text, values):
    """The env file with each KEY=VALUE line's value replaced; comments and order kept. Returns the
    new text and the keys whose value changed. A key the file lacks is an error: the file documents
    each key, and a silent append would leave it undocumented."""
    changed = []
    seen = set()
    out = []
    for line in env_text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k, v = stripped.split("=", 1)
            k = k.strip()
            if k in values:
                seen.add(k)
                if v.strip() != values[k]:
                    changed.append(k)
                    line = f"{k}={values[k]}\n"
        out.append(line)
    missing = [k for k in values if k not in seen]
    if missing:
        raise ValueError(f"{ENV_FILE} lacks {', '.join(missing)}")
    return "".join(out), changed


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="the repo root (default: the parent of tools/)")
    ap.add_argument("--dry-run", action="store_true", help="print what would change, write nothing")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    try:
        with open(os.path.join(root, DOCKERFILE), encoding="utf-8") as f:
            values = values_from_dockerfile(f.read())
        with open(os.path.join(root, ENV_FILE), encoding="utf-8") as f:
            env_text = f.read()
        new_text, changed = rewrite(env_text, values)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not changed:
        print(f"unchanged: {ENV_FILE} already matches {DOCKERFILE}'s FROM ({values['PF_IMAGE']})")
        return 0
    for k in changed:
        print(f"{'would set' if args.dry_run else 'set'} {k}={values[k]}")
    if not args.dry_run:
        with open(os.path.join(root, ENV_FILE), "w", encoding="utf-8") as f:
            f.write(new_text)
        print(f"rewrote {ENV_FILE}; now run tools/pf-version-check.py for what else must follow")
    return 0


if __name__ == "__main__":
    sys.exit(main())
