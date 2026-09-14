#!/usr/bin/env python3
"""Generate docs/coverage-dashboard.md and .html from jacoco, surefire and @Requirement annotations.

Two questions, one page:

  1. Are the security-critical decision methods covered? Read from each module's
     target/site/jacoco/jacoco.xml, cross-referenced against the <include> patterns in that
     module's pom, which are the gate.
  2. Are the standards this repo claims actually pinned by a test? Read from @Requirement
     annotations in test sources, joined against the ids the conformance matrices declare.

Deliberately reads the gate out of the poms rather than taking a hardcoded list: the pom is what
CI enforces, so a method quietly dropped from a rule shows up here as a shrinking gate rather
than staying invisible. Test counts come from surefire's own XML for the same reason - a number
somebody typed into a README went stale twice.

Both outputs render from one data pass, so they cannot disagree with each other.

Usage:
    tools/coverage-report.py            regenerate docs/coverage-dashboard.md and .html
    tools/coverage-report.py --check    exit 1 if either committed dashboard is stale

Run `mvn -o verify` first; without it the jacoco and surefire reports are missing or stale and
the numbers below are whatever the last build left behind.
"""

import argparse
import html
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "docs" / "coverage-dashboard.md"
DASHBOARD_HTML = ROOT / "docs" / "coverage-dashboard.html"

# servlets/oidf-war is a war assembly with no Java; services/harness is verification CLIs, not
# production code. Neither is gated, and saying so here stops them reading as an oversight.
NOT_GATED = {
    "bom": "dependency-version manifest, no source",
    "servlets/oidf-war": "war assembly, no Java source",
    "services/harness": "manual self-verify harnesses, not production code",
}

JACOCO_BLOCK_RE = re.compile(
    r"<artifactId>jacoco-maven-plugin</artifactId>(.*?)</plugin>", re.S)
INCLUDE_RE = re.compile(r"<include>([^<]+)</include>")
# (Lcom/foo/Bar;I)V -> ['com.foo.Bar', 'int'] — enough to tell two overloads apart.
DESC_RE = re.compile(r"\[*(?:L([^;]+);|([BCDFIJSZ]))")
PRIMITIVES = {"B": "byte", "C": "char", "D": "double", "F": "float",
              "I": "int", "J": "long", "S": "short", "Z": "boolean"}
REQUIREMENT_RE = re.compile(r'@Requirement\s*\(\s*(?:\{)?\s*((?:"[^"]*"\s*,?\s*)+)', re.S)
TEST_METHOD_RE = re.compile(r"\bvoid\s+(\w+)\s*\(")
TYPE_DECL_RE = re.compile(r"\b(?:class|interface|enum|record)\s+\w+")
ANNOTATION = ROOT / ("libs/conformance/src/main/java/com/pingidentity/ps/oidf/"
                     "conformance/Requirement.java")
CODE_TAG_RE = re.compile(r"\{@code ([^}]+)\}")
# Dots are legal in a prefix: AUTHZEN-1.0 carries its version. Lowercase is not, which is what
# keeps SdJwt.java and the other file and method names in that javadoc out of the vocabulary.
PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9.-]*$")
# Both appear in the javadoc as prose, not as prefixes: "SPEC §clause" is the id template and
# RUNTIME names a RetentionPolicy. Everything else uppercase in a {@code} tag is a real prefix.
NOT_A_PREFIX = {"SPEC", "RUNTIME"}

MATRIX_DOCS = ("docs/client-attestation-architecture.md",
               "docs/ai-agent-attestation-profile-1_0.md")
# A matrix row declares its id as the first cell, backticked and nothing else. Restricting to that
# shape keeps ids cited in prose out of the denominator.
MATRIX_ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|", re.M)

# What no coverage number can say. Rendered verbatim into both outputs so a green page never
# reads as covering them.
NOT_ESTABLISHED = [
    ("The token-endpoint filters may not run at all.",
     "There is no `@WebFilter` anywhere in the repo and `servlets/oidf-war`'s `web.xml` registers "
     "none — `ClientAttestationAuthFilter` and `TokenEndpointAutoRegistrationFilter` are activated "
     "by a hand edit to `pf-runtime.war`'s `web.xml` in the deploying repo. A gate on `doFilter(` "
     "proves the filter works, never that it runs."),
    ("Initial-grant RAR containment lives in a PingAuthorize policy file.",
     "`AttestationAwareRarProcessor.enrich` does not call containment; it forwards the attested "
     "ceiling and policy enforces `requested ⊆ attested` outside this repo. Its three permissive "
     "switches (`failOpenOnError`, `denyOnNonPermit`, `allowClientAssertedPrincipal`) have "
     "*defaults* that are the security property, which no coverage counter expresses."),
    ("`OutboundUrlPolicy`'s `allowHttp` / `allowPrivateNetworks` come from environment variables,",
     "so the SSRF posture of a running deployment is not a property of this code."),
]


def modules():
    """Every reactor module, in the order the root pom lists them."""
    root_pom = (ROOT / "pom.xml").read_text()
    return re.findall(r"<module>([^<]+)</module>", root_pom)


def gate_includes(module):
    """The <include> patterns in a module's jacoco check rule — i.e. what CI actually enforces.

    Scoped to the jacoco plugin block on purpose: `<include>` is a common element, and reading the
    whole pom also picks up maven-shade's artifact includes, which are not coverage patterns and
    match no method.
    """
    pom = ROOT / module / "pom.xml"
    if not pom.is_file():
        return []
    block = JACOCO_BLOCK_RE.search(pom.read_text())
    if not block:
        return []
    return [m.strip() for m in INCLUDE_RE.findall(block.group(1))]


def coverage(module):
    """Method-level coverage keyed by 'fully.qualified.Class.method'."""
    report = ROOT / module / "target" / "site" / "jacoco" / "jacoco.xml"
    if not report.is_file():
        return None, {}
    # jacoco emits a DOCTYPE pointing at a remote DTD; resolving it would make this network-bound.
    parser = ET.XMLParser()
    tree = ET.parse(report, parser=parser)
    root = tree.getroot()

    totals = {c.get("type"): (int(c.get("missed")), int(c.get("covered")))
              for c in root.findall("counter")}
    methods = {}
    for pkg in root.findall("package"):
        for cls in pkg.findall("class"):
            # Nested classes arrive as Outer$Nested; jacoco's own matcher treats the separator as a
            # dot, so normalise or every nested-class pattern silently matches nothing.
            fqcn = cls.get("name", "").replace("/", ".").replace("$", ".")
            for m in cls.findall("method"):
                counters = {c.get("type"): (int(c.get("missed")), int(c.get("covered")))
                            for c in m.findall("counter")}
                # Overloads share a name and each gets its own entry; keep every one rather than
                # letting the last write win, and keep the parameter types so a pattern that names
                # a signature can pick out the single overload jacoco selected.
                methods.setdefault(f"{fqcn}.{m.get('name')}", []).append(
                    {"counters": counters, "params": params_of(m.get("desc", ""))})
    return totals, methods


def tests(module):
    """(run, failures+errors, skipped) summed over the module's surefire reports, or None."""
    reports = list((ROOT / module / "target" / "surefire-reports").glob("TEST-*.xml"))
    if not reports:
        return None
    run = failed = skipped = 0
    for report in reports:
        suite = ET.parse(report).getroot()
        run += int(suite.get("tests", 0))
        failed += int(suite.get("failures", 0)) + int(suite.get("errors", 0))
        skipped += int(suite.get("skipped", 0))
    return run, failed, skipped


def params_of(desc):
    """JVM descriptor -> source-ish parameter type names, for telling overloads apart."""
    args = desc[1:desc.rfind(")")] if ")" in desc else ""
    return [(obj.replace("/", ".") if obj else PRIMITIVES.get(prim, prim))
            for obj, prim in DESC_RE.findall(args)]


def matches(pattern, key):
    """A jacoco include pattern (`a.b.C.method(*`) against our `a.b.C.method` key.

    Constructors are the trap: jacoco names them `<init>` in the XML, while an include pattern spells
    them `a.b.C.C(`. Matching naively marks every constructor pattern "not found", which reads as a
    failing gate on a build jacoco itself passed — so resolve that spelling here rather than reporting
    a disagreement with the tool that actually enforces the gate.
    """
    base = pattern.split("(")[0]
    if key == base:
        return True
    owner, _, member = base.rpartition(".")
    return bool(owner) and member == owner.rpartition(".")[2] and key == f"{owner}.<init>"


def selects(pattern, entry):
    """Whether a pattern's parameter prefix selects this particular overload.

    A pattern may name a signature (`C.C(com.foo.Bar*`) to gate one overload and not its siblings.
    Summing every overload there reports a failure on a method the gate never covered — a false
    alarm against the tool that actually enforces it.
    """
    _, _, params = pattern.partition("(")
    params = params.rstrip("*").strip()
    if not params:
        return True
    wanted = [p.strip() for p in params.split(",") if p.strip()]
    actual = entry["params"]
    return len(actual) >= len(wanted) and all(a == w for a, w in zip(actual, wanted))


def vocabulary():
    """The prefixes Requirement.java declares, read from Requirement.java.

    Hardcoding the list here would give the repo two vocabularies that drift apart, which is the
    exact failure the annotation exists to stop. Adding a prefix to the javadoc adds it here.
    """
    text = ANNOTATION.read_text()
    found = set()
    for tag in CODE_TAG_RE.findall(text):
        first = tag.strip().strip('"{').split()[0] if tag.strip() else ""
        if PREFIX_RE.match(first) and first not in NOT_A_PREFIX:
            found.add(first)
    return found


def matrix_rows():
    """Every conformance-matrix row that declares an id, in document order."""
    rows = []
    for name in MATRIX_DOCS:
        path = ROOT / name
        if not path.is_file():
            continue
        for rid in MATRIX_ROW_RE.findall(path.read_text(errors="replace")):
            if "§" in rid or " divergence " in rid or " item " in rid:
                rows.append((name, rid))
    return rows


def pins(rid, pinned):
    """The pinned ids that satisfy a matrix row.

    A row may be written at section granularity where the tests are finer - the CAS matrix says
    `CAS §4` while the tests pin `CAS §4.3`. A pinned id counts for a row when it is that row, or a
    strict refinement of it. Without this the coarse rows would read as uncovered while the tests
    that cover them sit one column away.
    """
    return [p for p in pinned
            if p == rid or p.startswith(rid + ".") or p.startswith(rid + "(")]


def requirements():
    """Every @Requirement id in test sources, mapped to the tests that pin it."""
    found = {}
    # Walk the reactor's modules, not the whole checkout: anything else under ROOT that happens to
    # carry a src/test tree (a vendored copy, a showcase, a scratch checkout) would otherwise count
    # every tag it contains again, and every number on the page would be silently inflated.
    paths = [p for module in modules()
             for p in (ROOT / module / "src" / "test").rglob("*.java")]
    for path in paths:
        text = path.read_text(errors="replace")
        if "@Requirement" not in text:
            continue
        for match in REQUIREMENT_RE.finditer(text):
            ids = re.findall(r'"([^"]+)"', match.group(1))
            tail = text[match.end():match.end() + 400]
            name = TEST_METHOD_RE.search(tail)
            # @Requirement is legal on a type as well as a method. On a type the next `void` is
            # some arbitrary test in the body, so naming it would credit one test with a tag that
            # covers the whole class - attribute those to the class instead.
            decl = TYPE_DECL_RE.search(tail)
            if decl and (not name or decl.start() < name.start()):
                test = path.stem
            else:
                test = f"{path.stem}#{name.group(1)}" if name else path.stem
            for rid in ids:
                found.setdefault(rid, []).append(test)
    return found


def spec_of(rid):
    return rid.split("§")[0].split(" divergence")[0].split(" item")[0].strip()


def pct(missed, covered):
    total = missed + covered
    return 100.0 if total == 0 else (covered / total) * 100.0


def collect():
    """One pass over the build outputs; both renderers read from this and nothing else."""
    mods = []
    for module in modules():
        entry = {"name": module, "not_gated": NOT_GATED.get(module), "tests": tests(module)}
        if module in NOT_GATED:
            mods.append(entry)
            continue
        includes = gate_includes(module)
        totals, methods = coverage(module)
        failing = []
        for pattern in includes:
            hits = [e for k, es in methods.items() if matches(pattern, k)
                    for e in es if selects(pattern, e)]
            if not hits:
                failing.append(f"{pattern} (not found in report)")
                continue
            # Every overload the pattern covers has to be clean, the same way jacoco checks them.
            line_missed = sum(h["counters"].get("LINE", (0, 0))[0] for h in hits)
            branch_missed = sum(h["counters"].get("BRANCH", (0, 0))[0] for h in hits)
            if line_missed or branch_missed:
                failing.append(f"{pattern} ({line_missed} line, {branch_missed} branch missed)")
        entry.update({
            "gated": len(includes),
            "failing": failing,
            "instruction": (pct(*totals["INSTRUCTION"])
                            if totals and "INSTRUCTION" in totals else None),
        })
        mods.append(entry)

    reqs = requirements()
    by_spec = {}
    for rid, tsts in sorted(reqs.items()):
        by_spec.setdefault(spec_of(rid), []).append((rid, sorted(tsts)))
    rows = {rid: doc for doc, rid in matrix_rows()}
    pinned = set(reqs)
    matrix = [(rid, doc, pins(rid, pinned)) for rid, doc in rows.items()]
    known = vocabulary()

    gated = [m for m in mods if not m["not_gated"] and m.get("gated")]
    all_tests = [m["tests"] for m in mods if m["tests"]]
    return {
        "modules": mods,
        "gated_total": sum(m["gated"] for m in gated),
        "failing_total": sum(len(m["failing"]) for m in gated),
        "tests": (sum(t[0] for t in all_tests), sum(t[1] for t in all_tests),
                  sum(t[2] for t in all_tests)),
        "requirements": reqs,
        "by_spec": by_spec,
        "matrix": matrix,
        "suspect": sorted(s for s in by_spec if s not in known),
    }


def render_md(d):
    out = []
    w = out.append

    w("# Coverage dashboard")
    w("")
    w("Generated by `tools/coverage-report.py` from each module's jacoco report and a scan of")
    w("`@Requirement` annotations. Do not edit by hand — CI regenerates it and fails if the")
    w("committed copy differs, which is what stops it drifting the way prose status tables do.")
    w("The same data renders to `coverage-dashboard.html` for reading in a browser.")
    w("")
    w("Run `mvn -o verify` before regenerating; the numbers are only as fresh as the last build.")
    w("")
    run, failed, skipped = d["tests"]
    w(f"**{run} tests, {failed} failed, {skipped} skipped** (surefire, summed over the reactor).")
    w("")

    w("## Critical-method gates")
    w("")
    w("Each module gates the methods that *decide* something — verify a signature, accept or")
    w("reject a credential, enforce a ceiling — at 100% line and branch. Plumbing and getters are")
    w("deliberately outside the gate: a blanket percentage rewards testing whatever is cheapest,")
    w("which says nothing about whether the security paths are the covered ones.")
    w("")
    w("| Module | Gated methods | Gate | Module instructions | Tests |")
    w("|---|---:|---|---:|---:|")

    ungated = []
    for m in d["modules"]:
        if m["not_gated"]:
            continue
        if not m.get("gated"):
            ungated.append(m["name"])
            continue
        status = "green" if not m["failing"] else f"**{len(m['failing'])} failing**"
        instr = f"{m['instruction']:.0f}%" if m["instruction"] is not None else "—"
        t = f"{m['tests'][0]}" if m["tests"] else "—"
        w(f"| `{m['name']}` | {m['gated']} | {status} | {instr} | {t} |")
        for f in m["failing"]:
            w(f"| | | `{f}` | | |")

    w("")
    w(f"**{d['gated_total']} methods gated across the reactor"
      + (f", {d['failing_total']} failing.**" if d["failing_total"] else ", all green.**"))
    w("")
    w("Module instruction coverage is context, not a target. A module can sit at 30% with every")
    w("decision method gated, and that is the intended shape.")
    w("")

    if ungated:
        w("### Not yet gated")
        w("")
        for module in ungated:
            w(f"- `{module}`")
        w("")
    if NOT_GATED:
        w("### Deliberately not gated")
        w("")
        for module, why in sorted(NOT_GATED.items()):
            w(f"- `{module}` — {why}")
        w("")

    reqs = d["requirements"]
    by_spec = d["by_spec"]
    w("## Conformance coverage")
    w("")
    w("A requirement is *pinned* when a test carries a `@Requirement` naming it. The id scheme, and")
    w("the three ways to get an id wrong, are documented on the annotation itself")
    w("(`libs/conformance/.../Requirement.java`) — most importantly that a test asserting a")
    w("*divergence* is tagged with the divergence, never with the clause it departs from.")
    w("")
    if not reqs:
        w("No `@Requirement` annotations found yet. Until tests carry them, conformance is asserted")
        w("in prose matrices and pinned by exactly one executable suite (`ProfileConformanceTest`),")
        w("so there is no fraction to report here — which is itself the finding.")
    else:
        w("| Specification | Requirements pinned | Tests |")
        w("|---|---:|---:|")
        for spec in sorted(by_spec):
            entries = by_spec[spec]
            note = " *(vendor interface, see below)*" if spec == "PF-SDK" else ""
            w(f"| {spec}{note} | {len(entries)} | {sum(len(t) for _, t in entries)} |")
        w("")
        w(f"**{len(reqs)} distinct requirements pinned by "
          f"{sum(len(t) for t in reqs.values())} tests.**")
        w("")
        matrix = d["matrix"]
        if matrix:
            unpinned = [(rid, doc) for rid, doc, p in matrix if not p]
            covered = len(matrix) - len(unpinned)
            w(f"**{covered} of {len(matrix)} conformance-matrix rows are pinned by a test.** The")
            w("denominator is the rows that declare an id in `docs/client-attestation-architecture.md`")
            w("and `docs/ai-agent-attestation-profile-1_0.md`. A row written at section granularity is")
            w("satisfied by a finer id beneath it, so `CAS §4` counts as pinned when a test pins")
            w("`CAS §4.3`.")
            w("")
            w("This is not a conformance score. A matrix row is one line of prose somebody wrote, not a")
            w("count of the clauses in the document behind it, and rows reading `—` because no clause id")
            w("could be verified are not in the denominator at all. It measures whether what this repo")
            w("*claims* is also *executed*.")
            if unpinned:
                w("")
                w("### Matrix rows nothing pins")
                w("")
                w("The work queue. Each is a row the docs claim and no test checks.")
                w("")
                for rid, doc in sorted(unpinned):
                    w(f"- `{rid}` — {doc.split('/')[-1]}")
        else:
            w("This counts what *is* pinned. There is no denominator yet: no conformance-matrix row")
            w("declares an id to join against, so read this as an inventory rather than a score.")
        if d["suspect"]:
            w("")
            w("### Ids with an undeclared prefix")
            w("")
            w("These prefixes are not in the vocabulary `Requirement.java` declares. A prefix nobody")
            w("declared is how a fabricated citation gets in, and how one clause ends up spelled two")
            w("ways — each spelling then reading as half-covered. Add the prefix to the annotation or")
            w("fix the id.")
            w("")
            for spec in d["suspect"]:
                ids = ", ".join(f"`{rid}`" for rid, _ in by_spec[spec])
                w(f"- **{spec}** — {ids}")
        if "PF-SDK" in by_spec:
            w("")
            w("`PF-SDK` ids name a vendor interface rather than a published specification, and")
            w("`docs/unverified.md` item 5 records that no PingFederate 13.x javadoc exists locally to")
            w("check them against. Real and worth pinning, but a weaker claim than an RFC.")
    w("")

    w("## What these gates do NOT establish")
    w("")
    w("Three guarantees in this system are configuration, not code. 100% coverage of the Java says")
    w("nothing about them, and a green dashboard must not be read as covering them:")
    w("")
    for lead, body in NOT_ESTABLISHED:
        w(f"- **{lead}** {body}")
    w("")
    w("These belong to the deployed probes (`services/harness`,")
    w("`plugins/rar-paz-plugin/probe-decision.sh`), not to any coverage number.")
    w("")

    return "\n".join(out) + "\n"


# --- HTML -------------------------------------------------------------------------------------

def inline(text):
    """Escape, then turn the markdown-ish `code`, *em* and **strong** used above into HTML."""
    text = html.escape(text, quote=False)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)
    text = re.sub(r"\*([^*]+)\*", r"<em>\1</em>", text)
    return text


CSS = """
:root {
  --bg: #F4F6F5; --surface: #FFFFFF; --line: #D9DEDC; --line-soft: #E8ECEA;
  --ink: #1A2024; --ink-2: #4C5860; --ink-3: #7A868D;
  --accent: #2C6B70; --accent-soft: #D8E9EA;
  --good: #2A7A4B; --good-soft: #DCEFE3; --warn: #9C6A12; --warn-soft: #F5EAD3;
  --crit: #B03A3A; --crit-soft: #F6DCDC;
  --sans: "IBM Plex Sans", "Helvetica Neue", Arial, sans-serif;
  --mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #131719; --surface: #1B2124; --line: #2E373B; --line-soft: #252D31;
    --ink: #E5EAE8; --ink-2: #AEB9BD; --ink-3: #7F8C92;
    --accent: #6FB8BC; --accent-soft: #1F3A3D;
    --good: #5FBF85; --good-soft: #1C3527; --warn: #E0A84A; --warn-soft: #3A2E15;
    --crit: #E06B6B; --crit-soft: #3D2020;
  }
}
:root[data-theme="dark"] {
  --bg: #131719; --surface: #1B2124; --line: #2E373B; --line-soft: #252D31;
  --ink: #E5EAE8; --ink-2: #AEB9BD; --ink-3: #7F8C92;
  --accent: #6FB8BC; --accent-soft: #1F3A3D;
  --good: #5FBF85; --good-soft: #1C3527; --warn: #E0A84A; --warn-soft: #3A2E15;
  --crit: #E06B6B; --crit-soft: #3D2020;
}
* { box-sizing: border-box; }
html { color-scheme: light dark; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 var(--sans); }
code { font-family: var(--mono); font-size: 0.92em; }
a { color: var(--accent); }
main { max-width: 1180px; margin: 0 auto; padding: 32px 24px 64px; display: grid; gap: 40px; }
header { display: flex; flex-wrap: wrap; align-items: baseline; justify-content: space-between; gap: 8px 24px; }
h1 { font-size: 22px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
h2 { font-size: 17px; font-weight: 600; margin: 0 0 6px; letter-spacing: -0.005em; text-wrap: balance; }
h3 { font-size: 13px; font-weight: 600; margin: 24px 0 8px; color: var(--ink-2); text-transform: uppercase; letter-spacing: 0.06em; }
p { margin: 0; max-width: 72ch; color: var(--ink-2); }
p.lede { color: var(--ink-2); }
.meta { font-size: 13px; color: var(--ink-3); font-family: var(--mono); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }
.tile { background: var(--surface); border: 1px solid var(--line); padding: 16px 18px 14px; display: grid; gap: 2px; }
.tile .label { font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-3); }
.tile .value { font-size: 34px; font-weight: 600; line-height: 1.1; letter-spacing: -0.02em; }
.tile .value small { font-size: 18px; font-weight: 500; color: var(--ink-3); letter-spacing: 0; }
.tile .note { font-size: 13px; color: var(--ink-2); margin-top: 6px; }
.pill { display: inline-flex; align-items: center; gap: 6px; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 600; letter-spacing: 0.02em; white-space: nowrap; }
.pill::before { content: ""; width: 7px; height: 7px; border-radius: 50%; background: currentColor; }
.pill.good { color: var(--good); background: var(--good-soft); }
.pill.warn { color: var(--warn); background: var(--warn-soft); }
.pill.crit { color: var(--crit); background: var(--crit-soft); }
.pill.muted { color: var(--ink-2); background: var(--line-soft); }
.pill.muted::before { display: none; }
section > p + p { margin-top: 8px; }
.tablewrap { overflow-x: auto; margin-top: 14px; background: var(--surface); border: 1px solid var(--line); }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 9px 14px; border-top: 1px solid var(--line-soft); vertical-align: top; }
thead th { border-top: 0; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-3); font-weight: 600; }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
td code { white-space: nowrap; }
tr.fail td { padding-top: 0; border-top: 0; color: var(--crit); font-family: var(--mono); font-size: 13px; }
.bar { display: inline-grid; grid-template-columns: 96px auto; align-items: center; gap: 10px; }
.bar i { display: block; height: 6px; background: var(--line-soft); border-radius: 3px; overflow: hidden; }
.bar i b { display: block; height: 100%; background: var(--accent); border-radius: 3px; }
.bar span { font-variant-numeric: tabular-nums; min-width: 3.5ch; text-align: right; }
.two { display: grid; grid-template-columns: 1fr; gap: 32px; }
@media (min-width: 900px) { .two { grid-template-columns: 1.15fr 1fr; } }
ul.plain { margin: 8px 0 0; padding: 0 0 0 18px; color: var(--ink-2); }
ul.plain li { margin: 3px 0; }
ul.plain li::marker { color: var(--ink-3); }
.filter { display: flex; gap: 10px; align-items: center; margin-top: 14px; }
.filter input { font: 14px var(--mono); padding: 7px 10px; border: 1px solid var(--line); background: var(--surface); color: var(--ink); width: min(100%, 360px); }
.filter input:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }
.filter .count { font-size: 13px; color: var(--ink-3); font-variant-numeric: tabular-nums; }
details.spec { border-top: 1px solid var(--line-soft); }
details.spec:first-of-type { border-top: 0; }
details.spec summary { list-style: none; cursor: pointer; display: grid; grid-template-columns: 1fr auto auto 18px; gap: 16px; align-items: center; padding: 9px 14px; font-size: 14px; }
details.spec summary::-webkit-details-marker { display: none; }
details.spec summary:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }
details.spec summary .n { font-variant-numeric: tabular-nums; color: var(--ink-2); min-width: 9ch; text-align: right; }
details.spec summary .chev { color: var(--ink-3); transition: transform 120ms; }
details.spec[open] summary .chev { transform: rotate(90deg); }
details.spec .ids { padding: 0 14px 12px 14px; display: grid; gap: 4px; font-size: 13px; }
details.spec .ids div { display: grid; grid-template-columns: minmax(200px, 0.6fr) 1fr; gap: 12px; color: var(--ink-2); }
details.spec .ids div code:first-child { color: var(--ink); }
details.spec .ids .t { font-family: var(--mono); font-size: 12px; color: var(--ink-3); overflow-wrap: anywhere; }
details.spec[hidden] { display: none; }
.speclist { background: var(--surface); border: 1px solid var(--line); margin-top: 10px; }
.speclist .head { display: grid; grid-template-columns: 1fr auto auto 18px; gap: 16px; padding: 8px 14px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-3); border-bottom: 1px solid var(--line-soft); font-weight: 600; }
.speclist .head .n { min-width: 9ch; text-align: right; }
.queue { margin-top: 12px; display: grid; gap: 6px; }
.queue div { display: grid; grid-template-columns: auto 1fr; gap: 12px; align-items: baseline; font-size: 14px; }
.queue .doc { color: var(--ink-3); font-size: 13px; }
.callout { border: 1px solid var(--line); background: var(--surface); padding: 18px 20px; display: grid; gap: 12px; }
.callout .item { display: grid; gap: 2px; max-width: 80ch; }
.callout .item strong { color: var(--ink); }
.callout .tag { font-size: 12px; text-transform: uppercase; letter-spacing: 0.06em; color: var(--warn); font-weight: 600; }
.legend { font-size: 13px; color: var(--ink-3); margin-top: 8px; }
footer { font-size: 13px; color: var(--ink-3); border-top: 1px solid var(--line); padding-top: 16px; }
@media (prefers-reduced-motion: reduce) { details.spec summary .chev { transition: none; } }
"""

JS = """
(function () {
  var q = document.getElementById('q');
  if (!q) return;
  var specs = Array.prototype.slice.call(document.querySelectorAll('details.spec'));
  var count = document.getElementById('qcount');
  var total = specs.reduce(function (n, s) { return n + s.querySelectorAll('.ids > div').length; }, 0);
  function apply() {
    var needle = q.value.trim().toLowerCase();
    var shown = 0;
    specs.forEach(function (s) {
      var rows = s.querySelectorAll('.ids > div'), any = false;
      rows.forEach(function (r) {
        var hit = !needle || r.textContent.toLowerCase().indexOf(needle) !== -1;
        r.hidden = !hit; if (hit) { any = true; shown++; }
      });
      s.hidden = !any;
      if (needle && any) s.open = true;
    });
    count.textContent = needle ? shown + ' of ' + total + ' ids' : total + ' ids';
  }
  q.addEventListener('input', apply);
  apply();
})();
"""


def render_html(d):
    out = []
    w = out.append
    e = html.escape
    run, failed, skipped = d["tests"]
    reqs = d["requirements"]
    by_spec = d["by_spec"]
    matrix = d["matrix"]
    unpinned = sorted((rid, doc) for rid, doc, p in matrix if not p)
    covered = len(matrix) - len(unpinned)
    n_tests_pinning = sum(len(t) for t in reqs.values())

    w("<title>pf-agentic-identity Coverage</title>")
    w('<link rel="preconnect" href="https://fonts.googleapis.com">')
    w('<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap">')
    w(f"<style>{CSS}</style>")
    w("<main>")

    # Header
    w("<header>")
    w("<div><h1>Coverage and conformance</h1>"
      "<p class=\"lede\">Are the methods that decide something covered, and is what the docs claim "
      "also executed? Generated from jacoco, surefire and the <code>@Requirement</code> "
      "annotations; CI fails if this page drifts from the build.</p></div>")
    w("<div class=\"meta\">tools/coverage-report.py · run <code>mvn -o verify</code> first</div>")
    w("</header>")

    # Tiles
    test_pill = ('<span class="pill good">passing</span>' if failed == 0
                 else f'<span class="pill crit">{failed} failing</span>')
    gate_pill = ('<span class="pill good">all green</span>' if d["failing_total"] == 0
                 else f'<span class="pill crit">{d["failing_total"]} failing</span>')
    w('<section class="tiles">')
    w(f'<div class="tile"><span class="label">Tests</span><span class="value">{run}</span>'
      f'<span class="note">{test_pill} &nbsp; {skipped} skipped</span></div>')
    w(f'<div class="tile"><span class="label">Critical methods gated</span>'
      f'<span class="value">{d["gated_total"]}</span>'
      f'<span class="note">{gate_pill} &nbsp; 100% line and branch</span></div>')
    w(f'<div class="tile"><span class="label">Requirements pinned</span>'
      f'<span class="value">{len(reqs)}</span>'
      f'<span class="note">by {n_tests_pinning} tests across {len(by_spec)} specifications</span></div>')
    if matrix:
        share = covered / len(matrix) * 100 if matrix else 0
        w(f'<div class="tile"><span class="label">Matrix rows pinned</span>'
          f'<span class="value">{covered}<small> / {len(matrix)}</small></span>'
          f'<span class="note">{share:.0f}% of what the docs claim is checked by a test</span></div>')
    w("</section>")

    # Gates
    w('<section>')
    w("<h2>Critical-method gates</h2>")
    w("<p>Each module gates the methods that <em>decide</em> something — verify a signature, accept "
      "or reject a credential, enforce a ceiling — at 100% line and branch. Plumbing and getters "
      "sit outside the gate on purpose: a blanket percentage rewards testing whatever is cheapest.</p>")
    w('<div class="tablewrap"><table>')
    w("<thead><tr><th>Module</th><th class=\"num\">Gated methods</th><th>Gate</th>"
      "<th>Module instructions</th><th class=\"num\">Tests</th></tr></thead><tbody>")
    ungated = []
    for m in d["modules"]:
        if m["not_gated"]:
            continue
        if not m.get("gated"):
            ungated.append(m["name"])
            continue
        pill = ('<span class="pill good">green</span>' if not m["failing"]
                else f'<span class="pill crit">{len(m["failing"])} failing</span>')
        if m["instruction"] is not None:
            bar = (f'<span class="bar"><i><b style="width:{m["instruction"]:.0f}%"></b></i>'
                   f'<span>{m["instruction"]:.0f}%</span></span>')
        else:
            bar = "—"
        t = str(m["tests"][0]) if m["tests"] else "—"
        w(f'<tr><td><code>{e(m["name"])}</code></td><td class="num">{m["gated"]}</td>'
          f'<td>{pill}</td><td>{bar}</td><td class="num">{t}</td></tr>')
        for f in m["failing"]:
            w(f'<tr class="fail"><td></td><td colspan="4">{e(f)}</td></tr>')
    w("</tbody></table></div>")
    w('<p class="legend">Module instruction coverage is context, not a target. A module can sit at '
      '30% with every decision method gated, and that is the intended shape.</p>')
    if ungated:
        w("<h3>Not yet gated</h3><ul class=\"plain\">")
        for module in ungated:
            w(f"<li><code>{e(module)}</code></li>")
        w("</ul>")
    w("<h3>Deliberately not gated</h3><ul class=\"plain\">")
    for module, why in sorted(NOT_GATED.items()):
        w(f"<li><code>{e(module)}</code> — {e(why)}</li>")
    w("</ul></section>")

    # Conformance
    w('<section class="two">')
    w("<div>")
    w("<h2>Conformance coverage</h2>")
    w("<p>A requirement is <em>pinned</em> when a test carries a <code>@Requirement</code> naming "
      "it. A test asserting a <em>divergence</em> is tagged with the divergence, never with the "
      "clause it departs from — the scheme lives on the annotation itself.</p>")
    if not reqs:
        w("<p>No <code>@Requirement</code> annotations found yet.</p>")
    else:
        w('<div class="filter"><label for="q" class="meta">filter</label>'
          '<input id="q" type="search" placeholder="RFC9449 §4.3, divergence, ActChainTest…" '
          'autocomplete="off"><span class="count" id="qcount"></span></div>')
        w('<div class="speclist">')
        w('<div class="head"><span>Specification</span><span class="n">Requirements</span>'
          '<span class="n">Tests</span><span></span></div>')
        for spec in sorted(by_spec):
            entries = by_spec[spec]
            n_t = sum(len(t) for _, t in entries)
            vendor = ' <span class="pill muted">vendor interface</span>' if spec == "PF-SDK" else ""
            undecl = ' <span class="pill warn">undeclared prefix</span>' if spec in d["suspect"] else ""
            w(f'<details class="spec"><summary><span>{e(spec)}{vendor}{undecl}</span>'
              f'<span class="n">{len(entries)}</span><span class="n">{n_t}</span>'
              f'<span class="chev">›</span></summary><div class="ids">')
            for rid, tsts in entries:
                w(f'<div><code>{e(rid)}</code><span class="t">{e(", ".join(tsts))}</span></div>')
            w("</div></details>")
        w("</div>")
        w(f'<p class="legend">{len(reqs)} distinct requirements pinned by {n_tests_pinning} tests.'
          + (" <code>PF-SDK</code> names a vendor interface with no local javadoc to check against "
             "(unverified.md item 5): real, but a weaker claim than an RFC." if "PF-SDK" in by_spec else "")
          + "</p>")
    w("</div>")

    w("<div>")
    w("<h2>What the docs claim</h2>")
    if matrix:
        w(f"<p><strong>{covered} of {len(matrix)}</strong> conformance-matrix rows are pinned by a "
          "test. The denominator is the rows that declare an id in the architecture doc and the "
          "profile. A row written at section granularity is satisfied by a finer id beneath it, so "
          "<code>CAS §4</code> counts when a test pins <code>CAS §4.3</code>.</p>")
        w("<p>Not a conformance score: a row is one line of prose somebody wrote, not a count of "
          "the clauses behind it, and rows with no verifiable id are outside the denominator. It "
          "measures whether what this repo <em>claims</em> is also <em>executed</em>.</p>")
        if unpinned:
            w("<h3>Rows nothing pins</h3>")
            w('<div class="queue">')
            for rid, doc in unpinned:
                w(f'<div><code>{e(rid)}</code><span class="doc">{e(doc.split("/")[-1])}</span></div>')
            w("</div>")
        else:
            w('<p><span class="pill good">every declared row is pinned</span></p>')
    else:
        w("<p>No conformance-matrix row declares an id yet, so there is no denominator.</p>")
    if d["suspect"]:
        w("<h3>Ids with an undeclared prefix</h3>")
        w("<p>Not in the vocabulary <code>Requirement.java</code> declares. An undeclared prefix "
          "is how a fabricated citation gets in, and how one clause ends up spelled two ways.</p>")
        w('<div class="queue">')
        for spec in d["suspect"]:
            for rid, _ in by_spec[spec]:
                w(f'<div><code>{e(rid)}</code><span class="doc">{e(spec)}</span></div>')
        w("</div>")
    w("</div>")
    w("</section>")

    # Not established
    w("<section>")
    w("<h2>What these gates do not establish</h2>")
    w("<p>Three guarantees in this system are configuration, not code. Full coverage of the Java "
      "says nothing about them, and a green page must not be read as covering them.</p>")
    w('<div class="callout" style="margin-top:14px">')
    for lead, body in NOT_ESTABLISHED:
        w(f'<div class="item"><span class="tag">configuration, not code</span>'
          f'<strong>{inline(lead)}</strong><span>{inline(body)}</span></div>')
    w("</div>")
    w('<p class="legend">These belong to the deployed probes (<code>services/harness</code>, '
      '<code>plugins/rar-paz-plugin/probe-decision.sh</code>), not to any coverage number.</p>')
    w("</section>")

    w("<footer>Same data as <code>coverage-dashboard.md</code>. Regenerate with "
      "<code>python3 tools/coverage-report.py</code> after <code>mvn -o verify</code>; "
      "<code>--check</code> is what CI runs.</footer>")
    w("</main>")
    w(f"<script>{JS}</script>")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if either committed dashboard differs from freshly generated output")
    args = ap.parse_args()

    data = collect()
    outputs = [(DASHBOARD, render_md(data)), (DASHBOARD_HTML, render_html(data))]
    if args.check:
        stale = [p for p, generated in outputs
                 if (p.read_text() if p.is_file() else "") != generated]
        for p in stale:
            print(f"{p.relative_to(ROOT)} is stale — run tools/coverage-report.py", file=sys.stderr)
        if stale:
            return 1
        print("docs/coverage-dashboard.md and .html are up to date")
        return 0

    for p, generated in outputs:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(generated)
        print(f"wrote {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
