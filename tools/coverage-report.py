#!/usr/bin/env python3
"""Generate docs/coverage-dashboard.md from jacoco reports and @Requirement annotations.

Two questions, one page:

  1. Are the security-critical decision methods covered? Read from each module's
     target/site/jacoco/jacoco.xml, cross-referenced against the <include> patterns in that
     module's pom, which are the gate.
  2. Are the standards this repo claims actually pinned by a test? Read from @Requirement
     annotations in test sources.

Deliberately reads the gate out of the poms rather than taking a hardcoded list: the pom is what
CI enforces, so a method quietly dropped from a rule shows up here as a shrinking gate rather
than staying invisible.

Usage:
    tools/coverage-report.py            regenerate docs/coverage-dashboard.md
    tools/coverage-report.py --check    exit 1 if the committed dashboard is stale

Run `mvn -o verify` first; without it the jacoco reports are missing or stale and the numbers
below are whatever the last build left behind.
"""

import argparse
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

ROOT = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD = ROOT / "docs" / "coverage-dashboard.md"

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


def requirements():
    """Every @Requirement id in test sources, mapped to the tests that pin it."""
    found = {}
    for path in ROOT.rglob("src/test/**/*.java"):
        if "/target/" in str(path):
            continue
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


def pct(missed, covered):
    total = missed + covered
    return 100.0 if total == 0 else (covered / total) * 100.0


def render():
    out = []
    w = out.append

    w("# Coverage dashboard")
    w("")
    w("Generated by `tools/coverage-report.py` from each module's jacoco report and a scan of")
    w("`@Requirement` annotations. Do not edit by hand — CI regenerates it and fails if the")
    w("committed copy differs, which is what stops it drifting the way prose status tables do.")
    w("")
    w("Run `mvn -o verify` before regenerating; the numbers are only as fresh as the last build.")
    w("")

    w("## Critical-method gates")
    w("")
    w("Each module gates the methods that *decide* something — verify a signature, accept or")
    w("reject a credential, enforce a ceiling — at 100% line and branch. Plumbing and getters are")
    w("deliberately outside the gate: a blanket percentage rewards testing whatever is cheapest,")
    w("which says nothing about whether the security paths are the covered ones.")
    w("")
    w("| Module | Gated methods | Gate | Module instructions |")
    w("|---|---:|---|---:|")

    gated_total = failing_total = 0
    ungated = []
    for module in modules():
        if module in NOT_GATED:
            continue
        includes = gate_includes(module)
        totals, methods = coverage(module)
        if not includes:
            ungated.append(module)
            continue

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

        gated_total += len(includes)
        failing_total += len(failing)
        status = "green" if not failing else f"**{len(failing)} failing**"
        instr = f"{pct(*totals['INSTRUCTION']):.0f}%" if totals and "INSTRUCTION" in totals else "—"
        w(f"| `{module}` | {len(includes)} | {status} | {instr} |")

    w("")
    w(f"**{gated_total} methods gated across the reactor"
      + (f", {failing_total} failing.**" if failing_total else ", all green.**"))
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

    reqs = requirements()
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
        by_spec = {}
        for rid, tests in reqs.items():
            by_spec.setdefault(rid.split("§")[0].split(" divergence")[0].split(" item")[0].strip(),
                               []).append((rid, tests))
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
        w("This counts what *is* pinned. It is not a conformance percentage: the denominator would be")
        w("the matrix rows across all ten specifications, and those rows do not yet carry ids to join")
        w("against. Until they do, read this as an inventory, not a score.")
        known = vocabulary()
        suspect = sorted(s for s in by_spec if s not in known)
        if suspect:
            w("")
            w("### Ids with an undeclared prefix")
            w("")
            w("These prefixes are not in the vocabulary `Requirement.java` declares. A prefix nobody")
            w("declared is how a fabricated citation gets in, and how one clause ends up spelled two")
            w("ways — each spelling then reading as half-covered. Add the prefix to the annotation or")
            w("fix the id.")
            w("")
            for spec in suspect:
                ids = ", ".join(f"`{rid}`" for rid, _ in sorted(by_spec[spec]))
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
    w("- **The token-endpoint filters may not run at all.** There is no `@WebFilter` anywhere in")
    w("  the repo and `servlets/oidf-war`'s `web.xml` registers none — `ClientAttestationAuthFilter`")
    w("  and `TokenEndpointAutoRegistrationFilter` are activated by a hand edit to `pf-runtime.war`'s")
    w("  `web.xml` in the deploying repo. A gate on `doFilter(` proves the filter works, never that")
    w("  it runs.")
    w("- **Initial-grant RAR containment lives in a PingAuthorize policy file.**")
    w("  `AttestationAwareRarProcessor.enrich` does not call containment; it forwards the attested")
    w("  ceiling and policy enforces `requested ⊆ attested` outside this repo. Its three permissive")
    w("  switches (`failOpenOnError`, `denyOnNonPermit`, `allowClientAssertedPrincipal`) have")
    w("  *defaults* that are the security property, which no coverage counter expresses.")
    w("- **`OutboundUrlPolicy`'s `allowHttp` / `allowPrivateNetworks` come from environment")
    w("  variables**, so the SSRF posture of a running deployment is not a property of this code.")
    w("")
    w("These belong to the deployed probes (`services/harness`,")
    w("`plugins/rar-paz-plugin/probe-decision.sh`), not to any coverage number.")
    w("")

    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the committed dashboard differs from freshly generated output")
    args = ap.parse_args()

    generated = render()
    if args.check:
        current = DASHBOARD.read_text() if DASHBOARD.is_file() else ""
        if current != generated:
            print(f"{DASHBOARD.relative_to(ROOT)} is stale — run tools/coverage-report.py",
                  file=sys.stderr)
            return 1
        print(f"{DASHBOARD.relative_to(ROOT)} is up to date")
        return 0

    DASHBOARD.parent.mkdir(parents=True, exist_ok=True)
    DASHBOARD.write_text(generated)
    print(f"wrote {DASHBOARD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
