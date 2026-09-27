#!/usr/bin/env python3
"""Generate docs/coverage-dashboard.md, .html and .json from jacoco, surefire and @Requirement annotations.

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

All three outputs render from one data pass, so they cannot disagree with each other. The JSON is
the machine-readable one: per module, each jacoco check's included methods with their line and
branch counters, the test counts, and the @Requirement ids and matrix rows its tests pin. It is
what the next run ratchets against.

Usage:
    tools/coverage-report.py                write the three files; exit 1 if the build they describe
                                            is incomplete (below)
    tools/coverage-report.py --no-strict    write them and exit 0 for an incomplete build
    tools/coverage-report.py --gate         also exit 1 when a gate enforces nothing or an id's
                                            prefix is undeclared (below)
    tools/coverage-report.py --baseline B   also exit 1 when this build has lost ground against B, a
                                            coverage-dashboard.json from an earlier build (below)
    tools/coverage-report.py --summary F    append the verdict to F as Markdown (CI passes
                                            $GITHUB_STEP_SUMMARY)

Run `mvn -o verify` first; without it the jacoco and surefire reports are missing or stale and
the numbers below are whatever the last build left behind.

None of the outputs is tracked (plan decision 18): a file every test change regenerated reactor-wide
conflicted in Phase 0's parallel merges. CI runs this after `mvn verify` on every Build whose reactor
build completes and publishes all three as the `coverage-dashboard` artefact, failure or not; a run
that fails in `mvn verify` publishes none. Locally they land at the same paths, git-ignored.

Strict, the default, is what stops a build that quietly skipped tests from producing a
clean-looking page: a module with test sources and no surefire report, a module that configures
jacoco and has no jacoco.xml, or a jacoco check that includes no method, is written into both
pages as an incomplete build and makes the exit status 1.

--gate refuses what the pom and the annotations can get wrong without any test failing: a jacoco
check that includes no method, an <include> pattern that names no method in the jacoco report
(jacoco passes a rule that selects nothing), and an @Requirement id whose prefix Requirement.java
does not declare. An id naming a section that no conformance-matrix row declares is counted and
reported, not refused: the matrices do not have a row for every section the tests cite (measured
2026-09-28: 65 of 500 ids, under 21 prefixes), so refusing would fail every build until they do.

--baseline refuses a build that has lost ground against an earlier one: a jacoco check the baseline
had is gone, or includes fewer methods; a gated method is below 100% line or branch coverage; or
fewer matrix rows are pinned. New modules, checks and methods pass, so adding a module needs no
edit here. CI's baseline is the coverage-dashboard.json of the last successful Build on main
(tools/ci/coverage-baseline.sh); with none, the run passes and says so.
"""

import argparse
import html
import json
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

# The checkout this reads and writes. Everything below resolves paths against it when called, not at
# import, so the tests point it at a fixture reactor.
ROOT = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD = "docs/coverage-dashboard.md"
DASHBOARD_HTML = "docs/coverage-dashboard.html"
DASHBOARD_JSON = "docs/coverage-dashboard.json"
# The JSON's shape. A baseline in another shape is refused rather than compared field by field.
JSON_FORMAT = 1

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
EXECUTION_RE = re.compile(r"<execution>(.*?)</execution>", re.S)
EXECUTION_ID_RE = re.compile(r"<id>([^<]+)</id>")
# A module's floor: the jacoco check execution with this id, holding one BUNDLE rule.
FLOOR_RE = re.compile(r"<id>coverage-floor</id>(.*?)</execution>", re.S)
LIMIT_RE = re.compile(r"<counter>([A-Z]+)</counter>\s*<value>COVEREDRATIO</value>\s*<minimum>([0-9.]+)</minimum>")
# (Lcom/foo/Bar;I)V -> ['com.foo.Bar', 'int'] — enough to tell two overloads apart.
DESC_RE = re.compile(r"\[*(?:L([^;]+);|([BCDFIJSZ]))")
PRIMITIVES = {"B": "byte", "C": "char", "D": "double", "F": "float",
              "I": "int", "J": "long", "S": "short", "Z": "boolean"}
REQUIREMENT_RE = re.compile(r'@Requirement\s*\(\s*(?:\{)?\s*((?:"[^"]*"\s*,?\s*)+)', re.S)
TEST_METHOD_RE = re.compile(r"\bvoid\s+(\w+)\s*\(")
TYPE_DECL_RE = re.compile(r"\b(?:class|interface|enum|record)\s+\w+")
ANNOTATION = "libs/conformance/src/main/java/com/pingidentity/ps/oidf/conformance/Requirement.java"
CODE_TAG_RE = re.compile(r"\{@code ([^}]+)\}")
# Dots are legal in a prefix: AUTHZEN-1.0 carries its version. Lowercase is not, which is what
# keeps SdJwt.java and the other file and method names in that javadoc out of the vocabulary.
PREFIX_RE = re.compile(r"^[A-Z][A-Z0-9.-]*$")
# Both appear in the javadoc as prose, not as prefixes: "SPEC §clause" is the id template and
# RUNTIME names a RetentionPolicy. Everything else uppercase in a {@code} tag is a real prefix.
NOT_A_PREFIX = {"SPEC", "RUNTIME"}

MATRIX_DOCS = ("docs/client-attestation-architecture.md",
               "docs/ai-agent-attestation-profile-1_0.md",
               "docs/federation/conformance-matrix.md")
# A matrix row declares its id as the first cell, backticked and nothing else. Restricting to that
# shape keeps ids cited in prose out of the denominator.
MATRIX_ROW_RE = re.compile(r"^\|\s*`([^`]+)`\s*\|", re.M)

# What no coverage number can say. Rendered verbatim into both outputs so a green page never
# reads as covering them.
NOT_ESTABLISHED = [
    ("The token-endpoint filters are registered by build surgery, not by code.",
     "There is no `@WebFilter` anywhere in the repo and `servlets/oidf-war`'s `web.xml` registers "
     "none — `ClientAttestationAuthFilter`, `TokenEndpointAutoRegistrationFilter` and "
     "`Fapi2ProfileFilter` are mapped over PingFederate's endpoints by "
     "`build/pingfederate/assemble-pf-runtime-war.sh` when it merges the jars "
     "into `pf-runtime.war` (it also checks their order). A gate on `doFilter(` proves the filter "
     "works, never that the war a deployment runs registered it."),
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


def floor(module):
    """The whole-module minimums a module's `coverage-floor` check enforces, by counter; empty when it has none."""
    pom = ROOT / module / "pom.xml"
    if not pom.is_file():
        return {}
    block = FLOOR_RE.search(pom.read_text())
    return {counter: float(minimum) for counter, minimum in LIMIT_RE.findall(block.group(1))} if block else {}


def floor_sentence(mods):
    """One sentence naming each module's floor, or None when no module has one."""
    floored = [m for m in mods if m.get("floor")]
    if not floored:
        return None
    counted = {"INSTRUCTION": "instructions", "BRANCH": "branches", "LINE": "lines", "METHOD": "methods"}
    parts = [f"`{m['name']}` " + ", ".join(f"{v * 100:.0f}% of {counted.get(c, c.lower())}" for c, v in m["floor"].items())
             for m in floored]
    return "Some modules also have a floor under the whole module, and the build fails below it: " + "; ".join(parts) + "."


def jacoco_block(module):
    """The jacoco plugin block of a module's pom, or None when the module does not configure jacoco."""
    pom = ROOT / module / "pom.xml"
    if not pom.is_file():
        return None
    block = JACOCO_BLOCK_RE.search(pom.read_text())
    return block.group(1) if block else None


def gate_includes(module):
    """The <include> patterns in a module's jacoco check rule — i.e. what CI actually enforces.

    Scoped to the jacoco plugin block on purpose: `<include>` is a common element, and reading the
    whole pom also picks up maven-shade's artifact includes, which are not coverage patterns and
    match no method.
    """
    block = jacoco_block(module)
    return [m.strip() for m in INCLUDE_RE.findall(block)] if block else []


def gates(module):
    """A module's jacoco checks that include methods, keyed by execution id: {id: [pattern, ...]}.

    The ratchet compares these by id, so a check that is renamed reads as one gone and one new. Every
    module has one today, `coverage-gate`; an <include> outside any execution is kept under `check`,
    so a pom laid out another way still has every pattern counted somewhere.
    """
    block = jacoco_block(module)
    if not block:
        return {}
    found = {}
    for execution in EXECUTION_RE.findall(block):
        includes = [m.strip() for m in INCLUDE_RE.findall(execution)]
        if includes:
            ident = EXECUTION_ID_RE.search(execution)
            found.setdefault(ident.group(1).strip() if ident else "check", []).extend(includes)
    loose = [m.strip() for m in INCLUDE_RE.findall(EXECUTION_RE.sub("", block))]
    if loose:
        found.setdefault("check", []).extend(loose)
    return found


# JUnit's test annotations. A class whose tests are all @ParameterizedTest or @RepeatedTest has no plain
# @Test in it, and a missing report there must count as a gap too; the boundary keeps @TestInstance and
# @Testcontainers, which mark no test, out.
TEST_ANNOTATION_RE = re.compile(r"@(Test|ParameterizedTest|RepeatedTest|TestFactory|TestTemplate)\b")


def has_tests(module):
    """Whether the module has a test source that declares a test - so surefire should have run it.

    Any file under src/test/java would over-count: a module can carry test helpers and no tests, and
    surefire writes no report for a module that ran nothing.
    """
    return any(TEST_ANNOTATION_RE.search(p.read_text(errors="replace"))
               for p in (ROOT / module / "src" / "test" / "java").rglob("*.java"))


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
    text = (ROOT / ANNOTATION).read_text()
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
    return [p for p in pinned if declares(rid, p)]


def module_requirements(module):
    """Every @Requirement id in one module's test sources, mapped to the tests that pin it."""
    found = {}
    for path in (ROOT / module / "src" / "test").rglob("*.java"):
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


def requirements(by_module=None):
    """Every @Requirement id in test sources, mapped to the tests that pin it.

    Walks the reactor's modules, not the whole checkout: anything else under ROOT that happens to
    carry a src/test tree (a vendored copy, a showcase, a scratch checkout) would otherwise count
    every tag it contains again, and every number on the page would be silently inflated.
    """
    if by_module is None:
        by_module = {module: module_requirements(module) for module in modules()}
    found = {}
    for reqs in by_module.values():
        for rid, tsts in reqs.items():
            found.setdefault(rid, []).extend(tsts)
    return found


def declares(row, rid):
    """Whether a matrix row declares the section an id names: the row itself, or a section beneath it."""
    return rid == row or rid.startswith(row + ".") or rid.startswith(row + "(")


def undeclared_sections(reqs, rows):
    """The ids no matrix row declares, by prefix: {spec: {"ids": [...], "documents": [...]}}.

    `documents` are the matrices that declare some row for that prefix, the place a missing row would
    go; empty when no matrix has a row for the prefix at all.
    """
    by_spec = {}
    for rid in sorted(reqs):
        if not any(declares(row, rid) for _, row in rows):
            by_spec.setdefault(spec_of(rid), []).append(rid)
    return {spec: {"ids": ids,
                   "documents": sorted({doc for doc, row in rows if spec_of(row) == spec})}
            for spec, ids in by_spec.items()}


def spec_of(rid):
    return rid.split("§")[0].split(" divergence")[0].split(" item")[0].strip()


def pct(missed, covered):
    total = missed + covered
    return 100.0 if total == 0 else (covered / total) * 100.0


def problems(mods):
    """What the build these reports came from failed to produce, one line per gap.

    A module with test sources and no surefire report, or a jacoco configuration and no jacoco.xml,
    is a build that skipped something - `-DskipTests`, a `-pl` subset, a test run that never
    reached verify. A jacoco check that includes no method is a gate that enforces nothing. Any of
    them would otherwise leave a page that reads as green, and the whole point of reading the gate
    out of the pom was that nothing here can be quietly satisfied.
    """
    found = []
    for m in mods:
        if m["has_tests"] and not m["tests"]:
            found.append(f"{m['name']}: has test sources and no surefire report under "
                         "target/surefire-reports - were the tests run?")
        if m["jacoco"] and not m["jacoco_report"]:
            found.append(f"{m['name']}: configures jacoco and has no report at "
                         "target/site/jacoco/jacoco.xml - was verify run?")
        if m["jacoco"] and not m.get("gated"):
            found.append(f"{m['name']}: its jacoco check includes no method, so it gates nothing")
    return found


def method_id(key, entry):
    """A gated method as the JSON names it: `a.b.C.m(java.lang.String,int)`, one per overload."""
    return f"{key}({','.join(entry['params'])})"


def gate_detail(includes, methods):
    """Each pattern of one jacoco check, resolved against the report: {pattern: [method, ...]}.

    A method carries its own line and branch counters, as [missed, covered]. A pattern that resolves to
    nothing maps to an empty list, which --gate refuses.
    """
    detail = {}
    for pattern in includes:
        detail[pattern] = [
            {"method": method_id(k, e),
             "line": list(e["counters"].get("LINE", (0, 0))),
             "branch": list(e["counters"].get("BRANCH", (0, 0)))}
            for k, es in sorted(methods.items()) if matches(pattern, k)
            for e in es if selects(pattern, e)]
    return detail


def collect():
    """One pass over the build outputs; the three renderers read from this and nothing else."""
    by_module = {module: module_requirements(module) for module in modules()}
    rows_list = matrix_rows()
    mods = []
    for module in modules():
        entry = {"name": module, "not_gated": NOT_GATED.get(module), "tests": tests(module),
                 "has_tests": has_tests(module), "jacoco": jacoco_block(module) is not None,
                 "jacoco_report": (ROOT / module / "target" / "site" / "jacoco" / "jacoco.xml").is_file(),
                 "requirements": sorted(by_module[module]),
                 "matrix_rows": sorted({row for _, row in rows_list if pins(row, by_module[module])}),
                 "gates": {}}
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
            "gates": {gid: gate_detail(patterns, methods) for gid, patterns in gates(module).items()},
            "floor": floor(module),
            "failing": failing,
            "instruction": (pct(*totals["INSTRUCTION"])
                            if totals and "INSTRUCTION" in totals else None),
        })
        mods.append(entry)

    reqs = requirements(by_module)
    by_spec = {}
    for rid, tsts in sorted(reqs.items()):
        by_spec.setdefault(spec_of(rid), []).append((rid, sorted(tsts)))
    rows = {rid: doc for doc, rid in rows_list}
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
        "problems": problems(mods),
        "requirements": reqs,
        "by_spec": by_spec,
        "matrix": matrix,
        "suspect": sorted(s for s in by_spec if s not in known),
        "undeclared": undeclared_sections(reqs, rows_list),
    }


def gate_failures(d):
    """What --gate refuses, one line each: checks that enforce nothing, and ids with an undeclared prefix.

    jacoco passes a METHOD rule whose includes select nothing - a renamed method, a moved class or a
    typo in the pattern leaves the build green and the method ungated - so a pattern that resolves to
    no method in the report is a failure here, not only a line on the page.
    """
    found = []
    for m in d["modules"]:
        if m["jacoco"] and not m.get("gated") and not m["not_gated"]:
            found.append(f"{m['name']}: its jacoco check includes no method, so it gates nothing")
        if not m["jacoco_report"]:
            continue  # strict names the missing report; every pattern would read as unresolved
        for gid, detail in sorted(m["gates"].items()):
            for pattern, methods in detail.items():
                if not methods:
                    found.append(f"{m['name']}: {gid} includes {pattern}, which names no method in the "
                                 "jacoco report, so jacoco checks nothing for it")
    for spec in d["suspect"]:
        ids = ", ".join(rid for rid, _ in d["by_spec"][spec])
        found.append(f"@Requirement prefix {spec} is not declared in {ANNOTATION}: {ids}")
    return found


def gate_warnings(d):
    """The ids no matrix row declares, counted: reported under --gate, not refused (see the docstring)."""
    undeclared = d["undeclared"]
    if not undeclared:
        return []
    total = sum(len(u["ids"]) for u in undeclared.values())
    lines = [f"{total} of {len(d['requirements'])} @Requirement ids name a section no conformance-matrix row "
             f"declares, under {len(undeclared)} prefixes (a warning: the matrices are not complete enough to "
             "refuse them; the dashboard lists the ids)"]
    for spec, u in sorted(undeclared.items()):
        where = ("rows for it would go in " + ", ".join(u["documents"]) if u["documents"]
                 else "no matrix has a row for this prefix")
        lines.append(f"{spec}: {len(u['ids'])} ({where})")
    return lines


def load_baseline(path):
    """A coverage-dashboard.json from an earlier build; SystemExit(2) naming the problem if it is not one."""
    try:
        data = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError) as err:
        raise SystemExit(f"--baseline {path}: not a readable coverage-dashboard.json ({err})")
    if not isinstance(data, dict) or data.get("format") != JSON_FORMAT:
        raise SystemExit(f"--baseline {path}: format {data.get('format') if isinstance(data, dict) else None!r}, "
                         f"this generator writes format {JSON_FORMAT}; compare with a baseline it wrote")
    return data


def ratchet(d, baseline):
    """How this build has lost ground against the baseline, one line each; empty when it has not.

    Refused: a jacoco check the baseline had is gone or includes fewer methods; a gated method is below
    100% line or branch; fewer matrix rows are pinned. Anything new passes - a module, a check, a method -
    so a pull request that adds a module needs no edit here. A check that includes a different set of
    the same size passes too: a method renamed in the source is renamed in the pattern.
    """
    now = render_json_data(d)
    found = []
    for name, before in sorted(baseline.get("modules", {}).items()):
        after = now["modules"].get(name, {"gates": {}})
        for gid, gate in sorted(before.get("gates", {}).items()):
            had = {m["method"] for methods in gate.values() for m in methods}
            if gid not in after["gates"]:
                what = "the module is gone" if name not in now["modules"] else "the module's pom no longer has it"
                found.append(f"{name}: jacoco check {gid} is gone ({what}); the baseline included "
                             f"{len(had)} methods")
                continue
            has = {m["method"] for methods in after["gates"][gid].values() for m in methods}
            if len(has) < len(had):
                lost = sorted(had - has)
                shown = ", ".join(lost[:10]) + (f" and {len(lost) - 10} more" if len(lost) > 10 else "")
                found.append(f"{name}: jacoco check {gid} includes {len(has)} methods, the baseline "
                             f"{len(had)}; no longer included: {shown}")
    for name, module in sorted(now["modules"].items()):
        for gid, gate in sorted(module["gates"].items()):
            seen = set()
            for methods in gate.values():
                for m in methods:
                    if m["method"] in seen:
                        continue
                    seen.add(m["method"])
                    if m["line"][0] or m["branch"][0]:
                        found.append(f"{name}: {m['method']} is below 100% ({m['line'][0]} of "
                                     f"{sum(m['line'])} lines, {m['branch'][0]} of {sum(m['branch'])} "
                                     "branches missed)")
    before_rows = set(baseline.get("matrix", {}).get("pinned", []))
    after_rows = set(now["matrix"]["pinned"])
    if len(after_rows) < len(before_rows):
        lost = sorted(before_rows - after_rows)
        found.append(f"{len(after_rows)} conformance-matrix rows are pinned, the baseline {len(before_rows)}; "
                     f"no longer pinned: {', '.join(lost)}")
    return found


def render_json_data(d):
    """The JSON document as a dict: stable keys and sorted lists, so two builds' files diff cleanly."""
    def counts(t):
        return {"run": t[0], "failed": t[1], "skipped": t[2]} if t else None
    return {
        "format": JSON_FORMAT,
        "tests": counts(d["tests"]),
        "modules": {m["name"]: {
            "not_gated": m["not_gated"],
            "tests": counts(m["tests"]),
            "gates": m["gates"],
            "requirements": m["requirements"],
            "matrix_rows": m["matrix_rows"],
        } for m in d["modules"]},
        "matrix": {"documents": list(MATRIX_DOCS), "rows": len(d["matrix"]),
                   "pinned": sorted(rid for rid, _, p in d["matrix"] if p)},
        "requirements": {"ids": len(d["requirements"]),
                         "undeclared_prefix": d["suspect"],
                         "undeclared_sections": d["undeclared"]},
        "problems": d["problems"],
    }


def render_json(d):
    return json.dumps(render_json_data(d), indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def test_cell(t):
    """A module's test count for the tables, with what surefire skipped or failed beside it.

    A skipped suite is how a missing Postgres hides: the count still reads as a number, so the
    skips are shown next to it rather than folded into a total nobody reads per module.
    """
    if not t:
        return "—"
    run, failed, skipped = t
    notes = [f"{failed} failed"] if failed else []
    notes += [f"{skipped} skipped"] if skipped else []
    return f"{run}" + (f" ({', '.join(notes)})" if notes else "")


def render_md(d):
    out = []
    w = out.append

    w("# Coverage dashboard")
    w("")
    w("Generated by `tools/coverage-report.py` from each module's jacoco report and a scan of")
    w("`@Requirement` annotations. Not tracked: CI regenerates it from every Build run whose reactor build")
    w("completes and publishes it as that run's `coverage-dashboard` artefact, which is what stops it")
    w("drifting the way prose status tables do. For a local copy run `python3 tools/coverage-report.py`")
    w("after `mvn -o verify`; the numbers are only as fresh as the last build. The same data renders to")
    w("`coverage-dashboard.html` for reading in a browser.")
    w("")
    run, failed, skipped = d["tests"]
    w(f"**{run} tests, {failed} failed, {skipped} skipped** (surefire, summed over the reactor).")
    w("")

    if d["problems"]:
        w("## Incomplete build")
        w("")
        w("**The build this page describes did not produce every report it should have.** The")
        w("generator exits 1 for these, so a build that skipped tests cannot pass as green:")
        w("")
        for problem in d["problems"]:
            w(f"- {problem}")
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
        w(f"| `{m['name']}` | {m['gated']} | {status} | {instr} | {test_cell(m['tests'])} |")
        for f in m["failing"]:
            w(f"| | | `{f}` | | |")

    w("")
    w(f"**{d['gated_total']} methods gated across the reactor"
      + (f", {d['failing_total']} failing.**" if d["failing_total"] else ", all green.**"))
    w("")
    w("Module instruction coverage is context, not a target. A module can sit at 30% with every")
    w("decision method gated, and that is the intended shape.")
    w("")
    floors = floor_sentence(d["modules"])
    if floors:
        w(floors)
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
            w("denominator is the rows that declare an id in `docs/client-attestation-architecture.md`,")
            w("`docs/ai-agent-attestation-profile-1_0.md` and `docs/federation/conformance-matrix.md`. A row written at section granularity is")
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
        if d["undeclared"]:
            total = sum(len(u["ids"]) for u in d["undeclared"].values())
            w("")
            w("### Ids no matrix row declares")
            w("")
            w(f"{total} of {len(reqs)} ids name a section that no conformance-matrix row declares, so")
            w("nothing on this page counts them against a claim. `--gate` reports them rather than")
            w("refusing them: the matrices do not yet have a row for every section the tests cite. Each")
            w("line names the matrix the missing rows belong in.")
            w("")
            for spec, u in sorted(d["undeclared"].items()):
                where = (", ".join(f"`{doc}`" for doc in u["documents"]) if u["documents"]
                         else "no matrix has a row for this prefix")
                w(f"- **{spec}** ({where}) — " + ", ".join(f"`{rid}`" for rid in u["ids"]))
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


LOGOS = {
    # Light and dark wordmarks from the ID Partners brand board, embedded so the published page
    # needs no network and the artifact CSP has nothing to block.
    "light": ROOT / "docs" / "assets" / "idpartners-logo-primary.png",
    "dark": ROOT / "docs" / "assets" / "idpartners-logo-white-orange.png",
}


def logo(which):
    """The wordmark as a data URI, or None if the asset is not in the checkout."""
    path = LOGOS[which]
    if not path.is_file():
        return None
    import base64
    return "data:image/png;base64," + base64.b64encode(path.read_bytes()).decode("ascii")


# ID Partners palette: white or #F1F1F1 grounds, black text, #FC6401 strictly as the accent.
# The two orange tints are fills, never text. Good/critical stay semantic - a failing gate has to
# read as failing - but there is no separate warning hue; brand orange is the attention colour.
CSS = """
:root {
  --bg: #FFFFFF; --surface: #FFFFFF; --surface-2: #F1F1F1; --line: #DADADA; --line-soft: #ECECEC;
  --ink: #000000; --ink-2: #3A3A3A; --ink-3: #6E6E6E;
  --accent: #FC6401; --accent-soft: #FFE1CE; --accent-tint: #FFC39D;
  --good: #1E7A3E; --good-soft: #DDF0E3;
  --crit: #B3261E; --crit-soft: #F8DCD9;
  --logo-light: block; --logo-dark: none;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Arial, sans-serif;
  --mono: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0E0E0E; --surface: #161616; --surface-2: #1E1E1E; --line: #2E2E2E; --line-soft: #242424;
    --ink: #FFFFFF; --ink-2: #CFCFCF; --ink-3: #8F8F8F;
    --accent: #FC6401; --accent-soft: #3A2210; --accent-tint: #FFC39D;
    --good: #5FBF85; --good-soft: #1C3527;
    --crit: #F08C85; --crit-soft: #3D2020;
    --logo-light: none; --logo-dark: block;
  }
}
:root[data-theme="dark"] {
  --bg: #0E0E0E; --surface: #161616; --surface-2: #1E1E1E; --line: #2E2E2E; --line-soft: #242424;
  --ink: #FFFFFF; --ink-2: #CFCFCF; --ink-3: #8F8F8F;
  --accent: #FC6401; --accent-soft: #3A2210; --accent-tint: #FFC39D;
  --good: #5FBF85; --good-soft: #1C3527;
  --crit: #F08C85; --crit-soft: #3D2020;
  --logo-light: none; --logo-dark: block;
}
* { box-sizing: border-box; }
html { color-scheme: light dark; }
body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 var(--sans); }
code { font-family: var(--mono); font-size: 0.92em; }
a { color: var(--accent); }
main { max-width: 1180px; margin: 0 auto; padding: 28px 24px 64px; display: grid; gap: 40px; }
header { display: grid; gap: 22px; }
.masthead { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding-bottom: 18px; border-bottom: 2px solid var(--ink); }
.masthead img { height: 26px; width: auto; }
.logo-light { display: var(--logo-light); }
.logo-dark { display: var(--logo-dark); }
h1 { font-size: 22px; font-weight: 700; margin: 0 0 6px; text-transform: uppercase; letter-spacing: 0.04em; }
h2 { font-size: 17px; font-weight: 700; margin: 0 0 6px; text-wrap: balance; }
h3 { font-size: 12px; font-weight: 700; margin: 24px 0 8px; color: var(--ink); text-transform: uppercase; letter-spacing: 0.08em; }
p { margin: 0; max-width: 72ch; color: var(--ink-2); }
p.lede { color: var(--ink-2); }
.meta { font-size: 13px; color: var(--ink-3); font-family: var(--mono); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 12px; }
.tile { background: var(--surface-2); padding: 16px 18px 14px; display: grid; gap: 2px; }
.tile .label { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink); }
.tile .value { font-size: 36px; font-weight: 700; line-height: 1.1; letter-spacing: -0.02em; color: var(--accent); }
.tile .value small { font-size: 18px; font-weight: 600; color: var(--ink-3); letter-spacing: 0; }
.tile .note { font-size: 13px; color: var(--ink-2); margin-top: 6px; }
.pill { display: inline-flex; align-items: center; gap: 6px; padding: 1px 8px; font-size: 12px; font-weight: 700; letter-spacing: 0.02em; white-space: nowrap; }
.pill::before { content: ""; width: 7px; height: 7px; background: currentColor; }
.pill.good { color: var(--good); background: var(--good-soft); }
.pill.warn { color: var(--accent); background: var(--accent-soft); }
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
.bar i { display: block; height: 6px; background: var(--surface-2); overflow: hidden; }
.bar i b { display: block; height: 100%; background: var(--accent); }
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
.callout { background: var(--surface-2); padding: 18px 20px; display: grid; gap: 14px; }
.callout .item { display: grid; gap: 2px; max-width: 80ch; }
.callout .item strong { color: var(--ink); }
.callout .tag { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--accent); font-weight: 700; }
.callout.crit { background: var(--crit-soft); }
.callout.crit .tag { color: var(--crit); }
.callout.crit ul.plain { margin: 0; font-family: var(--mono); font-size: 13px; }
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
    w(f"<style>{CSS}</style>")
    w("<main>")

    # Header: the wordmark on its own rule, then the page name. Both logo variants are in the
    # markup and the theme tokens decide which one shows.
    w("<header>")
    w('<div class="masthead"><div>')
    for which, cls in (("light", "logo-light"), ("dark", "logo-dark")):
        uri = logo(which)
        if uri:
            w(f'<img class="{cls}" src="{uri}" alt="ID Partners">')
    w("</div>")
    w("<div class=\"meta\">tools/coverage-report.py · run <code>mvn -o verify</code> first</div>")
    w("</div>")
    w("<div><h1>Coverage and conformance</h1>"
      "<p class=\"lede\">Are the methods that decide something covered, and is what the docs claim "
      "also executed? Generated from jacoco, surefire and the <code>@Requirement</code> "
      "annotations by every CI Build run whose reactor build completes, and published as its "
      "<code>coverage-dashboard</code> artefact; not tracked, so it cannot drift from the build.</p></div>")
    w("</header>")

    # An incomplete build comes first: nothing below it may be read as green.
    if d["problems"]:
        w('<section class="callout crit"><div class="item"><span class="tag">incomplete build</span>'
          "<strong>The build this page describes did not produce every report it should have.</strong>"
          "<span>The generator exits 1 for these, so a build that skipped tests cannot pass as green.</span>"
          "</div><ul class=\"plain\">"
          + "".join(f"<li>{e(problem)}</li>" for problem in d["problems"]) + "</ul></section>")

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
        w(f'<tr><td><code>{e(m["name"])}</code></td><td class="num">{m["gated"]}</td>'
          f'<td>{pill}</td><td>{bar}</td><td class="num">{e(test_cell(m["tests"]))}</td></tr>')
        for f in m["failing"]:
            w(f'<tr class="fail"><td></td><td colspan="4">{e(f)}</td></tr>')
    w("</tbody></table></div>")
    w('<p class="legend">Module instruction coverage is context, not a target. A module can sit at '
      '30% with every decision method gated, and that is the intended shape.</p>')
    floors = floor_sentence(d["modules"])
    if floors:
        w('<p class="legend">' + re.sub(r"`([^`]+)`", r"<code>\1</code>", e(floors)) + "</p>")
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
    if d["undeclared"]:
        total = sum(len(u["ids"]) for u in d["undeclared"].values())
        w("<h3>Ids no matrix row declares</h3>")
        w(f"<p>{total} of {len(reqs)} ids name a section no conformance-matrix row declares. "
          "<code>--gate</code> reports them rather than refusing them until the matrices have a row "
          "for every section the tests cite.</p>")
        w('<div class="queue">')
        for spec, u in sorted(d["undeclared"].items()):
            where = ", ".join(doc.split("/")[-1] for doc in u["documents"]) or "no matrix for this prefix"
            for rid in u["ids"]:
                w(f'<div><code>{e(rid)}</code><span class="doc">{e(where)}</span></div>')
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
      "<code>python3 tools/coverage-report.py</code> after <code>mvn -o verify</code>; CI runs the "
      "same on every Build whose reactor build completes and publishes both files as the "
      "<code>coverage-dashboard</code> artefact.</footer>")
    w("</main>")
    w(f"<script>{JS}</script>")
    return "\n".join(out) + "\n"


def summary(d, args, gate, warnings, ratcheted):
    """The verdict as Markdown for a CI step summary: what was checked, and every line that failed."""
    out = ["### Coverage gate and ratchet", ""]
    run, failed, skipped = d["tests"]
    out.append(f"{d['gated_total']} gate patterns, {run} tests ({failed} failed, {skipped} skipped), "
               f"{sum(1 for _, _, p in d['matrix'] if p)} of {len(d['matrix'])} matrix rows pinned.")
    out.append("")
    sections = [("Incomplete build", d["problems"] if args.strict else [])]
    if args.gate:
        sections.append(("Gate", gate))
    if args.baseline:
        sections.append((f"Ratchet against `{args.baseline}`", ratcheted))
    for title, lines in sections:
        out.append(f"**{title}:** " + ("passed." if not lines else f"{len(lines)} failing."))
        out.extend(f"- {line}" for line in lines)
        out.append("")
    if args.gate and warnings:
        out.append(f"**Warning:** {warnings[0]}.")
        out.extend(f"- {line}" for line in warnings[1:])
        out.append("")
    if not args.baseline:
        out.append("No baseline was given, so nothing was ratcheted.")
        out.append("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--strict", action=argparse.BooleanOptionalAction, default=True,
                    help="exit 1 when the build left a module without the reports it should have, or a "
                         "gate that includes no method (the default; --no-strict writes the same pages "
                         "and exits 0)")
    ap.add_argument("--gate", action="store_true",
                    help="exit 1 when a jacoco check or one of its patterns selects no method, or an "
                         "@Requirement prefix is not declared in Requirement.java; count and report the ids "
                         "no matrix row declares")
    ap.add_argument("--baseline", metavar="JSON",
                    help="a coverage-dashboard.json from an earlier build: exit 1 when a check it had is gone "
                         "or includes fewer methods, a gated method is below 100%%, or fewer matrix rows are "
                         "pinned")
    ap.add_argument("--summary", metavar="FILE",
                    help="append the verdict to FILE as Markdown (CI passes $GITHUB_STEP_SUMMARY)")
    args = ap.parse_args(argv)
    baseline = load_baseline(args.baseline) if args.baseline else None

    data = collect()
    # Written before the verdict either way: an incomplete build is easier to read about on the page
    # that names the gap than in a step that printed nothing else.
    for rel, generated in ((DASHBOARD, render_md(data)), (DASHBOARD_HTML, render_html(data)),
                           (DASHBOARD_JSON, render_json(data))):
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(generated)
        print(f"wrote {rel}")
    status = 0
    for problem in data["problems"]:
        print(f"incomplete build: {problem}", file=sys.stderr)
    if data["problems"] and args.strict:
        print(f"{len(data['problems'])} gap(s) in the build: the dashboard is written, and says so "
              "(--no-strict to exit 0 anyway)", file=sys.stderr)
        status = 1
    gate = gate_failures(data) if args.gate else []
    warnings = gate_warnings(data) if args.gate else []
    for line in warnings:
        print(f"gate warning: {line}", file=sys.stderr)
    for line in gate:
        print(f"gate: {line}", file=sys.stderr)
    if gate:
        print(f"{len(gate)} gate failure(s)", file=sys.stderr)
        status = 1
    ratcheted = ratchet(data, baseline) if baseline is not None else []
    for line in ratcheted:
        print(f"ratchet: {line}", file=sys.stderr)
    if ratcheted:
        print(f"{len(ratcheted)} ratchet failure(s) against {args.baseline}", file=sys.stderr)
        status = 1
    elif baseline is not None:
        print(f"ratchet: nothing lost against {args.baseline}")
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(summary(data, args, gate, warnings, ratcheted) + "\n")
    return status


if __name__ == "__main__":
    sys.exit(main())
