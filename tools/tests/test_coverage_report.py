"""tools/coverage-report.py on a fixture reactor: a complete build renders clean and exits 0; a build that
left a module without its surefire or jacoco report, or a gate that includes nothing, is written up as
incomplete and exits 1 (0 with --no-strict); a failing gate is reported, not treated as a gap; a module whose
tests are all @ParameterizedTest counts as tested; --check is gone. The JSON carries each check's methods,
the tests and the pins; --gate refuses a check or pattern that selects nothing and an undeclared prefix, and
counts the ids no matrix row declares; --baseline refuses a check gone or shrunk, a method below 100% and
fewer pinned rows, and lets anything new through."""
import io
import json
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

cr = load("coverage-report.py")

ROOT_POM = """<project>
    <modules>
        <module>bom</module>
        <module>libs/decide</module>
        <module>libs/helpers</module>
    </modules>
</project>
"""


def gated_pom(includes):
    inc = "".join(f"<include>{i}</include>" for i in includes)
    # The shade block is there to be ignored: its <include> is an artifact pattern, not a method.
    return f"""<project>
    <build><plugins>
        <plugin><artifactId>maven-shade-plugin</artifactId><configuration><artifactSet>
            <includes><include>org.example:*</include></includes></artifactSet></configuration></plugin>
        <plugin>
            <artifactId>jacoco-maven-plugin</artifactId>
            <executions><execution><id>coverage-gate</id><goals><goal>check</goal></goals><configuration>
                <rules><rule><element>METHOD</element><includes>{inc}</includes>
                <limits><limit><counter>LINE</counter><value>COVEREDRATIO</value><minimum>1.00</minimum></limit></limits>
                </rule></rules>
            </configuration></execution></executions>
        </plugin>
    </plugins></build>
</project>
"""


JACOCO_XML = """<?xml version="1.0" encoding="UTF-8"?>
<report name="decide">
  <package name="com/example">
    <class name="com/example/Gate" sourcefilename="Gate.java">
      <method name="&lt;init&gt;" desc="()V" line="3">
        <counter type="LINE" missed="0" covered="1"/><counter type="BRANCH" missed="0" covered="0"/>
      </method>
      <method name="decide" desc="(Ljava/lang/String;)Z" line="5">
        <counter type="LINE" missed="{missed}" covered="3"/><counter type="BRANCH" missed="0" covered="2"/>
      </method>
    </class>
  </package>
  <counter type="INSTRUCTION" missed="2" covered="18"/>
  <counter type="LINE" missed="{missed}" covered="4"/>
</report>
"""

SUREFIRE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="com.example.GateTest" tests="{tests}" failures="0" errors="0" skipped="{skipped}" time="0.1">
  <testcase name="accepts" classname="com.example.GateTest" time="0.01"/>
</testsuite>
"""

GATE_TEST = """package com.example;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.conformance.Requirement;
class GateTest {
    @Test
    @Requirement("RFC9999 §1.2")
    void accepts() { }
}
"""

# JUnit 5's other test annotations: nothing in this file contains "@Test".
CASES_TEST = """package com.example;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
class CasesTest {
    @ParameterizedTest
    @ValueSource(strings = {"a", "b"})
    void accepts(String s) { }
}
"""

REQUIREMENT_JAVA = """package com.pingidentity.ps.oidf.conformance;
/**
 * Ids are {@code "SPEC §clause"}; the prefixes in use: {@code RFC9999 §1.2} for the example RFC.
 * Retention is {@code RUNTIME}.
 */
public @interface Requirement { String[] value(); }
"""

MATRIX = """# Matrix

| Id | Requirement |
|---|---|
| `RFC9999 §1` | The whole of section 1 |
| `RFC9999 §2` | Section 2, which nothing pins |
"""


def write(root, rel, text):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def fixture(root, decide_missed=0, decide_includes=("com.example.Gate.decide(*", "com.example.Gate.Gate(*"),
            skipped=0):
    """A three-module reactor after `mvn verify`: bom (deliberately not gated), libs/decide (gated, tested,
    reported) and libs/helpers (a test helper and no test - nothing for surefire to have run)."""
    write(root, "pom.xml", ROOT_POM)
    write(root, "bom/pom.xml", "<project/>\n")
    write(root, "libs/decide/pom.xml", gated_pom(decide_includes))
    write(root, "libs/decide/src/test/java/com/example/GateTest.java", GATE_TEST)
    write(root, "libs/decide/target/site/jacoco/jacoco.xml", JACOCO_XML.format(missed=decide_missed))
    write(root, "libs/decide/target/surefire-reports/TEST-com.example.GateTest.xml",
          SUREFIRE_XML.format(tests=3, skipped=skipped))
    write(root, "libs/helpers/pom.xml", "<project/>\n")
    write(root, "libs/helpers/src/test/java/com/example/Helper.java", "class Helper { }\n")
    write(root, cr.ANNOTATION, REQUIREMENT_JAVA)
    write(root, "docs/client-attestation-architecture.md", MATRIX)


class CoverageReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        cr.ROOT = self.root

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cr.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def dashboard(self):
        return (self.root / cr.DASHBOARD).read_text(), (self.root / cr.DASHBOARD_HTML).read_text()

    def test_complete_build_renders_clean_and_exits_0(self):
        fixture(self.root)
        code, out, err = self.run_main()
        self.assertEqual(code, 0, err)
        self.assertIn("wrote docs/coverage-dashboard.md", out)
        self.assertIn("wrote docs/coverage-dashboard.html", out)
        md, html = self.dashboard()
        self.assertIn("**3 tests, 0 failed, 0 skipped**", md)
        self.assertIn("| `libs/decide` | 2 | green | 90% | 3 |", md)
        self.assertIn("**2 methods gated across the reactor, all green.**", md)
        self.assertNotIn("Incomplete build", md)
        self.assertNotIn('class="callout crit"', html)
        not_yet = md.split("### Not yet gated")[1].split("###")[0]
        self.assertIn("- `libs/helpers`", not_yet)
        self.assertIn("- `bom` — dependency-version manifest, no source", md)
        # The matrix: §1 is pinned by the finer §1.2 beneath it; §2 is the work queue.
        self.assertIn("**1 of 2 conformance-matrix rows are pinned by a test.**", md)
        self.assertIn("- `RFC9999 §2` — client-attestation-architecture.md", md)
        self.assertNotIn("- `RFC9999 §1` —", md)
        self.assertIn("Not tracked: CI regenerates it from every Build run whose reactor build", md)

    def test_a_missed_line_is_a_failing_gate_not_a_gap(self):
        fixture(self.root, decide_missed=1)
        code, _, err = self.run_main()
        self.assertEqual(code, 0, err)
        md, html = self.dashboard()
        self.assertIn("| `libs/decide` | 2 | **1 failing** |", md)
        self.assertIn("| | | `com.example.Gate.decide(* (1 line, 0 branch missed)` | | |", md)
        self.assertIn("**2 methods gated across the reactor, 1 failing.**", md)
        self.assertIn('<span class="pill crit">1 failing</span>', html)

    def test_tests_without_a_surefire_report_are_an_incomplete_build(self):
        fixture(self.root)
        for report in (self.root / "libs/decide/target/surefire-reports").iterdir():
            report.unlink()
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("incomplete build: libs/decide: has test sources and no surefire report", err)
        self.assertIn("1 gap(s) in the build", err)
        md, html = self.dashboard()  # written all the same, and the first thing it says
        self.assertIn("## Incomplete build", md)
        self.assertIn("- libs/decide: has test sources and no surefire report under target/surefire-reports", md)
        self.assertLess(md.index("## Incomplete build"), md.index("## Critical-method gates"))
        self.assertIn('class="callout crit"', html)
        self.assertIn("libs/decide: has test sources and no surefire report", html)
        self.assertIn("| `libs/decide` | 2 | green | 90% | — |", md)
        code, _, err = self.run_main("--no-strict")
        self.assertEqual(code, 0)
        self.assertIn("incomplete build: libs/decide", err)  # still said, just not fatal

    def test_jacoco_configured_without_a_report_is_an_incomplete_build(self):
        fixture(self.root)
        (self.root / "libs/decide/target/site/jacoco/jacoco.xml").unlink()
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("libs/decide: configures jacoco and has no report at target/site/jacoco/jacoco.xml", err)
        md, _ = self.dashboard()
        self.assertIn("| | | `com.example.Gate.decide(* (not found in report)` | | |", md)

    def test_a_gate_that_includes_nothing_is_an_incomplete_build(self):
        fixture(self.root, decide_includes=())
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("libs/decide: its jacoco check includes no method, so it gates nothing", err)
        self.assertEqual(len([line for line in err.splitlines() if line.startswith("incomplete build:")]), 1)

    def test_a_parameterized_test_alone_is_a_test_that_needs_a_report(self):
        fixture(self.root)
        write(self.root, "pom.xml",
              ROOT_POM.replace("</modules>", "    <module>libs/cases</module>\n    </modules>"))
        write(self.root, "libs/cases/pom.xml", "<project/>\n")
        write(self.root, "libs/cases/src/test/java/com/example/CasesTest.java", CASES_TEST)
        code, _, err = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("incomplete build: libs/cases: has test sources and no surefire report", err)
        cases = next(m for m in cr.collect()["modules"] if m["name"] == "libs/cases")
        self.assertTrue(cases["has_tests"])

    def test_a_helper_without_a_test_needs_no_report(self):
        fixture(self.root)
        data = cr.collect()
        self.assertEqual(data["problems"], [])
        helpers = next(m for m in data["modules"] if m["name"] == "libs/helpers")
        self.assertFalse(helpers["has_tests"])
        self.assertFalse(helpers["jacoco"])

    def test_skips_are_shown_beside_the_count(self):
        fixture(self.root, skipped=2)
        self.assertEqual(self.run_main()[0], 0)  # a skip is visible, not a gap the generator can prove
        md, html = self.dashboard()
        self.assertIn("**3 tests, 0 failed, 2 skipped**", md)
        self.assertIn("| `libs/decide` | 2 | green | 90% | 3 (2 skipped) |", md)
        self.assertIn('<td class="num">3 (2 skipped)</td>', html)

    def test_check_is_gone(self):
        fixture(self.root)
        with self.assertRaises(SystemExit) as raised, redirect_stderr(io.StringIO()):
            cr.main(["--check"])
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse((self.root / cr.DASHBOARD).exists())


UNDECLARED_TEST = """package com.example;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.conformance.Requirement;
class MoreTest {
    @Test
    @Requirement({"RFC9999 §3", "RFC9999 §2.1"})
    void more() { }
}
"""


class JsonAndGateTest(unittest.TestCase):
    """The machine-readable output, and --gate."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        cr.ROOT = self.root

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cr.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def written(self):
        return json.loads((self.root / cr.DASHBOARD_JSON).read_text())

    def test_the_json_carries_methods_tests_and_pins(self):
        fixture(self.root, decide_missed=1)
        code, out, _ = self.run_main()
        self.assertEqual(code, 0)
        self.assertIn("wrote docs/coverage-dashboard.json", out)
        data = self.written()
        self.assertEqual(data["format"], cr.JSON_FORMAT)
        self.assertEqual(data["tests"], {"run": 3, "failed": 0, "skipped": 0})
        decide = data["modules"]["libs/decide"]
        self.assertEqual(decide["tests"], {"run": 3, "failed": 0, "skipped": 0})
        self.assertEqual(decide["gates"], {"coverage-gate": {
            "com.example.Gate.decide(*": [{"method": "com.example.Gate.decide(java.lang.String)",
                                           "line": [1, 3], "branch": [0, 2]}],
            "com.example.Gate.Gate(*": [{"method": "com.example.Gate.<init>()",
                                         "line": [0, 1], "branch": [0, 0]}]}})
        self.assertEqual(decide["requirements"], ["RFC9999 §1.2"])
        self.assertEqual(decide["matrix_rows"], ["RFC9999 §1"])
        self.assertEqual(data["modules"]["bom"]["not_gated"], "dependency-version manifest, no source")
        self.assertEqual(data["modules"]["libs/helpers"]["gates"], {})
        self.assertEqual(data["matrix"]["rows"], 2)
        self.assertEqual(data["matrix"]["pinned"], ["RFC9999 §1"])
        self.assertEqual(data["requirements"]["undeclared_prefix"], [])

    def test_gate_passes_a_complete_build(self):
        fixture(self.root)
        code, _, err = self.run_main("--gate")
        self.assertEqual(code, 0, err)
        self.assertNotIn("gate", err)

    def test_gate_refuses_a_pattern_that_names_no_method(self):
        fixture(self.root, decide_includes=("com.example.Gate.decide(*", "com.example.Gate.gone(*"))
        self.assertEqual(self.run_main()[0], 0)  # without --gate it is a line on the page, as before
        code, _, err = self.run_main("--gate")
        self.assertEqual(code, 1)
        self.assertIn("gate: libs/decide: coverage-gate includes com.example.Gate.gone(*, which names no method "
                      "in the jacoco report", err)
        self.assertIn("1 gate failure(s)", err)
        self.assertEqual(self.written()["modules"]["libs/decide"]["gates"]["coverage-gate"]
                         ["com.example.Gate.gone(*"], [])

    def test_gate_refuses_a_check_that_includes_nothing_even_when_not_strict(self):
        fixture(self.root, decide_includes=())
        code, _, err = self.run_main("--no-strict", "--gate")
        self.assertEqual(code, 1)
        self.assertIn("gate: libs/decide: its jacoco check includes no method, so it gates nothing", err)

    def test_gate_leaves_a_missing_report_to_strict(self):
        fixture(self.root)
        (self.root / "libs/decide/target/site/jacoco/jacoco.xml").unlink()
        code, _, err = self.run_main("--no-strict", "--gate")
        self.assertEqual(code, 0, err)  # strict names the missing report; the gate does not repeat it per pattern

    def test_gate_refuses_an_undeclared_prefix(self):
        fixture(self.root)
        write(self.root, "libs/decide/src/test/java/com/example/OtherTest.java",
              GATE_TEST.replace("GateTest", "OtherTest").replace("RFC9999 §1.2", "RFC0000 §1"))
        self.assertEqual(self.run_main()[0], 0)  # a section on the page without --gate
        code, _, err = self.run_main("--gate")
        self.assertEqual(code, 1)
        self.assertIn(f"gate: @Requirement prefix RFC0000 is not declared in {cr.ANNOTATION}: RFC0000 §1", err)
        self.assertEqual(self.written()["requirements"]["undeclared_prefix"], ["RFC0000"])

    def test_gate_counts_ids_no_matrix_row_declares_and_passes(self):
        fixture(self.root)
        write(self.root, "libs/decide/src/test/java/com/example/MoreTest.java", UNDECLARED_TEST)
        code, _, err = self.run_main("--gate")
        self.assertEqual(code, 0, err)
        # §2.1 sits under the §2 row; §3 has no row.
        self.assertIn("gate warning: 1 of 3 @Requirement ids name a section no conformance-matrix row declares, "
                      "under 1 prefixes", err)
        self.assertIn("gate warning: RFC9999: 1 (rows for it would go in docs/client-attestation-architecture.md)",
                      err)
        self.assertEqual(self.written()["requirements"]["undeclared_sections"],
                         {"RFC9999": {"ids": ["RFC9999 §3"],
                                      "documents": ["docs/client-attestation-architecture.md"]}})
        md = (self.root / cr.DASHBOARD).read_text()
        self.assertIn("### Ids no matrix row declares", md)
        self.assertIn("- **RFC9999** (`docs/client-attestation-architecture.md`) — `RFC9999 §3`", md)
        self.assertIn("<h3>Ids no matrix row declares</h3>", (self.root / cr.DASHBOARD_HTML).read_text())
        self.assertNotIn("gate warning", self.run_main()[2])  # counted only under --gate

    def test_a_prefix_no_matrix_has_is_named_as_such(self):
        fixture(self.root)
        write(self.root, cr.ANNOTATION, REQUIREMENT_JAVA.replace("{@code RFC9999 §1.2}",
                                                                 "{@code RFC9999 §1.2}, {@code RFC8888}"))
        write(self.root, "libs/decide/src/test/java/com/example/OtherTest.java",
              GATE_TEST.replace("GateTest", "OtherTest").replace("RFC9999 §1.2", "RFC8888 §4"))
        code, _, err = self.run_main("--gate")
        self.assertEqual(code, 0, err)
        self.assertIn("gate warning: RFC8888: 1 (no matrix has a row for this prefix)", err)

    def test_checks_are_keyed_by_execution_and_loose_includes_are_kept(self):
        fixture(self.root)
        pom = gated_pom(("com.example.Gate.decide(*",)).replace(
            "<executions>", "<configuration><includes><include>com.example.Gate.Gate(*</include></includes>"
            "</configuration><executions>")
        write(self.root, "libs/decide/pom.xml", pom)
        self.assertEqual(cr.gates("libs/decide"), {"coverage-gate": ["com.example.Gate.decide(*"],
                                                   "check": ["com.example.Gate.Gate(*"]})
        self.assertEqual(cr.gates("libs/helpers"), {})

    def test_a_row_declares_itself_and_its_refinements(self):
        self.assertTrue(cr.declares("RFC9999 §1", "RFC9999 §1"))
        self.assertTrue(cr.declares("RFC9999 §1", "RFC9999 §1.2"))
        self.assertTrue(cr.declares("RFC9999 §1", "RFC9999 §1(b)"))
        self.assertFalse(cr.declares("RFC9999 §1", "RFC9999 §10"))
        self.assertFalse(cr.declares("RFC9999 §1", "RFC9999 §1b"))

    def test_summary_is_appended(self):
        fixture(self.root)
        summary = self.root / "summary.md"
        summary.write_text("before\n")
        self.assertEqual(self.run_main("--gate", "--summary", str(summary))[0], 0)
        text = summary.read_text()
        self.assertTrue(text.startswith("before\n### Coverage gate and ratchet"))
        self.assertIn("**Gate:** passed.", text)
        self.assertIn("No baseline was given, so nothing was ratcheted.", text)


class RatchetTest(unittest.TestCase):
    """--baseline: what a later build may not lose, and what it may add."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        cr.ROOT = self.root
        fixture(self.root)
        out = io.StringIO()
        with redirect_stdout(out):
            cr.main([])
        self.baseline = self.root / "baseline.json"
        self.baseline.write_text((self.root / cr.DASHBOARD_JSON).read_text())

    def tearDown(self):
        self.tmp.cleanup()

    def ratchet(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cr.main(["--baseline", str(self.baseline), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_the_same_build_passes(self):
        code, out, err = self.ratchet()
        self.assertEqual(code, 0, err)
        self.assertIn("ratchet: nothing lost against", out)

    def test_a_check_that_is_gone_fails(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",))
              .replace("<id>coverage-gate</id>", "<id>renamed</id>"))
        code, _, err = self.ratchet()
        self.assertEqual(code, 1)
        self.assertIn("ratchet: libs/decide: jacoco check coverage-gate is gone (the module's pom no longer has "
                      "it); the baseline included 2 methods", err)
        self.assertIn("1 ratchet failure(s)", err)

    def test_a_module_that_is_gone_fails(self):
        write(self.root, "pom.xml", ROOT_POM.replace("<module>libs/decide</module>", ""))
        code, _, err = self.ratchet("--no-strict")
        self.assertEqual(code, 1)
        self.assertIn("libs/decide: jacoco check coverage-gate is gone (the module is gone)", err)

    def test_a_check_with_fewer_methods_fails(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",)))
        code, _, err = self.ratchet()
        self.assertEqual(code, 1)
        self.assertIn("ratchet: libs/decide: jacoco check coverage-gate includes 1 methods, the baseline 2; "
                      "no longer included: com.example.Gate.<init>()", err)

    def test_a_method_below_100_percent_fails(self):
        write(self.root, "libs/decide/target/site/jacoco/jacoco.xml",
              JACOCO_XML.format(missed=0).replace('type="BRANCH" missed="0" covered="2"',
                                                  'type="BRANCH" missed="1" covered="1"'))
        code, _, err = self.ratchet()
        self.assertEqual(code, 1)
        self.assertIn("ratchet: libs/decide: com.example.Gate.decide(java.lang.String) is below 100% "
                      "(0 of 3 lines, 1 of 2 branches missed)", err)

    def test_fewer_pinned_rows_fails(self):
        (self.root / "libs/decide/src/test/java/com/example/GateTest.java").write_text(
            GATE_TEST.replace("RFC9999 §1.2", "RFC9999 §9"))
        code, _, err = self.ratchet()
        self.assertEqual(code, 1)
        self.assertIn("ratchet: 0 conformance-matrix rows are pinned, the baseline 1; no longer pinned: "
                      "RFC9999 §1", err)

    def test_anything_new_passes(self):
        # A new module with its own check, a new method in the old check, and a pin on a new row.
        write(self.root, "pom.xml",
              ROOT_POM.replace("</modules>", "    <module>libs/fresh</module>\n    </modules>"))
        write(self.root, "libs/fresh/pom.xml", gated_pom(("com.example.Gate.decide(*",)))
        write(self.root, "libs/fresh/src/test/java/com/example/GateTest.java",
              GATE_TEST.replace("RFC9999 §1.2", "RFC9999 §2"))
        write(self.root, "libs/fresh/target/site/jacoco/jacoco.xml", JACOCO_XML.format(missed=0))
        write(self.root, "libs/fresh/target/surefire-reports/TEST-com.example.GateTest.xml",
              SUREFIRE_XML.format(tests=1, skipped=0))
        write(self.root, "libs/decide/target/site/jacoco/jacoco.xml", JACOCO_XML.format(missed=0).replace(
            "</class>", '<method name="extra" desc="()V" line="9"><counter type="LINE" missed="0" covered="1"/>'
                        "</method></class>"))
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*", "com.example.Gate.Gate(*",
                                                            "com.example.Gate.extra(*")))
        code, _, err = self.ratchet("--gate")
        self.assertEqual(code, 0, err)
        data = json.loads((self.root / cr.DASHBOARD_JSON).read_text())
        self.assertEqual(data["matrix"]["pinned"], ["RFC9999 §1", "RFC9999 §2"])
        self.assertEqual(len(data["modules"]["libs/decide"]["gates"]["coverage-gate"]), 3)
        self.assertIn("coverage-gate", data["modules"]["libs/fresh"]["gates"])

    def test_a_renamed_method_of_the_same_count_passes(self):
        write(self.root, "libs/decide/target/site/jacoco/jacoco.xml",
              JACOCO_XML.format(missed=0).replace('name="decide"', 'name="choose"'))
        write(self.root, "libs/decide/pom.xml",
              gated_pom(("com.example.Gate.choose(*", "com.example.Gate.Gate(*")))
        self.assertEqual(self.ratchet()[0], 0)

    def test_a_line_miss_alone_is_below_100_percent(self):
        write(self.root, "libs/decide/target/site/jacoco/jacoco.xml", JACOCO_XML.format(missed=1))
        code, _, err = self.ratchet("--no-strict")
        self.assertEqual(code, 1)
        self.assertIn("ratchet: libs/decide: com.example.Gate.decide(java.lang.String) is below 100% "
                      "(1 of 4 lines, 0 of 2 branches missed)", err)

    def test_a_baseline_that_cannot_be_read_exits_2(self):
        for text in ("not json", "[1]"):
            self.baseline.write_text(text)
            with self.assertRaises(SystemExit) as raised:
                self.ratchet()
            self.assertEqual(raised.exception.code, 2)
        missing = self.root / "missing.json"
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(SystemExit) as raised:
            cr.main(["--baseline", str(missing)])
        self.assertEqual(raised.exception.code, 2)
        self.assertIn("not a readable coverage-dashboard.json", err.getvalue())

    def test_a_baseline_in_another_format_passes_and_says_so(self):
        # A future JSON_FORMAT bump must not fail every build until a baseline in the new format exists.
        self.baseline.write_text(json.dumps({"format": 99, "modules": {"libs/decide": {"gates": {"gone": {}}}}}))
        summary = self.root / "summary.md"
        code, out, err = self.ratchet("--summary", str(summary))
        self.assertEqual(code, 0, err)
        self.assertIn("is format 99 and this generator writes format 1, so nothing was ratcheted", out)
        text = summary.read_text()
        self.assertIn("Not ratcheted: the baseline", text)
        self.assertNotIn("**Ratchet against", text)

    def allow(self, *lines):
        write(self.root, cr.RATCHET_ALLOW, "# header\n\n" + "\n".join(lines) + "\n")

    def test_an_allowed_method_may_leave_its_check(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",)))
        self.allow("method libs/decide com.example.Gate.<init>()")
        code, _, err = self.ratchet()
        self.assertEqual(code, 0, err)
        self.assertNotIn("allows nothing", err)

    def test_an_allowance_for_another_method_does_not_excuse_this_one(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",)))
        self.allow("method libs/decide com.example.Gate.decide(java.lang.String)")
        code, _, err = self.ratchet()
        self.assertEqual(code, 1)
        # decide is still included, so its allowance excuses nothing: the loss of <init> is counted.
        self.assertIn("includes 1 methods, the baseline 2", err)
        self.assertIn("no longer included: com.example.Gate.<init>()", err)

    def test_an_allowed_check_may_go(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",))
              .replace("<id>coverage-gate</id>", "<id>renamed</id>"))
        self.allow("check libs/decide coverage-gate")
        code, _, err = self.ratchet()
        self.assertEqual(code, 0, err)

    def test_an_allowed_check_that_stays_is_still_ratcheted(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",)))
        self.allow("check libs/decide coverage-gate")
        self.assertEqual(self.ratchet()[0], 1)

    def test_an_allowed_row_may_be_unpinned(self):
        (self.root / "libs/decide/src/test/java/com/example/GateTest.java").write_text(
            GATE_TEST.replace("RFC9999 §1.2", "RFC9999 §9"))
        self.allow("row RFC9999 §1")
        code, _, err = self.ratchet()
        self.assertEqual(code, 0, err)

    def test_an_allowance_never_excuses_a_method_below_100_percent(self):
        write(self.root, "libs/decide/target/site/jacoco/jacoco.xml", JACOCO_XML.format(missed=1))
        self.allow("method libs/decide com.example.Gate.decide(java.lang.String)",
                   "check libs/decide coverage-gate")
        self.assertEqual(self.ratchet("--no-strict")[0], 1)

    def test_an_allowance_the_baseline_does_not_need_is_reported_idle(self):
        self.allow("method libs/decide com.example.Gate.gone()", "row RFC9999 §7", "check libs/other coverage-gate")
        summary = self.root / "summary.md"
        code, _, err = self.ratchet("--summary", str(summary))
        self.assertEqual(code, 0, err)
        self.assertIn(f"ratchet: {cr.RATCHET_ALLOW} allows nothing with `method libs/decide "
                      "com.example.Gate.gone()`", err)
        text = summary.read_text()
        self.assertIn("**Allowances that allow nothing:**", text)
        self.assertIn("- `check libs/other coverage-gate`", text)
        self.assertIn("- `row RFC9999 §7`", text)

    def test_a_malformed_allowance_exits_2(self):
        for line in ("method libs/decide", "check libs/decide a b", "forget libs/decide x", "row"):
            self.allow(line)
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
                cr.main(["--baseline", str(self.baseline)])
            self.assertEqual(raised.exception.code, 2, line)
            self.assertIn(f"{cr.RATCHET_ALLOW}:3:", err.getvalue())

    def test_the_repository_allowance_file_parses(self):
        real = pathlib.Path(__file__).resolve().parents[2] / cr.RATCHET_ALLOW
        self.assertTrue(real.is_file())
        cr.load_allowances(real)

    def test_the_summary_names_the_ratchet(self):
        write(self.root, "libs/decide/pom.xml", gated_pom(("com.example.Gate.decide(*",)))
        summary = self.root / "summary.md"
        self.assertEqual(self.ratchet("--summary", str(summary))[0], 1)
        text = summary.read_text()
        self.assertIn(f"**Ratchet against `{self.baseline}`:** 1 failing.", text)
        self.assertIn("- libs/decide: jacoco check coverage-gate includes 1 methods", text)


if __name__ == "__main__":
    unittest.main()
