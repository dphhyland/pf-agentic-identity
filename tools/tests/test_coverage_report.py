"""tools/coverage-report.py on a fixture reactor: a complete build renders clean and exits 0; a build that
left a module without its surefire or jacoco report, or a gate that includes nothing, is written up as
incomplete and exits 1 (0 with --no-strict); a failing gate is reported, not treated as a gap; --check is
gone."""
import io
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
        self.assertIn("Not tracked: CI regenerates it from every Build run", md)

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


if __name__ == "__main__":
    unittest.main()
