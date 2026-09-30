"""tools/set-version.py on fixture poms shaped like the reactor's: an aggregator, a BOM with
version.internal, a module that imports the BOM, and gm-api, which imports the BOM like any other
module and differs only in its groupId (au.com.idpartners). Every pom carries the
project.build.outputTimestamp the tool keeps in step with the version."""
import io
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

sv = load("set-version.py")

RELEASE_TIME = "2026-09-29T03:30:00Z"

ROOT_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.pingidentity.ps.oidf</groupId>
    <artifactId>pf-agentic-identity</artifactId>
    <version>{v}</version>
    <packaging>pom</packaging>
    <!-- a comment mentioning <version>9.9.9</version> is not a version element -->
    <properties>
        <project.build.outputTimestamp>{t}</project.build.outputTimestamp>
    </properties>
    <modules>
        <module>bom</module>
        <module>libs/a</module>
        <module>services/gm-api/servlet</module>
    </modules>
</project>
"""

BOM_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.pingidentity.ps.oidf</groupId>
    <artifactId>pf-agentic-identity-bom</artifactId>
    <version>{v}</version>
    <packaging>pom</packaging>
    <properties>
        <version.internal>{v}</version.internal>
        <version.pingfederate>13.1.3.0</version.pingfederate>
        <project.build.outputTimestamp>{t}</project.build.outputTimestamp>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency><groupId>com.pingidentity.ps.oidf</groupId><artifactId>a</artifactId><version>${{version.internal}}</version></dependency>
            <dependency><groupId>pingfederate</groupId><artifactId>pf-protocolengine</artifactId><version>${{version.pingfederate}}</version></dependency>
        </dependencies>
    </dependencyManagement>
</project>
"""

MODULE_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.pingidentity.ps.oidf</groupId>
    <artifactId>a</artifactId>
    <version>{v}</version>
    <properties>
        <maven.compiler.release>17</maven.compiler.release>
        <project.build.outputTimestamp>{t}</project.build.outputTimestamp>
    </properties>
    <dependencyManagement>
        <dependencies>
            <dependency><groupId>com.pingidentity.ps.oidf</groupId><artifactId>pf-agentic-identity-bom</artifactId><version>{v}</version><type>pom</type><scope>import</scope></dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency><groupId>org.bitbucket.b_c</groupId><artifactId>jose4j</artifactId></dependency>
        <dependency><groupId>com.pingidentity.ps.oidf</groupId><artifactId>conformance</artifactId><scope>test</scope></dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-surefire-plugin</artifactId><version>3.2.5</version></plugin>
        </plugins>
    </build>
</project>
"""

GM_API_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>au.com.idpartners</groupId>
    <artifactId>gm-api</artifactId>
    <version>{v}</version>
    <packaging>war</packaging>
    <properties><project.build.outputTimestamp>{t}</project.build.outputTimestamp></properties>
    <dependencyManagement>
        <dependencies>
            <dependency><groupId>com.pingidentity.ps.oidf</groupId><artifactId>pf-agentic-identity-bom</artifactId><version>{v}</version><type>pom</type><scope>import</scope></dependency>
        </dependencies>
    </dependencyManagement>
    <dependencies>
        <dependency><groupId>com.pingidentity.pingfederate</groupId><artifactId>pingfederate-sdk</artifactId><scope>provided</scope></dependency>
        <dependency><groupId>com.pingidentity.ps.oidf</groupId><artifactId>conformance</artifactId><scope>test</scope></dependency>
    </dependencies>
    <build>
        <plugins>
            <plugin><groupId>org.apache.maven.plugins</groupId><artifactId>maven-war-plugin</artifactId><version>3.4.0</version></plugin>
        </plugins>
    </build>
</project>
"""

FILES = {
    "pom.xml": ROOT_POM,
    "bom/pom.xml": BOM_POM,
    "libs/a/pom.xml": MODULE_POM,
    "services/gm-api/servlet/pom.xml": GM_API_POM,
}


def stamp_for(version):
    """The outputTimestamp set-version.py pairs with a version: the snapshot's, or RELEASE_TIME."""
    return sv.SNAPSHOT_TIMESTAMP if version.endswith("-SNAPSHOT") else RELEASE_TIME


def write_reactor(root, versions, stamps=None):
    """versions: a version per file, or one for all; stamps likewise, defaulting to stamp_for(version)."""
    for rel, template in FILES.items():
        v = versions[rel] if isinstance(versions, dict) else versions
        t = stamps[rel] if isinstance(stamps, dict) else (stamps or stamp_for(v))
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(template.format(v=v, t=t))


def edit(root, rel, old, new):
    text = read(root, rel)
    assert old in text, (rel, old)
    with open(os.path.join(root, rel), "w", encoding="utf-8") as f:
        f.write(text.replace(old, new))


def snapshot(root):
    return {rel: read(root, rel) for rel in FILES}


def read(root, rel):
    with open(os.path.join(root, rel), encoding="utf-8") as f:
        return f.read()


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = sv.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class FindSites(unittest.TestCase):

    def test_every_version_element_and_only_those(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            files, sites = sv.collect(root)
            kinds = sorted((os.path.relpath(s.path, root), s.kind) for s in sites)
            self.assertEqual(kinds, [
                ("bom/pom.xml", "output timestamp"),
                ("bom/pom.xml", "project version"),
                ("bom/pom.xml", "version.internal"),
                ("libs/a/pom.xml", "BOM import"),
                ("libs/a/pom.xml", "output timestamp"),
                ("libs/a/pom.xml", "project version"),
                ("pom.xml", "output timestamp"),
                ("pom.xml", "project version"),
                ("services/gm-api/servlet/pom.xml", "BOM import"),
                ("services/gm-api/servlet/pom.xml", "output timestamp"),
                ("services/gm-api/servlet/pom.xml", "project version"),
            ])
            # the ${version.internal} references, the PF pins, plugin versions and the comment are not sites
            self.assertTrue(all(s.value == "0.2.0" for s in sites if s.kind != sv.TIMESTAMP))
            self.assertTrue(all(s.value == RELEASE_TIME for s in sites if s.kind == sv.TIMESTAMP))

    def test_gm_api_is_read_like_any_other_module(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            files, sites = sv.collect(root)
            kinds = lambda rel: sorted(s.kind for s in sites if os.path.relpath(s.path, root) == rel)
            self.assertEqual(kinds("services/gm-api/servlet/pom.xml"), kinds("libs/a/pom.xml"))

    def test_a_literal_internal_dependency_is_still_a_site(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            rel = "libs/a/pom.xml"
            text = read(root, rel).replace(
                "<artifactId>conformance</artifactId><scope>test</scope>",
                "<artifactId>conformance</artifactId><version>0.2.0</version><scope>test</scope>")
            with open(os.path.join(root, rel), "w", encoding="utf-8") as f:
                f.write(text)
            files, sites = sv.collect(root)
            self.assertIn((rel, "dependency conformance"),
                          [(os.path.relpath(s.path, root), s.kind) for s in sites])

    def test_the_offsets_point_at_the_value(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            files, sites = sv.collect(root)
            for s in sites:
                want = RELEASE_TIME if s.kind == sv.TIMESTAMP else "0.2.0"
                self.assertEqual(files[s.path][s.start:s.end], want.encode(), repr(s))

    def test_the_property_counts_only_in_the_projects_own_properties(self):
        # a profile's properties, or a plugin's configuration, are not where the archivers read it from
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            edit(root, "libs/a/pom.xml", "</project>",
                 "<profiles><profile><id>p</id><properties><project.build.outputTimestamp>1</project.build.outputTimestamp>"
                 "</properties></profile></profiles>\n</project>")
            files, sites = sv.collect(root)
            stamps = [s for s in sites if s.kind == sv.TIMESTAMP and s.path.endswith("libs/a/pom.xml")]
            self.assertEqual([s.value for s in stamps], [RELEASE_TIME])


class Check(unittest.TestCase):

    def test_agree(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 0, err)
            self.assertIn("7 version elements in 4 poms all say 0.2.0", out)

    def test_expect(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            self.assertEqual(run(["--root", root, "--check", "--expect", "0.2.0"])[0], 0)
            code, out, err = run(["--root", root, "--check", "--expect", "0.3.0"])
            self.assertEqual(code, 1)
            self.assertIn("the poms say 0.2.0, expected 0.3.0", err)

    def test_no_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.3.0-SNAPSHOT")
            self.assertEqual(run(["--root", root, "--check"])[0], 0)
            code, out, err = run(["--root", root, "--check", "--no-snapshot"])
            self.assertEqual(code, 1)
            self.assertIn("is a snapshot", err)

    def test_disagree_names_the_pom(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, {"pom.xml": "0.2.0", "bom/pom.xml": "0.2.0", "libs/a/pom.xml": "0.2.0",
                                 "services/gm-api/servlet/pom.xml": "1.0.0"})
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1)
            self.assertIn("do not agree", err)
            self.assertIn("services/gm-api/servlet/pom.xml: project version = 1.0.0", err)
            self.assertIn("services/gm-api/servlet/pom.xml: BOM import = 1.0.0", err)

    def test_a_snapshot_and_its_timestamp(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.3.0-SNAPSHOT")
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 0, err)
            self.assertIn(f"all 4 say project.build.outputTimestamp {sv.SNAPSHOT_TIMESTAMP}", out)

    def test_a_pom_without_the_timestamp_is_named(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            edit(root, "services/gm-api/servlet/pom.xml",
                 f"<properties><project.build.outputTimestamp>{RELEASE_TIME}</project.build.outputTimestamp></properties>", "")
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1)
            self.assertIn("services/gm-api/servlet/pom.xml has no <project.build.outputTimestamp>", err)

    def test_an_empty_timestamp_is_a_missing_one(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            edit(root, "bom/pom.xml", f"<project.build.outputTimestamp>{RELEASE_TIME}<", "<project.build.outputTimestamp><")
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1)
            self.assertIn("bom/pom.xml has no <project.build.outputTimestamp>", err)

    def test_two_timestamps_in_one_pom_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            edit(root, "libs/a/pom.xml", "<maven.compiler.release>17</maven.compiler.release>",
                 f"<project.build.outputTimestamp>{RELEASE_TIME}</project.build.outputTimestamp>")
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1)
            self.assertIn("libs/a/pom.xml has 2 <project.build.outputTimestamp>", err)

    def test_timestamps_that_disagree_are_named(self):
        with tempfile.TemporaryDirectory() as root:
            stamps = {rel: RELEASE_TIME for rel in FILES}
            stamps["libs/a/pom.xml"] = "2026-09-28T00:00:00Z"
            write_reactor(root, "0.2.0", stamps)
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1)
            self.assertIn("do not agree on one project.build.outputTimestamp", err)
            self.assertIn("libs/a/pom.xml: 2026-09-28T00:00:00Z", err)

    def test_a_timestamp_that_does_not_parse_is_refused(self):
        for bad in ("2026-09-29 03:30:00Z",          # not ISO-8601's T
                    "2026-09-29T13:30:00+10:00",     # an offset: the poms say UTC, one way
                    "2026-09-29T03:30:00.000Z",      # fractions
                    "1790652600",                    # epoch seconds, which Maven accepts but this does not
                    "2026-02-30T00:00:00Z",          # the right shape, not a date
                    "1970-01-01T00:00:00Z",          # before a zip entry can say
                    "2100-01-01T00:00:00Z",          # after maven-archiver accepts
                    "${git.commit.time}"):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as root:
                write_reactor(root, "0.2.0", bad)
                code, out, err = run(["--root", root, "--check"])
                self.assertEqual(code, 1, err)
                self.assertIn("is not a UTC time like", err)

    def test_the_edges_of_the_range_parse(self):
        self.assertIsNotNone(sv.parse_timestamp("1980-01-01T00:00:02Z"))
        self.assertIsNotNone(sv.parse_timestamp("2099-12-31T23:59:59Z"))
        self.assertIsNone(sv.parse_timestamp("1980-01-01T00:00:01Z"))

    def test_a_snapshot_must_carry_the_snapshot_timestamp(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.3.0-SNAPSHOT", RELEASE_TIME)
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, 1)
            self.assertIn(f"0.3.0-SNAPSHOT is a snapshot, so its project.build.outputTimestamp is {sv.SNAPSHOT_TIMESTAMP}", err)

    def test_a_release_with_the_snapshot_timestamp_is_refused(self):
        # the versions edited by hand from a snapshot, without the tool: the jars would be dated as a snapshot's
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.3.0", sv.SNAPSHOT_TIMESTAMP)
            code, out, err = run(["--root", root, "--check", "--no-snapshot", "--expect", "0.3.0"])
            self.assertEqual(code, 1)
            self.assertIn("0.3.0 is a release, but its project.build.outputTimestamp is still the snapshot's", err)

    def test_timestamp_is_not_a_check_option(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            code, out, err = run(["--root", root, "--check", "--timestamp", RELEASE_TIME])
            self.assertEqual(code, 2)
            self.assertIn("--timestamp goes with a version to set", err)

    def test_a_listed_module_that_is_missing_is_an_error(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            os.remove(os.path.join(root, "libs/a/pom.xml"))
            code, out, err = run(["--root", root, "--check"])
            self.assertEqual(code, "error: libs/a/pom.xml is listed as a module but does not exist")


class Set(unittest.TestCase):

    def test_rewrites_every_site_and_nothing_else(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            code, out, err = run(["--root", root, "0.3.0", "--timestamp", "2026-10-01T00:00:00Z"])
            self.assertEqual(code, 0, err)
            self.assertIn("4 poms changed; 7 version elements now say 0.3.0, and 4 project.build.outputTimestamp "
                          "say 2026-10-01T00:00:00Z", out)
            for rel, template in FILES.items():
                self.assertEqual(read(root, rel), template.format(v="0.3.0", t="2026-10-01T00:00:00Z"), rel)
            self.assertEqual(run(["--root", root, "--check", "--expect", "0.3.0", "--no-snapshot"])[0], 0)

    def test_round_trip_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            before = snapshot(root)
            self.assertEqual(run(["--root", root, "0.4.0-SNAPSHOT"])[0], 0)
            self.assertEqual(run(["--root", root, "0.2.0", "--timestamp", RELEASE_TIME])[0], 0)
            self.assertEqual(snapshot(root), before)

    def test_a_pom_already_at_the_version_is_left_alone(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, {"pom.xml": "0.3.0", "bom/pom.xml": "0.2.0", "libs/a/pom.xml": "0.2.0",
                                 "services/gm-api/servlet/pom.xml": "0.2.0"})
            before = os.stat(os.path.join(root, "pom.xml")).st_mtime_ns
            code, out, err = run(["--root", root, "0.3.0", "--timestamp", RELEASE_TIME])
            self.assertEqual(code, 0)
            self.assertIn("3 poms changed", out)
            self.assertEqual(os.stat(os.path.join(root, "pom.xml")).st_mtime_ns, before)

    def test_refuses_a_version_that_is_not_one(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            code, out, err = run(["--root", root, "latest"])
            self.assertEqual(code, "error: 'latest' is not a version like 0.3.0 or 0.3.0-SNAPSHOT")
            self.assertEqual(read(root, "pom.xml"), ROOT_POM.format(v="0.2.0", t=RELEASE_TIME))


def git(root, *args, date=None):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.invalid",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", "-C", root, "-c", "commit.gpgsign=false", *args], env=env, check=True,
                   capture_output=True)


class Timestamps(unittest.TestCase):

    def test_a_snapshot_gets_the_snapshot_timestamp(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            code, out, err = run(["--root", root, "0.3.0-SNAPSHOT"])
            self.assertEqual(code, 0, err)
            for rel, template in FILES.items():
                self.assertEqual(read(root, rel), template.format(v="0.3.0-SNAPSHOT", t=sv.SNAPSHOT_TIMESTAMP), rel)
            self.assertEqual(run(["--root", root, "--check"])[0], 0)

    def test_a_release_gets_heads_commit_time_in_utc(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.3.0-SNAPSHOT")
            git(root, "init", "-q")
            git(root, "add", "-A")
            git(root, "commit", "-q", "-m", "c", date="2026-09-29T13:30:00+10:00")
            code, out, err = run(["--root", root, "0.3.0"])
            self.assertEqual(code, 0, err)
            self.assertIn("project.build.outputTimestamp say 2026-09-29T03:30:00Z", out)
            first = snapshot(root)
            self.assertEqual(first["libs/a/pom.xml"], MODULE_POM.format(v="0.3.0", t="2026-09-29T03:30:00Z"))
            self.assertEqual(run(["--root", root, "--check", "--no-snapshot", "--expect", "0.3.0"])[0], 0)
            # the bump is a function of the commit: done again there, it writes the same poms
            run(["--root", root, "0.3.0-SNAPSHOT"])
            run(["--root", root, "0.3.0"])
            self.assertEqual(snapshot(root), first)

    def test_a_release_outside_git_needs_a_timestamp_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.3.0-SNAPSHOT")
            before = snapshot(root)
            code, out, err = run(["--root", root, "0.3.0"])
            self.assertIsInstance(code, str)
            self.assertIn("cannot read HEAD's commit time", code)
            self.assertEqual(snapshot(root), before)

    def test_timestamp_is_refused_for_a_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            before = snapshot(root)
            code, out, err = run(["--root", root, "0.3.0-SNAPSHOT", "--timestamp", RELEASE_TIME])
            self.assertIn("--timestamp is for a release", code)
            self.assertEqual(snapshot(root), before)

    def test_an_unparsable_timestamp_writes_nothing(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            before = snapshot(root)
            code, out, err = run(["--root", root, "0.3.0", "--timestamp", "yesterday"])
            self.assertIn("--timestamp 'yesterday' is not a UTC time", code)
            self.assertEqual(snapshot(root), before)

    def test_a_pom_without_the_property_stops_the_bump_before_any_write(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            edit(root, "services/gm-api/servlet/pom.xml",
                 f"<properties><project.build.outputTimestamp>{RELEASE_TIME}</project.build.outputTimestamp></properties>", "")
            before = snapshot(root)
            code, out, err = run(["--root", root, "0.3.0", "--timestamp", RELEASE_TIME])
            self.assertIn("no <project.build.outputTimestamp> in the <properties> of services/gm-api/servlet/pom.xml", code)
            self.assertEqual(snapshot(root), before)


if __name__ == "__main__":
    unittest.main()
