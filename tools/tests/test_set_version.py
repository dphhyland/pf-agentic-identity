"""tools/set-version.py on fixture poms shaped like the reactor's: an aggregator, a BOM with
version.internal, a module that imports the BOM, and gm-api with its own coordinates and a literal
dependency on the conformance module."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

sv = load("set-version.py")

ROOT_POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.pingidentity.ps.oidf</groupId>
    <artifactId>pf-agentic-identity</artifactId>
    <version>{v}</version>
    <packaging>pom</packaging>
    <!-- a comment mentioning <version>9.9.9</version> is not a version element -->
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

  <properties>
    <pingfederate.version>13.1.3</pingfederate.version>
  </properties>

  <dependencies>
    <dependency>
      <groupId>local.pingfederate</groupId>
      <artifactId>pingfederate-sdk</artifactId>
      <version>${{pingfederate.version}}</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>local.pingfederate</groupId>
      <artifactId>jose4j</artifactId>
      <version>1.x</version>
      <scope>provided</scope>
    </dependency>
    <dependency>
      <groupId>com.pingidentity.ps.oidf</groupId>
      <artifactId>conformance</artifactId>
      <version>{v}</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""

FILES = {
    "pom.xml": ROOT_POM,
    "bom/pom.xml": BOM_POM,
    "libs/a/pom.xml": MODULE_POM,
    "services/gm-api/servlet/pom.xml": GM_API_POM,
}


def write_reactor(root, versions):
    """versions: a version per file, or one for all."""
    for rel, template in FILES.items():
        v = versions[rel] if isinstance(versions, dict) else versions
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(template.format(v=v))


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
                ("bom/pom.xml", "project version"),
                ("bom/pom.xml", "version.internal"),
                ("libs/a/pom.xml", "BOM import"),
                ("libs/a/pom.xml", "project version"),
                ("pom.xml", "project version"),
                ("services/gm-api/servlet/pom.xml", "dependency conformance"),
                ("services/gm-api/servlet/pom.xml", "project version"),
            ])
            # the ${version.internal} references, the PF pins, plugin versions and the comment are not sites
            self.assertTrue(all(s.value == "0.2.0" for s in sites))

    def test_the_offsets_point_at_the_value(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            files, sites = sv.collect(root)
            for s in sites:
                self.assertEqual(files[s.path][s.start:s.end], b"0.2.0", repr(s))


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
            self.assertIn("services/gm-api/servlet/pom.xml: dependency conformance = 1.0.0", err)

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
            code, out, err = run(["--root", root, "0.3.0"])
            self.assertEqual(code, 0, err)
            self.assertIn("4 poms changed; 7 version elements now say 0.3.0", out)
            for rel, template in FILES.items():
                self.assertEqual(read(root, rel), template.format(v="0.3.0"), rel)
            self.assertEqual(run(["--root", root, "--check", "--expect", "0.3.0"])[0], 0)

    def test_round_trip_is_byte_identical(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            before = {rel: read(root, rel) for rel in FILES}
            run(["--root", root, "0.4.0-SNAPSHOT"])
            run(["--root", root, "0.2.0"])
            self.assertEqual({rel: read(root, rel) for rel in FILES}, before)

    def test_a_pom_already_at_the_version_is_left_alone(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, {"pom.xml": "0.3.0", "bom/pom.xml": "0.2.0", "libs/a/pom.xml": "0.2.0",
                                 "services/gm-api/servlet/pom.xml": "0.2.0"})
            before = os.stat(os.path.join(root, "pom.xml")).st_mtime_ns
            code, out, err = run(["--root", root, "0.3.0"])
            self.assertEqual(code, 0)
            self.assertIn("3 poms changed", out)
            self.assertEqual(os.stat(os.path.join(root, "pom.xml")).st_mtime_ns, before)

    def test_refuses_a_version_that_is_not_one(self):
        with tempfile.TemporaryDirectory() as root:
            write_reactor(root, "0.2.0")
            code, out, err = run(["--root", root, "latest"])
            self.assertEqual(code, "error: 'latest' is not a version like 0.3.0 or 0.3.0-SNAPSHOT")
            self.assertEqual(read(root, "pom.xml"), ROOT_POM.format(v="0.2.0"))


if __name__ == "__main__":
    unittest.main()
