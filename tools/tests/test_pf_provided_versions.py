"""tools/pf-provided-versions.py against jars built here to look like PF's (no version in the file
name, the version in the manifest or pom.properties) and a BOM fixture."""
import io
import os
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

pv = load("pf-provided-versions.py")

SHIPPED = {"jackson-databind": "2.21.1", "jose4j": "0.9.6", "commons-lang3": "3.18.0",
           "commons-logging": "1.1.1", "log4j-api": "2.25.4"}


def bom(versions):
    props = "".join(f"        <version.pf.{k}>{v}</version.pf.{k}>\n" for k, v in versions.items())
    return f"<project>\n    <properties>\n{props}    </properties>\n</project>\n"


BOM_IN_STEP = bom({"jackson": "2.21.1", "jose4j": "0.9.6", "commons-lang3": "3.18.0", "commons-logging": "1.1.1", "log4j": "2.25.4"})


def jar(path, manifest=None, pom_properties=None):
    with zipfile.ZipFile(path, "w") as z:
        if manifest is not None:
            z.writestr("META-INF/MANIFEST.MF", manifest)
        if pom_properties is not None:
            z.writestr("META-INF/maven/org.example/lib/pom.properties", pom_properties)
        z.writestr("org/example/A.class", b"")


def write_lib(lib, shipped=SHIPPED, how="implementation"):
    os.makedirs(lib, exist_ok=True)
    for name, version in shipped.items():
        path = os.path.join(lib, name + ".jar")
        if how == "implementation":
            jar(path, manifest=f"Manifest-Version: 1.0\r\nImplementation-Title: {name}\r\nImplementation-Version: {version}\r\n\r\n")
        elif how == "bundle":
            jar(path, manifest=f"Manifest-Version: 1.0\r\nBundle-Version: {version}\r\n\r\n")
        elif how == "pom.properties":
            jar(path, manifest="Manifest-Version: 1.0\r\n\r\n", pom_properties=f"version={version}\nartifactId={name}\n")


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = pv.main(argv)
    return code, out.getvalue(), err.getvalue()


class Compare(unittest.TestCase):

    def test_agree(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); write_lib(lib)
            b = os.path.join(root, "bom.xml"); open(b, "w").write(BOM_IN_STEP)
            code, out, err = run(["--lib", lib, "--bom", b])
            self.assertEqual(code, 0, err)
            self.assertIn("ok: the 5 PF-provided libraries", out)
            self.assertIn("jackson-databind   BOM 2.21.1     image 2.21.1     ok", out)

    def test_disagree(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); write_lib(lib)
            b = os.path.join(root, "bom.xml"); open(b, "w").write(BOM_IN_STEP.replace("2.21.1", "2.17.1").replace("1.1.1", "1.2"))
            code, out, err = run(["--lib", lib, "--bom", b])
            self.assertEqual(code, 1)
            self.assertIn("jackson-databind   BOM 2.17.1     image 2.21.1     MISMATCH", out)
            self.assertIn("2 PF-provided libraries differ from the BOM: jackson-databind, commons-logging", err)

    def test_report_only_never_fails(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); write_lib(lib)
            b = os.path.join(root, "bom.xml"); open(b, "w").write(BOM_IN_STEP.replace("2.25.4", "2.20.0"))
            code, out, err = run(["--lib", lib, "--bom", b, "--report-only"])
            self.assertEqual(code, 0)
            self.assertIn("report-only: 1 PF-provided library differ", out)

    def test_a_library_the_image_lacks(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); write_lib(lib, {k: v for k, v in SHIPPED.items() if k != "jose4j"})
            b = os.path.join(root, "bom.xml"); open(b, "w").write(BOM_IN_STEP)
            code, out, err = run(["--lib", lib, "--bom", b])
            self.assertEqual(code, 1)
            self.assertIn("jose4j             BOM 0.9.6      image (not found)", out)

    def test_a_bom_missing_a_property(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); write_lib(lib)
            b = os.path.join(root, "bom.xml"); open(b, "w").write(BOM_IN_STEP.replace("        <version.pf.log4j>2.25.4</version.pf.log4j>\n", ""))
            code, out, err = run(["--lib", lib, "--bom", b])
            self.assertEqual(code, 2)
            self.assertIn("lacks version.pf.log4j", err)

    def test_jars_spread_over_two_lib_directories(self):
        with tempfile.TemporaryDirectory() as root:
            a = os.path.join(root, "a"); write_lib(a, {"jackson-databind": "2.21.1", "jose4j": "0.9.6"})
            c = os.path.join(root, "c"); write_lib(c, {"commons-lang3": "3.18.0", "commons-logging": "1.1.1", "log4j-api": "2.25.4"})
            b = os.path.join(root, "bom.xml"); open(b, "w").write(BOM_IN_STEP)
            self.assertEqual(run(["--lib", a, "--lib", c, "--bom", b])[0], 0)


class JarVersion(unittest.TestCase):

    def test_where_the_version_is_read_from(self):
        for how in ("implementation", "bundle", "pom.properties"):
            with tempfile.TemporaryDirectory() as root:
                lib = os.path.join(root, "pf-lib"); write_lib(lib, how=how)
                self.assertEqual(pv.jar_version(os.path.join(lib, "jose4j.jar")), "0.9.6", how)

    def test_the_file_name_is_the_last_resort(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); os.makedirs(lib)
            jar(os.path.join(lib, "jose4j-0.9.6.jar"), manifest="Manifest-Version: 1.0\r\n\r\n")
            self.assertEqual(pv.find_jar([lib], "jose4j"), os.path.join(lib, "jose4j-0.9.6.jar"))
            self.assertEqual(pv.jar_version(os.path.join(lib, "jose4j-0.9.6.jar")), "0.9.6")

    def test_listing_without_a_bom(self):
        with tempfile.TemporaryDirectory() as root:
            lib = os.path.join(root, "pf-lib"); write_lib(lib)
            code, out, err = run(["--lib", lib])
            self.assertEqual(code, 0)
            self.assertIn("log4j-api\t2.25.4\t", out)


if __name__ == "__main__":
    unittest.main()
