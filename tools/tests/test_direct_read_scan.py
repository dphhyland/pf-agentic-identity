"""tools/direct-read-scan.py on made-up reactors: each form of direct read and what is not one, the exclusions, each
form of allow-list line and the lines it refuses, a stale line, a new module, the report, and the repository as it
is."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

scan = load("direct-read-scan.py")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ALLOW = "tools/direct-read-allow.txt"


def java(body, cls="A", package="x", imports=""):
    return f"package {package};\n{imports}\nclass {cls} {{\n{body}\n}}\n"


def whats(source):
    """The hit descriptions in `source`, in order."""
    return [what for _start, _end, what in scan.direct_reads(source)]


class Tree:
    """A reactor on disk: a root pom listing modules, their main sources, an allow-list, findings and the stage
    script."""

    def __init__(self, test, modules=("libs/a", "servlets/b")):
        self.dir = tempfile.TemporaryDirectory()
        test.addCleanup(self.dir.cleanup)
        self.root = self.dir.name
        self.modules = list(modules)
        self.pom()

    def pom(self):
        body = "".join(f"<module>{m}</module>" for m in self.modules)
        self.write("pom.xml", f"<project><modules>{body}</modules></project>")

    def add_module(self, module):
        self.modules.append(module)
        self.pom()

    def write(self, rel, text):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return rel

    def source(self, module, cls, body, package="x", imports=""):
        return self.write(f"{module}/src/main/java/{package}/{cls}.java", java(body, cls, package, imports))

    def allow(self, text):
        self.write(ALLOW, text)

    def finding(self, fid, status="open"):
        self.write(f"docs/findings/{fid}.yaml", f"id: {fid}\nstatus: {status}\n")

    def stage(self, *modules):
        entries = "".join(f'  "libs {m}/target/{m.split("/")[-1]}-${{VERSION}}.jar"\n' for m in modules)
        self.write("build/pingfederate/stage-modules.sh", f"ENTRIES=(\n{entries})\n")

    def scan(self, check=False):
        return scan.scan(self.root, scan.direct_reads, scan.EXCLUDED, ALLOW, check)

    def run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = scan.main(["--root", self.root, *args], scan.__doc__, scan.direct_reads, scan.EXCLUDED, ALLOW,
                               "direct read(s) outside platform", "read it through platform.settings")
        return status, out.getvalue(), err.getvalue()


class WhatIsARead(unittest.TestCase):

    def test_system_calls(self):
        self.assertEqual(whats('String a = System.getenv("X");'), ["System.getenv reads the environment"])
        self.assertEqual(whats('String a = System.getProperty("x", "d");'), ["System.getProperty reads a system property"])
        self.assertEqual(whats("Object a = System.getProperties();"), ["System.getProperties takes every system property"])
        self.assertEqual(whats("Object a = System.getenv();"), ["System.getenv takes the whole environment"])

    def test_qualified_and_spaced(self):
        self.assertEqual(len(whats('String a = java.lang.System . getenv ( "X" );')), 1)

    def test_method_references(self):
        self.assertEqual(whats("f(System::getenv, System::getProperty);"),
                         ["a System::getenv reference hands the process's lookup on",
                          "a System::getProperty reference hands the process's lookup on"])

    def test_boxed_property_readers(self):
        self.assertEqual(len(whats('boolean a = Boolean.getBoolean("x"); Integer b = Integer.getInteger("y");'
                                   ' Long c = Long.getLong("z");')), 3)

    def test_init_params(self):
        self.assertEqual(whats('String a = config.getInitParameter("p");'), ["getInitParameter reads an init-param"])
        self.assertEqual(whats('String a = getServletContext().getInitParameter("p");'),
                         ["getInitParameter reads an init-param"])
        self.assertEqual(whats('String a = getInitParameter("p");'), ["getInitParameter reads an init-param"])
        self.assertEqual(whats("Object a = config.getInitParameterNames();"),
                         ["getInitParameterNames takes every init-param"])
        self.assertEqual(whats("f(config::getInitParameter);"),
                         ["a getInitParameter reference hands the init-params on"])

    def test_a_declaration_is_not_a_read(self):
        self.assertEqual(whats("public String getInitParameter(String name) { return null; }"
                               " public java.util.Enumeration<String> getInitParameterNames() { return null; }"), [])

    def test_a_return_of_a_call_is_a_read(self):
        self.assertEqual(len(whats('String a() { return getInitParameter("p"); }')), 1)

    def test_static_import(self):
        imports = "import static java.lang.System.getenv;\n"
        self.assertEqual(whats(java('String a = getenv("X");', imports=imports)),
                         ["getenv (statically imported from System) reads the environment"])
        star = "import static java.lang.System.*;\n"
        self.assertEqual(len(whats(java('String a = getProperty("x"); String b = getenv("Y");', imports=star))), 2)

    def test_a_bare_getenv_without_the_import_is_not_a_read(self):
        self.assertEqual(whats(java('String a = getenv("X");')), [])

    def test_comments_and_strings_are_not_reads(self):
        self.assertEqual(whats('// System.getenv("X")\n/* System.getProperty("y") */\n'
                               'String s = "System.getenv(\\"X\\") and config.getInitParameter(p)";'), [])

    def test_other_receivers_are_not_reads(self):
        self.assertEqual(whats('String a = props.getProperty("x"); String b = MySystem.getenv("Y");'
                               ' String c = env.apply("Z");'), [])

    def test_the_snippet_is_the_call(self):
        text = java('  String a = System.getProperty(NAME, fallback(1)) + tail();')
        (start, end, _what), = scan.direct_reads(text)
        _code, bare = scan.strip_java(text)
        self.assertEqual(scan.snippet(text, bare, start, end), "System.getProperty(NAME, fallback(1))")

    def test_the_snippet_takes_the_receiver_of_an_init_param(self):
        text = java('  String a = config.getInitParameter("p");')
        (start, end, _what), = scan.direct_reads(text)
        _code, bare = scan.strip_java(text)
        self.assertEqual(scan.snippet(text, bare, start, end), 'config.getInitParameter("p")')


class TheReactor(unittest.TestCase):

    def test_a_hit_is_reported_with_the_line_that_would_admit_it(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", '  String a = System.getenv("X");')
        status, _out, err = tree.run()
        self.assertEqual(status, 1)
        self.assertIn(f'{path}:4: System.getenv reads the environment, and the allow-list line that would admit it: '
                      f'{path} | System.getenv("X") | <finding id, or why>', err)

    def test_clean_is_zero(self):
        tree = Tree(self)
        tree.source("libs/a", "A", "  int a = 1;")
        status, out, _err = tree.run("--check-allow-list")
        self.assertEqual(status, 0)
        self.assertIn("clean", out)

    def test_platform_and_platform_pf_settings_are_not_read(self):
        tree = Tree(self, modules=("libs/platform", "libs/platform-pf"))
        tree.source("libs/platform", "P", '  String a = System.getenv("X");', package="com/pingidentity/ps/oidf/platform/settings")
        tree.source("libs/platform-pf", "InitParams", "  Object f = config::getInitParameter;",
                    package="com/pingidentity/ps/oidf/platform/pf/settings")
        hits, _admitted, problems, _u = tree.scan()
        self.assertEqual((hits, problems), ([], []))

    def test_platform_pf_outside_its_settings_package_is_read(self):
        tree = Tree(self, modules=("libs/platform-pf",))
        tree.source("libs/platform-pf", "Audit", "  Object f = System::getenv;",
                    package="com/pingidentity/ps/oidf/platform/pf/audit")
        hits, _admitted, _problems, _u = tree.scan()
        self.assertEqual(len(hits), 1)

    def test_test_code_is_not_read(self):
        tree = Tree(self)
        tree.write("libs/a/src/test/java/x/ATest.java", java('String a = System.getenv("X");', "ATest"))
        hits, _admitted, _problems, _u = tree.scan()
        self.assertEqual(hits, [])

    def test_a_new_module_is_held_at_once(self):
        tree = Tree(self)
        tree.source("services/c", "C", '  String a = System.getenv("X");')
        self.assertEqual(tree.scan()[0], [])
        tree.add_module("services/c")
        hits, _admitted, _problems, _u = tree.scan()
        self.assertEqual([h.path for h in hits], ["services/c/src/main/java/x/C.java"])


class TheAllowList(unittest.TestCase):

    def test_a_class_line_admits_the_lines_that_contain_its_pattern(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", '  String a = System.getenv("X");\n  String b = System.getenv("Y");')
        tree.allow(f'# group g\n{path} | System.getenv("X") | a JVM property the JDK defines\n')
        hits, admitted, problems, _u = tree.scan(check=True)
        self.assertEqual(([h.line for h in hits], admitted, problems), ([5], 1, []))

    def test_whitespace_in_the_pattern_is_one_space(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", '  String a = System.getenv(  "X"  );')
        tree.allow(f'# group g\n{path} | System.getenv( "X" ) | why\n')
        self.assertEqual(tree.scan(check=True)[0], [])

    def test_a_finding_id_must_name_an_open_finding(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", '  String a = System.getenv("X");')
        tree.allow(f"# group g\n{path} | System.getenv | F-0001\n")
        self.assertIn("F-0001 has no file", "\n".join(tree.scan()[2]))
        tree.finding("F-0001")
        self.assertEqual(tree.scan()[2], [])
        tree.finding("F-0001", status="closed")
        self.assertIn("F-0001 is closed", "\n".join(tree.scan()[2]))

    def test_a_not_shipped_module_line_admits_the_module(self):
        tree = Tree(self, modules=("libs/testkit",))
        tree.source("libs/testkit", "T", '  String a = System.getenv("X"); Object b = System::getProperty;')
        tree.allow("# group not shipped\nlibs/testkit: test support, never staged\n")
        hits, admitted, problems, _u = tree.scan(check=True)
        self.assertEqual((hits, admitted, problems), ([], 2, []))

    def test_a_module_line_outside_not_shipped_is_refused(self):
        tree = Tree(self)
        tree.source("libs/a", "A", '  String a = System.getenv("X");')
        tree.allow("# group later\nlibs/a: to be converted\n")
        self.assertIn('belongs in the "not shipped" group', "\n".join(tree.scan()[2]))

    def test_a_staged_module_cannot_be_not_shipped(self):
        tree = Tree(self)
        tree.stage("libs/a")
        tree.source("libs/a", "A", '  String a = System.getenv("X");')
        tree.allow("# group not shipped\nlibs/a: claimed\n")
        self.assertIn("is staged by", "\n".join(tree.scan()[2]))

    def test_a_module_line_needs_a_reason_and_a_reactor_module(self):
        tree = Tree(self)
        tree.allow("# group not shipped\nlibs/a\nlibs/nope: gone\n")
        problems = "\n".join(tree.scan()[2])
        self.assertIn("says why it is never shipped", problems)
        self.assertIn("libs/nope is not a module of the reactor", problems)

    def test_malformed_and_misplaced_lines_are_refused(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", '  String a = System.getenv("X");')
        tree.allow(f"{path} | System.getenv | why\n"                      # under no group
                   f"# group g\n{path} | System.getenv\n"                   # no reason
                   "Not A Line\n"                                           # neither form
                   f"# group not shipped\n{path} | System.getenv | why\n"   # a class line in not shipped
                   "# group h\nlibs/platform/src/main/java/P.java | x | why\n"
                   "libs/a/README.md | x | why\n")
        problems = "\n".join(tree.scan()[2])
        self.assertIn("under no `# group` line", problems)
        self.assertIn("a class line is `<path> | <pattern> | <finding id, or why>`", problems)
        self.assertIn("neither a module line nor a class line", problems)
        self.assertIn('takes module lines only', problems)
        self.assertIn("libs/a/README.md is not under the src/main of a reactor module", problems)

    def test_a_line_under_an_exclusion_is_refused(self):
        tree = Tree(self, modules=("libs/platform",))
        path = tree.source("libs/platform", "P", "  int a;")
        tree.allow(f"# group g\n{path} | x | why\n")
        self.assertIn("which the scan does not read", "\n".join(tree.scan()[2]))

    def test_a_class_line_in_a_not_shipped_module_is_refused(self):
        tree = Tree(self, modules=("libs/testkit",))
        path = tree.source("libs/testkit", "T", '  String a = System.getenv("X");')
        tree.allow(f"# group not shipped\nlibs/testkit: why\n# group g\n{path} | System.getenv | why\n")
        self.assertIn("is admitted whole", "\n".join(tree.scan()[2]))

    def test_a_missing_file_is_refused(self):
        tree = Tree(self)
        tree.allow("# group g\nlibs/a/src/main/java/x/Gone.java | x | why\n")
        self.assertIn("does not exist", "\n".join(tree.scan()[2]))

    def test_a_line_given_twice_is_refused(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", '  String a = System.getenv("X");')
        tree.allow(f"# group g\n{path} | System.getenv | why\n{path} | System.getenv | why\n")
        self.assertIn("the same line as line 2", "\n".join(tree.scan()[2]))

    def test_a_stale_line_fails_only_with_check_allow_list(self):
        tree = Tree(self, modules=("libs/a", "libs/testkit"))
        path = tree.source("libs/a", "A", "  int a = 1;")
        tree.source("libs/testkit", "T", "  int t = 1;")
        tree.allow(f"# group not shipped\nlibs/testkit: why\n# group g\n{path} | System.getenv | why\n")
        self.assertEqual(tree.scan()[2], [])
        status, _out, _err = tree.run()
        self.assertEqual(status, 0)
        problems = tree.scan(check=True)[2]
        self.assertEqual(len(problems), 2)
        self.assertIn("stale: libs/testkit admits no hit", problems[0])
        self.assertIn(f"stale: {path} | System.getenv admits no hit", problems[1])
        status, _out, err = tree.run("--check-allow-list")
        self.assertEqual(status, 1)
        self.assertIn("delete the line", err)


class TheRepository(unittest.TestCase):

    def test_the_repository_is_clean_and_its_allow_list_current(self):
        hits, admitted, problems, unreadable = scan.scan(REPO, scan.direct_reads, scan.EXCLUDED, ALLOW, True)
        self.assertEqual([f"{h.path}:{h.line}: {h.what}" for h in hits], [])
        self.assertEqual(problems, [])
        self.assertEqual(unreadable, [])
        self.assertGreater(admitted, 0)

    def test_every_shipped_line_names_a_finding_or_a_reason(self):
        lines, _problems = scan.read_allow_list(REPO, ALLOW)
        for line in lines:
            self.assertTrue(line.reason, line.text)


if __name__ == "__main__":
    unittest.main()
