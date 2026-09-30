"""tools/trust-scan.py on made-up sources: every trust-all shape it names is found, the secure shapes and the prose
that names them are not, tests and documents are not read, the exempt files stay exempt, and the repository as it
is passes."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

scan = load("trust-scan.py")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

ANONYMOUS = """package x;
import javax.net.ssl.*;
class A {
    static SSLContext trustAll() throws Exception {
        TrustManager[] all = {new X509TrustManager() {
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
        }};
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, all, null);
        return ctx;
    }
}
"""

SHAPES = {
    "anonymous X509TrustManager": (ANONYMOUS, [(5, "anonymous trust manager")]),
    "anonymous fully qualified": ("Object t = new javax.net.ssl.X509TrustManager() { };\n", [(1, "anonymous trust manager")]),
    "anonymous extended": ("Object t = new X509ExtendedTrustManager() { };\n", [(1, "anonymous trust manager")]),
    "anonymous TrustManager": ("Object t = new TrustManager ( ) {\n};\n", [(1, "anonymous trust manager")]),
    "class implements": ("final class Trust implements X509TrustManager {\n}\n", [(1, "trust manager class")]),
    "class implements among others": ("class T implements\n  java.io.Serializable,\n  javax.net.ssl.X509TrustManager {}\n",
                                      [(1, "trust manager class")]),
    "class extends extended": ("public abstract class T extends X509ExtendedTrustManager {}\n", [(1, "trust manager class")]),
    "record implements": ("record T(int a) implements X509TrustManager {}\n", [(1, "trust manager class")]),
    "verifier lambda": ("HostnameVerifier v = (h, s) -> true;\n", [(1, "always-true hostname verifier")]),
    "verifier set lambda": ("conn.setHostnameVerifier((host, session) -> true);\n", [(1, "always-true hostname verifier")]),
    "default verifier block lambda": ("HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> { return true; });\n",
                                      [(1, "always-true hostname verifier")]),
    "anonymous verifier": ("HostnameVerifier v = new HostnameVerifier() {\n  public boolean verify(String h, SSLSession s) {\n"
                           "    return true;\n  }\n};\n", [(1, "always-true hostname verifier")]),
    "verifier class": ("class AllowAll implements HostnameVerifier {\n  public boolean verify(String h, SSLSession s) { return true; }\n}\n",
                       [(1, "always-true hostname verifier")]),
    "apache noop": ("builder.setHostnameVerifier(NoopHostnameVerifier.INSTANCE);\n", [(1, "always-true hostname verifier")]),
    "apache allow all": ("x = SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER;\n", [(1, "always-true hostname verifier")]),
    "endpoint identity null": ("params.setEndpointIdentificationAlgorithm(null);\n", [(1, "no endpoint identity")]),
    "endpoint identity empty": ("params.setEndpointIdentificationAlgorithm( \"\" );\n", [(1, "no endpoint identity")]),
    "jvm flag": ("System.setProperty(\"jdk.internal.httpclient.disableHostnameVerification\", \"true\");\n",
                 [(1, "JVM hostname flag")]),
    "jvm flag in a text block": ('String s = """\n  -Djdk.internal.httpclient.disableHostnameVerification=true\n  """;\n',
                                 [(2, "JVM hostname flag")]),
}

CLEAN = {
    "secure verifier": ("HostnameVerifier v = (h, s) -> h.equals(\"example.com\");\n"
                        "class Checked implements HostnameVerifier {\n  public boolean verify(String h, SSLSession s) {"
                        " return h.endsWith(\".example\"); }\n}\n"),
    "https endpoint identity": "params.setEndpointIdentificationAlgorithm(\"HTTPS\");\n",
    "a trust manager factory": "TrustManagerFactory f = TrustManagerFactory.getInstance(\"PKIX\");\nX509TrustManager tm = pick(f);\n",
    "comments": ("// new X509TrustManager() { } was here\n/* class T implements X509TrustManager {}\n"
                 " jdk.internal.httpclient.disableHostnameVerification */\n/** setEndpointIdentificationAlgorithm(null) */\n"),
    "strings": ("String a = \"new X509TrustManager() {\";\nString b = \"class T implements X509TrustManager {\";\n"
                "String c = \"(h, s) -> true\";\nchar q = '\\'';\nString d = \"setEndpointIdentificationAlgorithm(null)\";\n"),
    "the platform call": "HttpClient c = InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), \"X\", on).build();\n",
    "an unterminated literal keeps the lines": "String s = \"abc\nint x;\n",
}


class ScanJavaTest(unittest.TestCase):
    def test_every_trust_all_shape_is_found(self):
        for name, (text, expected) in SHAPES.items():
            with self.subTest(name):
                self.assertEqual(expected, scan.scan_java(text))

    def test_secure_shapes_comments_and_strings_are_not(self):
        for name, text in CLEAN.items():
            with self.subTest(name):
                self.assertEqual([], scan.scan_java(text))

    def test_a_hit_after_comments_and_literals_is_on_its_own_line(self):
        text = "/* one\n two */\nString s = \"x\";\n// three\nparams.setEndpointIdentificationAlgorithm(null);\n"
        self.assertEqual([(5, "no endpoint identity")], scan.scan_java(text))

    def test_stripping_keeps_every_offset(self):
        text = "a /* b\n c */ d \"e\\\"f\" 'g' // h\n\"\"\"\n i\n\"\"\" j\n\"open\n"
        code, bare = scan.strip_java(text)
        self.assertEqual(len(text), len(code))
        self.assertEqual(len(text), len(bare))
        self.assertEqual(text.count("\n"), bare.count("\n"))
        self.assertNotIn("b", code)
        self.assertIn("e\\\"f", code)
        self.assertNotIn("e", bare.replace("\"", ""))

    def test_a_body_without_its_close_runs_to_the_end(self):
        self.assertEqual("{ a { b }", scan.body_at("x { a { b }", 2))


class ScanConfigTest(unittest.TestCase):
    def test_the_flag_in_a_start_up_file_is_found(self):
        text = "FROM x\nENV JAVA_OPTS=\"-Djdk.internal.httpclient.disableHostnameVerification=true\"\n"
        self.assertEqual([(2, "JVM hostname flag")], scan.scan_config(text))
        self.assertEqual([], scan.scan_config("ENV JAVA_OPTS=-Xmx1g\n"))

    def test_which_paths_are_read(self):
        self.assertEqual("java", scan.scanned("libs/x/src/main/java/A.java"))
        self.assertEqual("java", scan.scanned("services/gm-api/examples/java/GrantManagementClient.java"))
        self.assertIsNone(scan.scanned("libs/x/src/test/java/A.java"))
        self.assertIsNone(scan.scanned("src/test/java/A.java"))
        self.assertIsNone(scan.scanned("tools/tests/test_x.py"))
        self.assertIsNone(scan.scanned("docs/findings/F-0035.yaml"))
        self.assertIsNone(scan.scanned("README.md"))
        for path in ("build/pingfederate/Dockerfile", "x/app.dockerfile", "build/run.sh", "conformance/c.yml",
                     ".github/workflows/b.yaml", "server/run.properties", "jvm-memory.options", "rig.env"):
            with self.subTest(path):
                self.assertEqual("config", scan.scanned(path))


class ScanFilesTest(unittest.TestCase):
    def write(self, root, path, text):
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)

    def test_hits_fail_exempt_files_are_listed_and_tests_are_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "libs/a/src/main/java/A.java", ANONYMOUS)
            self.write(root, scan.INSECURE_TLS, ANONYMOUS)
            self.write(root, "libs/a/src/test/java/T.java", ANONYMOUS)
            self.write(root, "build/Dockerfile", "ENV X=-Djdk.internal.httpclient.disableHostnameVerification\n")
            paths = ["libs/a/src/main/java/A.java", scan.INSECURE_TLS, "libs/a/src/test/java/T.java",
                     "build/Dockerfile", "gone/Missing.java"]
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                status = scan.main(["--root", root] + paths)
            self.assertEqual(1, status)
            self.assertIn("libs/a/src/main/java/A.java:5: anonymous trust manager", err.getvalue())
            self.assertIn("build/Dockerfile:1: JVM hostname flag", err.getvalue())
            self.assertIn("2 trust-all site(s) outside InsecureTls", err.getvalue())
            self.assertIn("exempt: " + scan.INSECURE_TLS + " (1 hit(s))", out.getvalue())
            self.assertNotIn("T.java", err.getvalue())

    def test_a_clean_tree_passes(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "libs/a/src/main/java/A.java", CLEAN["the platform call"])
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(0, scan.main(["--root", root, "libs/a/src/main/java/A.java"]))
            self.assertIn("clean", out.getvalue())

    def test_an_unreadable_file_is_exit_two(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "d.java"))
            os.makedirs(os.path.join(root, "x"))
            self.write(root, "x/A.java", "class A {}\n")
            hits, exempted, unreadable = scan.scan(root, ["x/A.java"])
            self.assertEqual(([], [], []), (hits, exempted, unreadable))
            real_open = open

            def failing(path, *a, **k):
                if path.endswith("A.java"):
                    raise OSError("denied")
                return real_open(path, *a, **k)

            scan.open = failing
            try:
                err = io.StringIO()
                with redirect_stdout(io.StringIO()), redirect_stderr(err):
                    self.assertEqual(2, scan.main(["--root", root, "x/A.java"]))
                self.assertIn("x/A.java: cannot read: denied", err.getvalue())
            finally:
                del scan.open

    def test_the_exemptions_say_why(self):
        for path, why in scan.EXEMPT.items():
            self.assertTrue(why.strip(), path)
        self.assertIn(scan.INSECURE_TLS, scan.EXEMPT)

    def test_the_repository_passes(self):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(0, scan.main(["--root", REPO]))


if __name__ == "__main__":
    unittest.main()
