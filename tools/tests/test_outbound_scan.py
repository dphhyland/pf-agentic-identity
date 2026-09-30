"""tools/outbound-scan.py on made-up reactors: each form of outbound client and what is not one, platform.http's
exclusion, the allow-list's forms on this scan's file, a stale line, a new module, and the repository as it is. The
allow-list's parsing and rules are direct-read-scan.py's, tested in test_direct_read_scan.py."""
import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from _tools import load

scan = load("outbound-scan.py")
engine = scan.engine

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ALLOW = "tools/outbound-allow.txt"
HTTP_PACKAGE = "com/pingidentity/ps/oidf/platform/http"


def java(body, cls="A", package="x", imports=""):
    return f"package {package};\n{imports}\nclass {cls} {{\n{body}\n}}\n"


def whats(source):
    return [what for _start, _end, what in scan.outbound(source)]


class Tree:
    def __init__(self, test, modules=("libs/a", "servlets/b")):
        self.dir = tempfile.TemporaryDirectory()
        test.addCleanup(self.dir.cleanup)
        self.root = self.dir.name
        self.modules = list(modules)
        self.pom()

    def pom(self):
        body = "".join(f"<module>{m}</module>" for m in self.modules)
        self.write("pom.xml", f"<project><modules>{body}</modules></project>")

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

    def scan(self, check=False):
        return engine.scan(self.root, scan.outbound, scan.EXCLUDED, ALLOW, check)

    def run(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            status = engine.main(["--root", self.root, *args], scan.__doc__, scan.outbound, scan.EXCLUDED, ALLOW,
                                 "outbound client(s) outside platform.http", "call through platform.http's OutboundHttp")
        return status, out.getvalue(), err.getvalue()


class WhatIsAClient(unittest.TestCase):

    def test_the_jdk_client(self):
        self.assertEqual(whats(java("", imports="import java.net.http.HttpClient;\nimport java.net.http.*;\n")),
                         ["the JDK's java.net.http client"] * 2)
        self.assertEqual(whats("Object c = java.net.http.HttpClient.newHttpClient();"),
                         ["the JDK's java.net.http client"])

    def test_url_connections(self):
        self.assertEqual(whats("HttpURLConnection c = (HttpURLConnection) u.openConnection();"),
                         ["HttpURLConnection", "HttpURLConnection", "URL.openConnection"])
        self.assertEqual(whats("javax.net.ssl.HttpsURLConnection c = null;"), ["HttpsURLConnection"])
        self.assertEqual(whats("InputStream in = new URL(s).openStream();"), ["URL.openStream"])
        self.assertEqual(whats("f(URL::openStream);"), ["URL.openStream (a reference)"])

    def test_raw_sockets(self):
        self.assertEqual(whats("Socket s = new Socket(); Object t = new java.net.Socket(h, 80);"
                               " Object u = factory.createSocket(s, h, 443, true); Object v = SocketChannel.open();"),
                         ["a raw socket"] * 4)

    def test_third_party_clients(self):
        imports = ("import org.apache.hc.client5.http.classic.HttpClient;\nimport okhttp3.OkHttpClient;\n"
                   "import org.springframework.web.client.RestTemplate;\nimport jakarta.ws.rs.client.ClientBuilder;\n")
        self.assertEqual(whats(java("", imports=imports)),
                         ["Apache HttpClient 5", "OkHttp", "Spring's RestTemplate or RestClient", "the JAX-RS client"])
        self.assertEqual(whats("Object c = io.netty.bootstrap.Bootstrap.class;"), ["Netty"])

    def test_a_client_named_for_reflection(self):
        self.assertEqual(whats('Class<?> c = Class.forName("org.apache.kafka.clients.producer.KafkaProducer");'),
                         ["Kafka's client (not HTTP), named for a reflective load"])

    def test_what_is_not_a_client(self):
        self.assertEqual(whats('// java.net.http.HttpClient\n/* new Socket() */\nString s = "u.openConnection()";'
                               " URLConnection c = null; Object h = com.sun.net.httpserver.HttpServer.class;"
                               " Object o = my.okhttp3.Thing.class; Object p = java.net.URI.create(s);"), [])

    def test_the_snippet_names_the_import(self):
        text = java("", imports="import java.net.http.HttpRequest;\n")
        (start, end, _what), = scan.outbound(text)
        _code, bare = engine.strip_java(text)
        self.assertEqual(engine.snippet(text, bare, start, end), "java.net.http.HttpRequest")


class TheReactor(unittest.TestCase):

    def test_a_hit_is_reported_with_the_line_that_would_admit_it(self):
        tree = Tree(self)
        path = tree.source("servlets/b", "B", "  Object c = url.openConnection();")
        status, _out, err = tree.run()
        self.assertEqual(status, 1)
        self.assertIn(f"{path}:4: URL.openConnection, and the allow-list line that would admit it: "
                      f"{path} | url.openConnection() | <finding id, or why>", err)

    def test_platform_http_is_not_read_and_the_rest_of_platform_is(self):
        tree = Tree(self, modules=("libs/platform",))
        tree.source("libs/platform", "DeadlineSocket", "  Object s = new Socket();", package=HTTP_PACKAGE)
        path = tree.source("libs/platform", "Redis", "  Object s = new Socket();",
                           package="com/pingidentity/ps/oidf/platform/redis")
        hits, _admitted, problems, _u = tree.scan()
        self.assertEqual(([h.path for h in hits], problems), ([path], []))

    def test_a_new_module_is_held_at_once(self):
        tree = Tree(self)
        tree.source("services/c", "C", "", imports="import java.net.http.HttpClient;\n")
        self.assertEqual(tree.scan()[0], [])
        tree.modules.append("services/c")
        tree.pom()
        self.assertEqual(len(tree.scan()[0]), 1)

    def test_each_allow_list_form(self):
        tree = Tree(self, modules=("libs/a", "services/harness"))
        path = tree.source("libs/a", "A", '  Class<?> k = Class.forName("org.apache.kafka.clients.producer.Callback");')
        tree.source("services/harness", "H", "", imports="import java.net.http.HttpClient;\n")
        tree.allow("# group not shipped\nservices/harness: run by hand\n"
                   f'# group not HTTP\n{path} | "org.apache.kafka. | Kafka\'s own client\n')
        hits, admitted, problems, _u = tree.scan(check=True)
        self.assertEqual((hits, admitted, problems), ([], 2, []))

    def test_a_stale_line(self):
        tree = Tree(self)
        path = tree.source("libs/a", "A", "  int a = 1;")
        tree.allow(f"# group g\n{path} | url.openConnection() | a class-path read\n")
        self.assertEqual(tree.scan()[2], [])
        status, _out, err = tree.run("--check-allow-list")
        self.assertEqual(status, 1)
        self.assertIn(f"stale: {path} | url.openConnection() admits no hit", err)


class TheRepository(unittest.TestCase):

    def test_the_repository_is_clean_and_its_allow_list_current(self):
        hits, admitted, problems, unreadable = engine.scan(REPO, scan.outbound, scan.EXCLUDED, ALLOW, True)
        self.assertEqual([f"{h.path}:{h.line}: {h.what}" for h in hits], [])
        self.assertEqual(problems, [])
        self.assertEqual(unreadable, [])
        self.assertGreater(admitted, 0)


if __name__ == "__main__":
    unittest.main()
