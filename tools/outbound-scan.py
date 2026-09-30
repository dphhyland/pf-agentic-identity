#!/usr/bin/env python3
"""No outbound HTTP client outside platform.http (plan item ST-6, finding F-0025).

  tools/outbound-scan.py                        # the reactor under the current directory; exit 1 with each hit listed
  tools/outbound-scan.py --check-allow-list     # the same, and a stale allow-list line is a failure too (CI runs this)
  tools/outbound-scan.py --root DIR [--allow-list FILE]

build.yml's lint job runs this. From 0.6.0 every outbound call goes through libs/platform's OutboundHttp (package
platform.http, plan item S5d): a deadline on the whole exchange, the address policy, the TLS trust a setting names, a
bulkhead per host. A client built beside it has none of that. In the main Java code of every module in the root pom's
<modules>, each of these is a hit

  java.net.http           an import from, or a qualified use of, the JDK's HTTP client package
  HttpURLConnection       HttpURLConnection or HttpsURLConnection, named anywhere
  URL.openConnection      a call of openConnection( or openStream( on any receiver, or a reference to either:
                          the scan cannot tell a URL from anything else with those methods, so a class of its own
                          with a method of that name is a hit too, and a URL of any scheme is (a jar: or file: read
                          of the class path is admitted by class, with that reason)
  raw socket              new Socket(, new SSLSocket(, createSocket( and SocketChannel.open(: an HTTP client can be
                          written on one, as platform.http's is
  third-party client      an import from, or a qualified use of, a package in THIRD_PARTY; or a string literal that
                          starts with one, which is how a client is loaded by reflection (KafkaSetPublisher's is)

unless the file is under platform.http (EXCLUDED) or tools/outbound-allow.txt admits it. The allow-list, the
--check-allow-list rule and the report are tools/direct-read-scan.py's (this script loads it for them): module lines
for the modules that are never shipped, class lines `<path> | <pattern> | <finding id, or why>` for the rest.

What it does not see. It reads Java only, with comments removed, and matches by name: a client reached through a
name built at run time, an HTTP call made by a library this code calls (PingFederate's SDK, the JDBC driver's),
URL.getContent(), and a server (com.sun.net.httpserver in device-enrolment) are not hits. libs/platform's other
packages are read: a Redis connection, a class-path read and InsecureTls's builder hook are admitted by class. The
plugins' relocated copies of platform.http are made at package time from libs/platform, so they are platform.http.
Checked with fixtures in tools/tests/test_outbound_scan.py.

Exit status: 0 when clean, 1 with a list of problems, 2 when a file cannot be read.
"""
import importlib.util
import os
import re
import sys


def _engine():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "direct-read-scan.py")
    spec = importlib.util.spec_from_file_location("direct_read_scan", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


engine = _engine()

ALLOW_LIST = "tools/outbound-allow.txt"

# Path prefix, relative to the root -> why nothing under it is scanned.
EXCLUDED = {
    "libs/platform/src/main/java/com/pingidentity/ps/oidf/platform/http/":
        "platform.http: OutboundHttp, the one outbound HTTP client, with its deadline, address policy and bulkhead",
}

# Package prefix -> the client it is. Kafka's client is not HTTP; it is here so that a module that talks to a broker
# says so in the allow-list.
THIRD_PARTY = {
    "org.apache.http.": "Apache HttpClient 4",
    "org.apache.hc.": "Apache HttpClient 5",
    "okhttp3.": "OkHttp",
    "com.squareup.okhttp.": "OkHttp 2",
    "org.eclipse.jetty.client.": "Jetty's HTTP client",
    "io.netty.": "Netty",
    "reactor.netty.": "Reactor Netty",
    "org.springframework.web.client.": "Spring's RestTemplate or RestClient",
    "org.springframework.web.reactive.function.client.": "Spring's WebClient",
    "jakarta.ws.rs.client.": "the JAX-RS client",
    "javax.ws.rs.client.": "the JAX-RS client",
    "org.glassfish.jersey.client.": "Jersey's client",
    "com.sun.jersey.api.client.": "Jersey 1's client",
    "com.google.api.client.http.": "Google's HTTP client",
    "org.asynchttpclient.": "AsyncHttpClient",
    "feign.": "Feign",
    "retrofit2.": "Retrofit",
    "io.vertx.": "Vert.x",
    "kong.unirest.": "Unirest",
    "org.apache.kafka.": "Kafka's client (not HTTP)",
}

_PACKAGES = "|".join(re.escape(p) for p in sorted(THIRD_PARTY, key=len, reverse=True))
JDK_HTTP = re.compile(r"(?<![\w$.])java\s*\.\s*net\s*\.\s*http\b")
URL_CONNECTION = re.compile(r"(?<![\w$])Https?URLConnection\b")
OPEN_CALL = re.compile(r"(?:\.|::)\s*(openConnection|openStream)\b(\s*\()?")
RAW_SOCKET = re.compile(r"(?<![\w$])(?:new\s+(?:java\s*\.\s*net\s*\.\s*|javax\s*\.\s*net\s*\.\s*ssl\s*\.\s*)?(?:SSL)?Socket\s*\("
                        r"|createSocket\s*\(|SocketChannel\s*\.\s*open\s*\()")
THIRD_PARTY_USE = re.compile(r"(?<![\w$.])(" + _PACKAGES + r")")
THIRD_PARTY_LITERAL = re.compile(r"\"(" + _PACKAGES + r")")


def client_of(prefix):
    return THIRD_PARTY[prefix]


def outbound(text):
    """Each hit in Java source as (offset, end, what)."""
    code, bare = engine.strip_java(text)
    hits = []
    for m in JDK_HTTP.finditer(bare):
        end = m.end()
        tail = re.match(r"(?:\s*\.\s*[\w*]+)+", bare[end:])
        hits.append((m.start(), end + (tail.end() if tail else 0), "the JDK's java.net.http client"))
    for m in URL_CONNECTION.finditer(bare):
        hits.append((m.start(), m.end(), m.group(0)))
    for m in OPEN_CALL.finditer(bare):
        k = m.start() - 1
        while k >= 0 and (bare[k].isalnum() or bare[k] in "_$"):
            k -= 1
        what = f"URL.{m.group(1)}" + (" (a reference)" if bare[m.start()] == ":" else "")
        hits.append((k + 1, m.end(), what))
    for m in RAW_SOCKET.finditer(bare):
        hits.append((m.start(), m.end(), "a raw socket"))
    for m in THIRD_PARTY_USE.finditer(bare):
        end = m.end()
        tail = re.match(r"[\w.*]*", bare[end:])
        hits.append((m.start(), end + (tail.end() if tail else 0), client_of(m.group(1))))
    for m in THIRD_PARTY_LITERAL.finditer(code):
        close = code.find('"', m.end())
        end = close + 1 if close >= 0 and "\n" not in code[m.end():close] else m.end()
        hits.append((m.start(), end, client_of(m.group(1)) + ", named for a reflective load"))
    return sorted(set(hits))


if __name__ == "__main__":
    sys.exit(engine.main(sys.argv[1:], __doc__, outbound, EXCLUDED, ALLOW_LIST,
                         "outbound client(s) outside platform.http", "call through platform.http's OutboundHttp"))
