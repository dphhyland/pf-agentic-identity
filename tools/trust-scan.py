#!/usr/bin/env python3
"""No trust-all TLS outside platform's InsecureTls (plan item PR-1, finding F-0042).

  tools/trust-scan.py                  # every tracked file (git ls-files); exit 1 with each hit listed
  tools/trust-scan.py --root DIR
  tools/trust-scan.py FILE...          # these files, relative to the root, instead of git ls-files

build.yml's lint job runs this. InsecureTls (libs/platform, package platform.tls) is the one place a trust-all
trust manager is built and the one place the JDK HTTP client's hostname check is turned off; every other main
source must ask it, so each use names its setting, warns once and is recorded for the start-up audit.

What is a hit, in a tracked .java file outside src/test (comments are not read; string literals are read only
for the system property):
  trust manager class     a class, enum or record that implements, or a class that extends, X509TrustManager
                          or X509ExtendedTrustManager
  anonymous trust manager new TrustManager() { ... }, new X509TrustManager() { ... } or the extended one
  always-true verifier    a HostnameVerifier lambda whose body is `true`, an anonymous HostnameVerifier or a
                          class implementing one whose body returns true, and the always-true verifiers of
                          Apache HttpClient (NoopHostnameVerifier, ALLOW_ALL_HOSTNAME_VERIFIER)
  no endpoint identity    setEndpointIdentificationAlgorithm(null) or with "" (either turns the check off)
  JVM hostname flag       the jdk.internal.httpclient.disableHostnameVerification system property, named in code
And in a tracked Dockerfile, shell script, YAML file, .properties, .options or .env file outside docs/: the JVM
hostname flag (a -D option in a start-up line turns the check off for the whole JVM, finding F-0035).

The files allowed a hit are listed in EXEMPT, each with why; nothing else is. Exit status: 0 when clean, 1 with
a list otherwise, 2 when a file cannot be read.
"""
import argparse
import os
import re
import subprocess
import sys

INSECURE_TLS = "libs/platform/src/main/java/com/pingidentity/ps/oidf/platform/tls/InsecureTls.java"

# Path, relative to the root -> why its hits are allowed.
EXEMPT = {
    INSECURE_TLS: "the one trust-all: every other main source asks it",
    "services/gm-api/examples/java/GrantManagementClient.java":
        "a single-file example run as `java GrantManagementClient.java`, outside the reactor and not shipped: it"
        " cannot import platform, and its trust-all is opt-in (--insecure) for a demo PingFederate (F-0163)",
    "tools/trust-scan.py": "carries the patterns it looks for",
}

TRUST_MANAGER = r"(?:javax\.net\.ssl\.)?X509(?:Extended)?TrustManager"
IMPLEMENTS_TRUST_MANAGER = re.compile(
    r"\b(?:class|enum|record)\s+\w+[^{;]*?\b(?:implements|extends)\b[^{;]*?\b" + TRUST_MANAGER + r"\b")
ANONYMOUS_TRUST_MANAGER = re.compile(
    r"\bnew\s+(?:javax\.net\.ssl\.)?(?:X509(?:Extended)?)?TrustManager\s*\(\s*\)\s*\{")
VERIFIER_LAMBDA_TRUE = re.compile(
    r"(?:\bHostnameVerifier\b[^;=]*=|\bset(?:Default)?HostnameVerifier\s*\()\s*\(?[\w\s,]*\)?\s*->\s*\{?\s*(?:return\s+)?true\b")
VERIFIER_BODY = re.compile(
    r"(?:\bnew\s+(?:javax\.net\.ssl\.)?HostnameVerifier\s*\(\s*\)\s*|\b(?:class|enum|record)\s+\w+[^{;]*?\bimplements\b[^{;]*?"
    r"\bHostnameVerifier\b[^{;]*)\{")
RETURNS_TRUE = re.compile(r"\breturn\s+true\s*;")
APACHE_ALWAYS_TRUE = re.compile(r"\b(?:NoopHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER)\b")
NO_ENDPOINT_IDENTITY = re.compile(r"\bsetEndpointIdentificationAlgorithm\s*\(\s*(?:null|\"\")\s*\)")
JVM_FLAG = re.compile(r"jdk\.internal\.httpclient\.disableHostnameVerification")

CONFIG_SUFFIXES = (".sh", ".yml", ".yaml", ".properties", ".options", ".env")


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def strip_java(text):
    """(code, code_without_strings): the source with comments blanked, and with string and char literals blanked too.

    Blanking keeps every newline, so an offset in either view is on the same line as in the source."""
    code, bare = [], []
    i, n = 0, len(text)

    def blank(chunk):
        return "".join("\n" if c == "\n" else " " for c in chunk)

    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            code.append(blank(text[i:j]))
            bare.append(blank(text[i:j]))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            code.append(blank(text[i:j]))
            bare.append(blank(text[i:j]))
            i = j
        elif text.startswith('"""', i):
            j = text.find('"""', i + 3)
            while j > 0 and text[j - 1] == "\\":
                j = text.find('"""', j + 1)
            j = n if j < 0 else j + 3
            code.append(text[i:j])
            bare.append('"' + blank(text[i + 1:j - 1]) + '"')
            i = j
        elif text[i] in "\"'":
            quote = text[i]
            j = i + 1
            while j < n and text[j] != quote and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j, n)
            closed = j < n and text[j] == quote
            end = j + 1 if closed else j
            code.append(text[i:end])
            bare.append(quote + blank(text[i + 1:j]) + (quote if closed else ""))
            i = end
        else:
            code.append(text[i])
            bare.append(text[i])
            i += 1
    return "".join(code), "".join(bare)


def body_at(text, brace):
    """The text from the brace at `brace` to its match, or to the end."""
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace:i + 1]
    return text[brace:]


def scan_java(text):
    """Each hit in Java source as (line, kind), in line order."""
    code, bare = strip_java(text)
    hits = []
    for m in IMPLEMENTS_TRUST_MANAGER.finditer(bare):
        hits.append((line_of(bare, m.start()), "trust manager class"))
    for m in ANONYMOUS_TRUST_MANAGER.finditer(bare):
        hits.append((line_of(bare, m.start()), "anonymous trust manager"))
    for m in VERIFIER_LAMBDA_TRUE.finditer(bare):
        hits.append((line_of(bare, m.start()), "always-true hostname verifier"))
    for m in VERIFIER_BODY.finditer(bare):
        if RETURNS_TRUE.search(body_at(bare, m.end() - 1)):
            hits.append((line_of(bare, m.start()), "always-true hostname verifier"))
    for m in APACHE_ALWAYS_TRUE.finditer(bare):
        hits.append((line_of(bare, m.start()), "always-true hostname verifier"))
    # The bare view keeps "" as two quotes, so an empty argument is still seen, and blanks a call quoted in a string.
    for m in NO_ENDPOINT_IDENTITY.finditer(bare):
        hits.append((line_of(bare, m.start()), "no endpoint identity"))
    for m in JVM_FLAG.finditer(code):
        hits.append((line_of(code, m.start()), "JVM hostname flag"))
    return sorted(set(hits))


def scan_config(text):
    """Each JVM hostname flag in a start-up file as (line, kind)."""
    return [(line_of(text, m.start()), "JVM hostname flag") for m in JVM_FLAG.finditer(text)]


def is_test(path):
    """Tests, and the documents that describe the flag (the findings register is YAML)."""
    return "/src/test/" in "/" + path or path.startswith(("tools/tests/", "docs/"))


def scanned(path):
    """How a path is read: 'java', 'config' or None."""
    if is_test(path):
        return None
    if path.endswith(".java"):
        return "java"
    name = os.path.basename(path)
    if name.startswith("Dockerfile") or name.endswith(".dockerfile") or name.endswith(CONFIG_SUFFIXES):
        return "config"
    return None


def tracked(root):
    out = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout
    return [p for p in out.decode("utf-8").split("\0") if p]


def scan(root, paths):
    """(hits, exempted, unreadable): hits as (path, line, kind); exempted as (path, count, why)."""
    hits, exempted, unreadable = [], [], []
    for path in paths:
        kind = scanned(path)
        if kind is None:
            continue
        full = os.path.join(root, path)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            unreadable.append((path, str(e)))
            continue
        found = scan_java(text) if kind == "java" else scan_config(text)
        if path in EXEMPT:
            exempted.append((path, len(found), EXEMPT[path]))
            continue
        hits.extend((path, line, what) for line, what in found)
    return hits, exempted, unreadable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    parser.add_argument("files", nargs="*")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.root)
    paths = args.files or tracked(root)
    hits, exempted, unreadable = scan(root, paths)
    for path, error in unreadable:
        print(f"{path}: cannot read: {error}", file=sys.stderr)
    for path, count, why in exempted:
        print(f"exempt: {path} ({count} hit(s)): {why}")
    if hits:
        for path, line, what in hits:
            print(f"::error file={path},line={line}::{what}: build it with platform's InsecureTls, or record why not")
            print(f"{path}:{line}: {what}", file=sys.stderr)
        print(f"{len(hits)} trust-all site(s) outside InsecureTls", file=sys.stderr)
        return 1
    if unreadable:
        return 2
    print("clean: no trust-all TLS outside InsecureTls")
    return 0


if __name__ == "__main__":
    sys.exit(main())
