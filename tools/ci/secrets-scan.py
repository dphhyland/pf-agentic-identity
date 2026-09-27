#!/usr/bin/env python3
"""No private key, in any of the shapes one takes, is tracked.

  tools/ci/secrets-scan.py                 # every tracked file (git ls-files); exit 1 with each hit listed
  tools/ci/secrets-scan.py --root DIR
  tools/ci/secrets-scan.py FILE...         # these files, relative to the root, instead of git ls-files

build.yml's secrets-guard job runs this after its filename check (no *.zip, *.jwk, *.jks, ... may be tracked).
A filename cannot catch what this catches: an age identity may be called anything, a PEM block sits in any
text file, and a private JWK is one JSON object among many.

What is a hit:
  age identity     AGE-SECRET-KEY-1 followed by its bech32 payload. The bare prefix is not one: the first
                   version of this guard flagged pf-entrypoint.sh, which names the variable in a comment, and
                   failed two builds before anyone looked. A guard that cries wolf gets excluded, not fixed.
  PEM private key  BEGIN PRIVATE KEY, with or without a qualifier before PRIVATE: the RSA, EC, DSA, OPENSSH,
                   ENCRYPTED, SSH2 ENCRYPTED (RFC 4716) and PGP forms, and any other made of capitals, digits,
                   spaces, - and _.
  private JWK      a JSON object with a "kty" member and a "d" member holding a string: d is the private
                   exponent of an RSA key and the private key of an EC or OKP key (RFC 7518 sections 6.2.2 and
                   6.3.2, RFC 8037 section 2). A public JWK has kty and no d, which is what every fixture and
                   document here carries. The quotes may be backslash-escaped, so a key pasted into a Java
                   string literal is a hit as well. The d of a multi-prime RSA key sits in the objects of its
                   "oth" array (RFC 7518 section 6.3.2.7), so an object is read with the objects nested in it.

The files that carry these patterns on purpose are listed in EXCLUDED, each with why; nothing else is.
Exit status: 0 when clean, 1 with a list otherwise, 2 when a file cannot be read.
"""
import argparse
import os
import re
import subprocess
import sys

# Path, relative to the root -> why its hits are not a leak. tools/tests/test_secrets_scan.py is not here: it
# assembles its keys at run time so that its own text matches nothing, and the scanner reads it like any file.
EXCLUDED = {
    "tools/ci/secrets-scan.py": "carries the patterns it looks for",
}

AGE_IDENTITY = re.compile(r"AGE-SECRET-KEY-1[A-Z0-9]{20,}")
PEM_PRIVATE_KEY = re.compile(r"BEGIN [A-Z0-9 _-]{0,40}PRIVATE KEY")
KTY_MEMBER = re.compile(r'\\?"kty\\?"\s*:')
D_MEMBER = re.compile(r'\\?"d\\?"\s*:\s*\\?"[A-Za-z0-9_\-=]{16,}')


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def brace_objects(text):
    """(offset, body) of every {...} in text, nested ones included, each as its closing brace is reached."""
    opens = []
    for i, ch in enumerate(text):
        if ch == "{":
            opens.append(i)
        elif ch == "}" and opens:
            start = opens.pop()
            yield start, text[start:i + 1]


def scan_text(text):
    """Each hit in text as (line, kind), in line order."""
    hits = []
    for m in AGE_IDENTITY.finditer(text):
        hits.append((line_of(text, m.start()), "age identity"))
    for m in PEM_PRIVATE_KEY.finditer(text):
        hits.append((line_of(text, m.start()), "PEM private key"))
    # Inner objects come first, so a private key is reported at its own kty line and the JWK set around it,
    # whose text holds the same kty and d, is not reported a second time. A multi-prime key's d is only in its
    # oth objects, which have no kty, so the key itself is the object reported.
    found = []
    for start, body in brace_objects(text):
        if any(start <= inner < start + len(body) for inner in found):
            continue
        kty = KTY_MEMBER.search(body)
        if kty and D_MEMBER.search(body):
            found.append(start)
            hits.append((line_of(text, start + kty.start()), "private JWK"))
    return sorted(hits)


def tracked_files(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True, capture_output=True).stdout
    return [p.decode("utf-8") for p in out.split(b"\0") if p]


def scan_files(root, files):
    """(path, line, kind) for every hit in the files that are not excluded; the excluded paths seen."""
    hits, excluded = [], []
    for rel in files:
        if rel in EXCLUDED:
            excluded.append(rel)
            continue
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", errors="replace")
        hits.extend((rel, line, kind) for line, kind in scan_text(text))
    return hits, excluded


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."),
                    help="the repository root (default: the grandparent of tools/ci/)")
    ap.add_argument("files", nargs="*", help="files to scan, relative to the root (default: git ls-files)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    try:
        files = args.files or tracked_files(root)
        hits, excluded = scan_files(root, files)
    except (OSError, subprocess.CalledProcessError) as e:
        print(f"error: cannot read the files to scan: {e}", file=sys.stderr)
        return 2
    if hits:
        print(f"error: {len(hits)} private key(s) or identity tracked - never, whatever encrypts the archive:",
              file=sys.stderr)
        for rel, line, kind in hits:
            print(f"  {rel}:{line}: {kind}", file=sys.stderr)
            print(f"::error file={rel},line={line}::{kind} tracked in {rel}")
        return 1
    print(f"ok: no private key in {len(files) - len(excluded)} tracked files"
          + (f" ({len(excluded)} excluded on purpose: {', '.join(excluded)})" if excluded else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
