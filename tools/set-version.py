#!/usr/bin/env python3
"""One project version across the reactor: set it, or check that every pom already agrees.

  tools/set-version.py 0.3.0                      # rewrite every version element to 0.3.0
  tools/set-version.py --check                    # every version element is the same one
  tools/set-version.py --check --expect 0.3.0     # ... and it is this one
  tools/set-version.py --check --no-snapshot      # ... and it is not a -SNAPSHOT (a release)

Twenty poms carry the version, and until this existed a bump was twenty hand edits: the aggregator
and each module's own <version>, the BOM's <version.internal> (what the internal dependencies resolve
to), the BOM import each module makes (an import's version is written where it is imported, not where
it is defined), and gm-api, which keeps its own coordinates (au.com.idpartners:gm-api) and imports no
BOM, so its <version> and its literal dependency on the conformance module are written here too. One
missed edit is a reactor that builds a module against a stale copy of its neighbour from ~/.m2, which
is exactly the kind of failure no test notices.

What counts as a version element, decided from the XML and not from a regex over the file:
  - project/version                                                   every pom
  - project/properties/version.internal                               the BOM
  - a dependencyManagement import of pf-agentic-identity-bom          the module poms
  - a dependency on a com.pingidentity.ps.oidf artifact whose version is a literal (not ${...})
                                                                      gm-api's conformance test dependency
The poms are the aggregator's <modules> plus the aggregator itself, so a module the reactor does not
build is not touched, and a new module joins the moment it is listed.

Edits are text-preserving: the parser (expat) reports where each element's text begins, and only
those bytes are replaced, so comments, whitespace and attribute order are exactly as they were. The
version is never taken from a file name or a directory name.

Exit status: 0 when the poms agree (or were rewritten), 1 when --check finds a disagreement, 2 for a
usage or parse error.
"""
import argparse
import os
import re
import sys
import xml.parsers.expat

BOM_ARTIFACT = "pf-agentic-identity-bom"
INTERNAL_GROUP = "com.pingidentity.ps.oidf"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$")


class Site:
    """One version element: where its text is in the file's bytes, and what it says."""

    def __init__(self, path, kind, start, end, value):
        self.path, self.kind, self.start, self.end, self.value = path, kind, start, end, value

    def __repr__(self):
        return f"{self.path}: {self.kind} = {self.value}"


def _local(name):
    """expat reports a namespaced element as 'uri name' when namespace processing is on; we turn it
    off and strip any prefix instead, so a pom with or without the xmlns declaration reads the same."""
    return name.rsplit(":", 1)[-1]


def find_sites(path, data):
    """Every version element in one pom, as Sites with byte offsets into `data`."""
    parser = xml.parsers.expat.ParserCreate()
    stack = []          # element names from the root down
    frames = []         # per <dependency>: {'texts': {child: text}, 'version': (start, end, value)}
    text_start = [None]
    text_buf = []
    sites = []

    def start(name, attrs):
        stack.append(_local(name))
        text_start[0] = None
        text_buf.clear()
        if stack[-1] == "dependency":
            frames.append({"texts": {}, "version": None})

    def chars(s):
        # Unbuffered on purpose: with buffer_text the callback fires at the closing tag and
        # CurrentByteIndex points there, not at the text. The first chunk's index is where the text starts.
        if text_start[0] is None:
            text_start[0] = parser.CurrentByteIndex
        text_buf.append(s)

    def end(name):
        local = _local(name)
        path_names = tuple(stack)
        value = "".join(text_buf)
        if text_start[0] is not None and value.strip():
            raw = value
            start_b = text_start[0]
            # the byte range of the text as written: the offsets are byte offsets, the value is str
            end_b = start_b + len(raw.encode("utf-8"))
            lead = len(raw) - len(raw.lstrip())
            trail = len(raw) - len(raw.rstrip())
            start_b += len(raw[:lead].encode("utf-8"))
            end_b -= len(raw[len(raw) - trail:].encode("utf-8")) if trail else 0
            stripped = raw.strip()
            if path_names == ("project", "version"):
                sites.append(Site(path, "project version", start_b, end_b, stripped))
            elif path_names == ("project", "properties", "version.internal"):
                sites.append(Site(path, "version.internal", start_b, end_b, stripped))
            elif frames and len(path_names) >= 2 and path_names[-2] == "dependency":
                frames[-1]["texts"][local] = stripped
                if local == "version":
                    frames[-1]["version"] = (start_b, end_b, stripped)
        if local == "dependency" and frames:
            frame = frames.pop()
            texts, ver = frame["texts"], frame["version"]
            if ver and not ver[2].startswith("${"):
                in_management = "dependencyManagement" in path_names
                if texts.get("artifactId") == BOM_ARTIFACT and texts.get("scope") == "import" and in_management:
                    sites.append(Site(path, "BOM import", *ver))
                elif texts.get("groupId") == INTERNAL_GROUP and not in_management:
                    sites.append(Site(path, f"dependency {texts.get('artifactId')}", *ver))
        stack.pop()
        text_start[0] = None
        text_buf.clear()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.buffer_text = False
    parser.Parse(data, True)
    return sites


def modules_of(root_pom_data):
    """The <module> paths the aggregator lists."""
    parser = xml.parsers.expat.ParserCreate()
    stack, out, buf = [], [], []

    def start(name, attrs):
        stack.append(_local(name)); buf.clear()

    def chars(s):
        buf.append(s)

    def end(name):
        if tuple(stack) == ("project", "modules", "module"):
            out.append("".join(buf).strip())
        stack.pop(); buf.clear()

    parser.StartElementHandler, parser.EndElementHandler, parser.CharacterDataHandler = start, end, chars
    parser.buffer_text = True
    parser.Parse(root_pom_data, True)
    return out


def pom_paths(root):
    root_pom = os.path.join(root, "pom.xml")
    with open(root_pom, "rb") as f:
        data = f.read()
    paths = [root_pom]
    for m in modules_of(data):
        paths.append(os.path.join(root, m, "pom.xml"))
    return paths


def collect(root):
    """All version Sites across the reactor, and the file bytes they index into."""
    files = {}
    sites = []
    for p in pom_paths(root):
        if not os.path.isfile(p):
            raise SystemExit(f"error: {os.path.relpath(p, root)} is listed as a module but does not exist")
        with open(p, "rb") as f:
            data = f.read()
        files[p] = data
        found = find_sites(p, data)
        if not any(s.kind == "project version" for s in found):
            raise SystemExit(f"error: {os.path.relpath(p, root)} has no project <version>")
        sites.extend(found)
    return files, sites


def check(root, expect=None, no_snapshot=False, quiet=False):
    files, sites = collect(root)
    values = sorted({s.value for s in sites})
    ok = True
    if len(values) != 1:
        ok = False
        print("error: the poms do not agree on one version:", file=sys.stderr)
        for s in sites:
            print(f"  {os.path.relpath(s.path, root)}: {s.kind} = {s.value}", file=sys.stderr)
    else:
        v = values[0]
        if expect is not None and v != expect:
            ok = False
            print(f"error: the poms say {v}, expected {expect}", file=sys.stderr)
        if no_snapshot and v.endswith("-SNAPSHOT"):
            ok = False
            print(f"error: {v} is a snapshot, and a release must not be", file=sys.stderr)
        if ok and not quiet:
            print(f"ok: {len(sites)} version elements in {len(files)} poms all say {v}")
    return ok


def set_version(root, version):
    if not VERSION_RE.match(version):
        raise SystemExit(f"error: {version!r} is not a version like 0.3.0 or 0.3.0-SNAPSHOT")
    files, sites = collect(root)
    by_file = {}
    for s in sites:
        by_file.setdefault(s.path, []).append(s)
    changed = 0
    for path, data in files.items():
        edits = sorted(by_file.get(path, []), key=lambda s: s.start, reverse=True)
        out = data
        touched = False
        for s in edits:
            if s.value == version:
                continue
            out = out[:s.start] + version.encode("utf-8") + out[s.end:]
            touched = True
        if touched:
            with open(path, "wb") as f:
                f.write(out)
            changed += 1
            print(f"set {os.path.relpath(path, root)} -> {version} ({len(edits)} element{'s' if len(edits) != 1 else ''})")
    print(f"{changed} pom{'s' if changed != 1 else ''} changed; {len(sites)} version elements now say {version}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", nargs="?", help="the version to set, e.g. 0.3.0 or 0.4.0-SNAPSHOT")
    ap.add_argument("--check", action="store_true", help="verify every pom already agrees; change nothing")
    ap.add_argument("--expect", metavar="V", help="with --check: the version they must all say")
    ap.add_argument("--no-snapshot", action="store_true", help="with --check: refuse a -SNAPSHOT version")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="the reactor root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if args.check:
        if args.version:
            ap.error("--check takes no version; use --expect V")
        return 0 if check(root, args.expect, args.no_snapshot) else 1
    if not args.version:
        ap.error("a version to set, or --check")
    if args.expect or args.no_snapshot:
        ap.error("--expect and --no-snapshot go with --check")
    set_version(root, args.version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
