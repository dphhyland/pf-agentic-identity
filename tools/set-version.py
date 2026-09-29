#!/usr/bin/env python3
"""One project version across the reactor: set it, or check that every pom already agrees.

  tools/set-version.py 0.3.0                      # rewrite every version element to 0.3.0, and stamp the
                                                  # outputTimestamp with HEAD's commit time
  tools/set-version.py 0.3.0 --timestamp T        # ... with the timestamp T instead (2026-09-29T03:30:00Z)
  tools/set-version.py 0.4.0-SNAPSHOT             # a snapshot: the fixed snapshot outputTimestamp
  tools/set-version.py --check                    # every version element is the same one
  tools/set-version.py --check --expect 0.3.0     # ... and it is this one
  tools/set-version.py --check --no-snapshot      # ... and it is not a -SNAPSHOT (a release)

Twenty poms carry the version, and until this existed a bump was twenty hand edits: the aggregator
and each module's own <version>, the BOM's <version.internal> (what the internal dependencies resolve
to), and the BOM import each module makes (an import's version is written where it is imported, not
where it is defined). gm-api is a module like the others here - its <version> and its BOM import -
though its groupId is au.com.idpartners, not the reactor's. One missed edit is a reactor that builds
a module against a stale copy of its neighbour from ~/.m2, which is exactly the kind of failure no
test notices.

What counts as a version element, decided from the XML and not from a regex over the file:
  - project/version                                                   every pom
  - project/properties/version.internal                               the BOM
  - a dependencyManagement import of pf-agentic-identity-bom          the module poms
  - a dependency on a com.pingidentity.ps.oidf artifact whose version is a literal (not ${...})
                                                                      none today (gm-api's conformance
                                                                      test dependency was one until it
                                                                      imported the BOM); kept so a literal
                                                                      one moves with the rest
The poms are the aggregator's <modules> plus the aggregator itself, so a module the reactor does not
build is not touched, and a new module joins the moment it is listed.

The outputTimestamp. Every pom also carries project/properties/project.build.outputTimestamp, the date
maven-jar, -war, -shade and -assembly write on every archive entry instead of the file's mtime. Without
it a jar's bytes depend on when its classes were compiled, and the release's `mvn deploy` - which
recompiles any module whose reactor dependency it has just rebuilt - published 12 jars that differed
from the ones `mvn verify` had built and dist/ held (the v0.5.0 Release, run 36518030296). No parent pom
is shared, so the property is in each pom, and this tool keeps them in step with the version:
  - a release version gets HEAD's committer time, in UTC, at the moment of the bump (or --timestamp).
    That is the last commit before the release, so bumping twice on one commit writes the same poms,
    and the value comes from the repository rather than from the clock of whoever ran the bump;
  - a -SNAPSHOT gets SNAPSHOT_TIMESTAMP, a fixed date that says it is not a release's.
--check holds every pom to one value, in the form 2026-09-29T03:30:00Z (UTC, whole seconds, inside
the range maven-archiver accepts), and to the pairing: a snapshot carries SNAPSHOT_TIMESTAMP and a
release does not. So a release made by editing the versions by hand from a snapshot, without this
tool, fails --check rather than shipping jars dated by the snapshot.

Edits are text-preserving: the parser (expat) reports where each element's text begins, and only
those bytes are replaced, so comments, whitespace and attribute order are exactly as they were. The
version is never taken from a file name or a directory name.

Exit status: 0 when the poms agree (or were rewritten), 1 when --check finds a disagreement, 2 for a
usage or parse error.
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import xml.parsers.expat

BOM_ARTIFACT = "pf-agentic-identity-bom"
INTERNAL_GROUP = "com.pingidentity.ps.oidf"
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$")

TIMESTAMP = "output timestamp"      # the Site kind of project/properties/project.build.outputTimestamp
TIMESTAMP_PROPERTY = "project.build.outputTimestamp"
TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
# A snapshot's outputTimestamp: fixed, so a snapshot build is reproducible too, and plainly not a release's.
SNAPSHOT_TIMESTAMP = "2000-01-01T00:00:00Z"
# The range maven-archiver 3.6 and later accept: a zip entry's DOS date cannot say anything earlier.
TIMESTAMP_MIN = datetime.datetime(1980, 1, 1, 0, 0, 2, tzinfo=datetime.timezone.utc)
TIMESTAMP_MAX = datetime.datetime(2099, 12, 31, 23, 59, 59, tzinfo=datetime.timezone.utc)


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
            elif path_names == ("project", "properties", TIMESTAMP_PROPERTY):
                sites.append(Site(path, TIMESTAMP, start_b, end_b, stripped))
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
    """All version and outputTimestamp Sites across the reactor, and the file bytes they index into."""
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


def parse_timestamp(value):
    """The instant a TIMESTAMP_RE value names, or None when it is not one maven-archiver would accept."""
    if not TIMESTAMP_RE.match(value):
        return None
    try:
        t = datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
    except ValueError:          # the right shape but not a date, e.g. 2026-02-30T00:00:00Z
        return None
    return t if TIMESTAMP_MIN <= t <= TIMESTAMP_MAX else None


def format_timestamp(epoch_seconds):
    return datetime.datetime.fromtimestamp(int(epoch_seconds), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def head_timestamp(root):
    """HEAD's committer time in UTC: the last commit before the release bump."""
    try:
        out = subprocess.run(["git", "-C", root, "log", "-1", "--format=%ct", "HEAD"],
                             capture_output=True, text=True, check=True).stdout.strip()
        return format_timestamp(int(out))
    except (OSError, subprocess.CalledProcessError, ValueError):
        raise SystemExit(f"error: cannot read HEAD's commit time in {root}; give the release's "
                         f"outputTimestamp with --timestamp, e.g. --timestamp 2026-09-29T03:30:00Z")


def check_timestamps(root, files, stamps, version):
    """Every pom has one outputTimestamp, they agree, it parses, and it pairs with the version."""
    ok = True
    counts = {}
    for s in stamps:
        counts[s.path] = counts.get(s.path, 0) + 1
    for p in files:
        n = counts.get(p, 0)
        if n != 1:
            ok = False
            what = "no" if n == 0 else f"{n}"
            print(f"error: {os.path.relpath(p, root)} has {what} <{TIMESTAMP_PROPERTY}> in its <properties>; "
                  f"every pom needs exactly one, or its archives are dated by the clock", file=sys.stderr)
    values = sorted({s.value for s in stamps})
    if len(values) > 1:
        print(f"error: the poms do not agree on one {TIMESTAMP_PROPERTY}:", file=sys.stderr)
        for s in stamps:
            print(f"  {os.path.relpath(s.path, root)}: {s.value}", file=sys.stderr)
        return False
    if not values:
        return False
    value = values[0]
    if parse_timestamp(value) is None:
        print(f"error: {TIMESTAMP_PROPERTY} {value!r} is not a UTC time like 2026-09-29T03:30:00Z "
              f"between 1980-01-01T00:00:02Z and 2099-12-31T23:59:59Z", file=sys.stderr)
        return False
    if version is not None:
        snapshot = version.endswith("-SNAPSHOT")
        if snapshot and value != SNAPSHOT_TIMESTAMP:
            ok = False
            print(f"error: {version} is a snapshot, so its {TIMESTAMP_PROPERTY} is {SNAPSHOT_TIMESTAMP}, "
                  f"not {value}; set the version with tools/set-version.py", file=sys.stderr)
        if not snapshot and value == SNAPSHOT_TIMESTAMP:
            ok = False
            print(f"error: {version} is a release, but its {TIMESTAMP_PROPERTY} is still the snapshot's "
                  f"{SNAPSHOT_TIMESTAMP}; set the version with tools/set-version.py {version}", file=sys.stderr)
    return ok and value


def check(root, expect=None, no_snapshot=False, quiet=False):
    files, all_sites = collect(root)
    sites = [s for s in all_sites if s.kind != TIMESTAMP]
    stamps = [s for s in all_sites if s.kind == TIMESTAMP]
    values = sorted({s.value for s in sites})
    ok = True
    v = None
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
    stamp = check_timestamps(root, files, stamps, v)
    if not stamp:
        ok = False
    if ok and not quiet:
        print(f"ok: {len(sites)} version elements in {len(files)} poms all say {v}, "
              f"and all {len(stamps)} say {TIMESTAMP_PROPERTY} {stamp}")
    return ok


def set_version(root, version, timestamp=None):
    if not VERSION_RE.match(version):
        raise SystemExit(f"error: {version!r} is not a version like 0.3.0 or 0.3.0-SNAPSHOT")
    snapshot = version.endswith("-SNAPSHOT")
    if timestamp is not None:
        if snapshot:
            raise SystemExit(f"error: --timestamp is for a release; a snapshot's {TIMESTAMP_PROPERTY} "
                             f"is always {SNAPSHOT_TIMESTAMP}")
        if parse_timestamp(timestamp) is None:
            raise SystemExit(f"error: --timestamp {timestamp!r} is not a UTC time like 2026-09-29T03:30:00Z "
                             f"between 1980-01-01T00:00:02Z and 2099-12-31T23:59:59Z")
    files, sites = collect(root)
    # Every pom must already have the property: an edit here replaces text, it never inserts an element.
    missing = sorted(os.path.relpath(p, root) for p in files
                     if not any(s.path == p and s.kind == TIMESTAMP for s in sites))
    if missing:
        raise SystemExit(f"error: no <{TIMESTAMP_PROPERTY}> in the <properties> of {', '.join(missing)}; "
                         f"add one, with any value, and run this again")
    stamp = SNAPSHOT_TIMESTAMP if snapshot else (timestamp or head_timestamp(root))
    by_file = {}
    for s in sites:
        by_file.setdefault(s.path, []).append(s)
    changed = 0
    for path, data in files.items():
        edits = sorted(by_file.get(path, []), key=lambda s: s.start, reverse=True)
        out = data
        touched = False
        for s in edits:
            new = stamp if s.kind == TIMESTAMP else version
            if s.value == new:
                continue
            out = out[:s.start] + new.encode("utf-8") + out[s.end:]
            touched = True
        if touched:
            with open(path, "wb") as f:
                f.write(out)
            changed += 1
            print(f"set {os.path.relpath(path, root)} -> {version}, {stamp} ({len(edits)} element{'s' if len(edits) != 1 else ''})")
    versions = sum(1 for s in sites if s.kind != TIMESTAMP)
    print(f"{changed} pom{'s' if changed != 1 else ''} changed; {versions} version elements now say {version}, "
          f"and {len(files)} {TIMESTAMP_PROPERTY} say {stamp}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", nargs="?", help="the version to set, e.g. 0.3.0 or 0.4.0-SNAPSHOT")
    ap.add_argument("--check", action="store_true", help="verify every pom already agrees; change nothing")
    ap.add_argument("--expect", metavar="V", help="with --check: the version they must all say")
    ap.add_argument("--no-snapshot", action="store_true", help="with --check: refuse a -SNAPSHOT version")
    ap.add_argument("--timestamp", metavar="T",
                    help="with a release version: the outputTimestamp to write, e.g. 2026-09-29T03:30:00Z "
                         "(default: HEAD's committer time, in UTC)")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="the reactor root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if args.check:
        if args.version:
            ap.error("--check takes no version; use --expect V")
        if args.timestamp:
            ap.error("--timestamp goes with a version to set, not --check")
        return 0 if check(root, args.expect, args.no_snapshot) else 1
    if not args.version:
        ap.error("a version to set, or --check")
    if args.expect or args.no_snapshot:
        ap.error("--expect and --no-snapshot go with --check")
    set_version(root, args.version, args.timestamp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
