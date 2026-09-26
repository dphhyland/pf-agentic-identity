#!/usr/bin/env python3
"""The libraries PingFederate ships are the ones the BOM compiles against.

  tools/pf-provided-versions.py --lib pf-lib --bom bom/pom.xml                # exit 1 on a mismatch
  tools/pf-provided-versions.py --lib pf-lib --bom bom/pom.xml --report-only  # print, exit 0
  tools/pf-provided-versions.py --lib pf-lib                                  # just list what PF ships

The staged modules bundle none of jackson, jose4j, commons-lang3, commons-logging or log4j: at run
time they get PF's copies from server/default/lib. So the version a module compiles against ought to
be the version it will run on, and the BOM writes that down as version.pf.<library>. This compares
the two. PF names its jars without a version (jackson-databind.jar, not jackson-databind-2.21.1.jar),
so the version is read from inside each jar: Implementation-Version in its manifest, then
Bundle-Version, then META-INF/maven/*/pom.properties, and only then a version in the file name.

The lib directory is the image's server/default/lib, extracted the way the composite action does it
(docker create, docker cp; running PF needs a licence, extracting does not) - `--lib` may be given
more than once when the jars are spread over directories.

Exit status: 0 when every property matches (or with --report-only), 1 on a mismatch or a library the
lib directories do not hold, 2 when the BOM lacks a version.pf.* property this expects.
"""
import argparse
import glob
import os
import re
import sys
import zipfile

# BOM property -> the jar (by base name) whose version it must equal
LIBRARIES = {
    "version.pf.jackson": "jackson-databind",
    "version.pf.jose4j": "jose4j",
    "version.pf.commons-lang3": "commons-lang3",
    "version.pf.commons-logging": "commons-logging",
    "version.pf.log4j": "log4j-api",
}


def find_jar(lib_dirs, name):
    """`name.jar` first (how PF names them), then `name-<digits>...jar` (how Maven would)."""
    for d in lib_dirs:
        exact = os.path.join(d, name + ".jar")
        if os.path.isfile(exact):
            return exact
    for d in lib_dirs:
        hits = sorted(glob.glob(os.path.join(d, name + "-[0-9]*.jar")))
        if hits:
            return hits[0]
    return None


def jar_version(path):
    """The version a jar says it is, from the most authoritative place that has one."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        if "META-INF/MANIFEST.MF" in names:
            manifest = z.read("META-INF/MANIFEST.MF").decode("utf-8", errors="replace")
            for key in ("Implementation-Version", "Bundle-Version"):
                m = re.search(r"^%s:\s*(\S+)" % key, manifest, re.M)
                if m:
                    return m.group(1)
        props = [n for n in names if n.startswith("META-INF/maven/") and n.endswith("/pom.properties")]
        for n in sorted(props):
            text = z.read(n).decode("utf-8", errors="replace")
            m = re.search(r"^version=(\S+)", text, re.M)
            if m:
                return m.group(1)
    m = re.search(r"-([0-9][0-9A-Za-z.]*)\.jar$", os.path.basename(path))
    return m.group(1) if m else None


def bom_properties(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return dict(re.findall(r"<(version\.pf\.[A-Za-z0-9-]+)>\s*([^<\s]+)\s*</\1>", text))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lib", action="append", required=True, metavar="DIR", help="a directory of PF's jars (repeatable)")
    ap.add_argument("--bom", metavar="POM", help="the BOM whose version.pf.* properties to compare")
    ap.add_argument("--report-only", action="store_true", help="print the comparison, never fail on it")
    args = ap.parse_args(argv)

    for d in args.lib:
        if not os.path.isdir(d):
            print(f"error: {d} is not a directory", file=sys.stderr)
            return 2

    shipped = {}
    missing = []
    for prop, name in LIBRARIES.items():
        jar = find_jar(args.lib, name)
        if jar is None:
            missing.append(name)
            continue
        shipped[prop] = (name, jar_version(jar), jar)

    if not args.bom:
        for prop, (name, version, jar) in shipped.items():
            print(f"{name}\t{version}\t{jar}")
        for name in missing:
            print(f"{name}\t(not found)")
        return 1 if missing else 0

    props = bom_properties(args.bom)
    absent = [p for p in LIBRARIES if p not in props]
    if absent:
        print(f"error: {args.bom} lacks {', '.join(absent)}", file=sys.stderr)
        return 2

    mismatches = []
    for prop, name in LIBRARIES.items():
        want = props[prop]
        if prop not in shipped:
            print(f"{name:18} BOM {want:10} image (not found)")
            mismatches.append(name)
            continue
        _, got, jar = shipped[prop]
        mark = "ok" if got == want else "MISMATCH"
        print(f"{name:18} BOM {want:10} image {str(got):10} {mark}   {os.path.basename(jar)}")
        if got != want:
            mismatches.append(name)

    if mismatches:
        verdict = f"{len(mismatches)} PF-provided librar{'y' if len(mismatches) == 1 else 'ies'} differ from the BOM: {', '.join(mismatches)}"
        if args.report_only:
            print(f"report-only: {verdict}")
            return 0
        print(f"error: {verdict}", file=sys.stderr)
        return 1
    print(f"ok: the {len(LIBRARIES)} PF-provided libraries the BOM names are the ones the image ships")
    return 0


if __name__ == "__main__":
    sys.exit(main())
