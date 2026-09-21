#!/usr/bin/env python3
"""Binary linkage check: will these built artifacts LINK against a given PingFederate?

Answers the question a version bump actually asks - not "does it compile against the new jars"
but "does the jar I already built resolve every PingFederate and servlet member it references".
It reads what the JVM will link (constant pools, via `javap -v`), not what grep guesses from
imports, and resolves each Methodref / InterfaceMethodref / Fieldref owner+name+descriptor
against the target classpath with `javap -s -p`, walking superclasses and interfaces. Jars nested
in a war's WEB-INF/lib are opened too.

It was written for docs/pf-13_1-jakarta-migration-plan.md, which records what it found.

  # extract a PingFederate without running it (running needs a licence, extracting does not)
  id=$(docker create pingidentity/pingfederate:13.1.3-alpine_3.24.1-al21-latest)
  docker cp "$id:/opt/server" /tmp/pf131 && docker rm "$id"

  mvn -q -DskipTests package
  tools/pf-linkcheck.py --pf /tmp/pf131 --reactor .        # every artifact this repo ships
  tools/pf-linkcheck.py --pf /tmp/pf131 some.jar other.war  # or name them

  # CI extracts directories of jars rather than a whole /opt/server; point at those instead.
  # BOTH are needed: PF's own jars, and /opt/server/lib, where the servlet API jars live.
  tools/pf-linkcheck.py --lib pf-lib --lib pf-jetty-lib --reactor .

Exit status is 1 when anything is unresolved, or when an artifact had classes but none of this
repo's own - "checked nothing" must never read as "clean".

WHAT IT DOES NOT SEE. Linking is not loading. A class that implements javax.servlet.Filter links
perfectly well on PingFederate 13.1, which still ships the javax servlet API jar - and is then
refused by Jetty's ee9 container, which wants a jakarta.servlet.Filter. Nor does it see anything
named by a string (OGNL expressions, log4j logger names, web.xml class names, reflection), or an
annotation such as @Deprecated(forRemoval=true). Always run it against the PingFederate the
artifacts were BUILT for first: that run must report zero, or the tool is what is broken. Its
first version mis-split `extends HashMap<String, V>` on the comma and reported an inherited
method as missing; its second reported a war "clean" without opening the jars inside it.
"""
import argparse
import functools
import glob
import os
import re
import subprocess
import sys
import tempfile
import zipfile

# this repo's own packages: the classes whose references are checked
OWN = ("com/pingidentity/ps/", "au/com/idpartners/")
# owners whose members must resolve on the target PingFederate
WATCH = ("javax/servlet/", "jakarta/servlet/", "com/pingidentity/", "org/sourceid/")

REF = re.compile(r"=\s+(Methodref|InterfaceMethodref|Fieldref)\s+\S+\s+//\s+(\S+?)\.(\"?<?[\w$]+>?\"?):(\S+)")
CLS = re.compile(r"=\s+Class\s+\S+\s+//\s+\"?([\w/$\[;]+)\"?")
DECL = re.compile(r"^(?:public |final |abstract |super )*(?:class|interface|enum)\s+([\w.$]+)")
NOT_SHIPPED = re.compile(r"(^original-|-tests\.jar$|-sources\.jar$|-javadoc\.jar$)")


def watched(owner):
    return owner.startswith(WATCH) and not owner.startswith(OWN)


def classpath_of(pf_roots, lib_dirs):
    dirs = list(lib_dirs)
    for root in pf_roots:
        dirs += [os.path.join(root, "server/default/lib"), os.path.join(root, "lib")]
    jars = sorted(j for d in dirs for j in glob.glob(os.path.join(d, "*.jar")))
    if not jars:
        sys.exit(f"ERROR: no jars found in {dirs} - point --pf at an extracted /opt/server, or --lib at directories of jars")
    return os.pathsep.join(jars)


def reactor_artifacts(root):
    """What this repo ships into PingFederate: the module and library jars, both wars, the plugins."""
    found = []
    for pattern in ("servlets/*/target/*.jar", "libs/*/target/*.jar", "plugins/*/target/pf.plugins.*.jar",
                    "servlets/oidf-war/target/oidf.war", "services/gm-api/servlet/target/gm-api.war"):
        found += [p for p in sorted(glob.glob(os.path.join(root, pattern)))
                  if not NOT_SHIPPED.search(os.path.basename(p))]
    if not found:
        sys.exit(f"ERROR: no built artifacts under {root} - run 'mvn -q -DskipTests package' first")
    return found


def make_resolver(cp):
    @functools.lru_cache(maxsize=None)
    def describe(owner):
        """-> (exists, {(name, descriptor)}, (supertypes...))"""
        out = subprocess.run(["javap", "-s", "-p", "-cp", cp, owner.replace("/", ".")],
                             capture_output=True, text=True)
        if "class not found" in (out.stdout + out.stderr) or not out.stdout.strip():
            return (False, frozenset(), ())
        lines = out.stdout.splitlines()
        members = set()
        for i, line in enumerate(lines):
            if i and line.strip().startswith("descriptor:"):
                desc = line.split("descriptor:")[1].strip()
                decl = lines[i - 1].strip().rstrip(";")
                if "(" in decl:
                    name = decl.split("(")[0].split()[-1]
                    if "." in name:          # a constructor prints as the FQCN
                        name = "<init>"
                else:
                    name = decl.split()[-1]
                members.add((name, desc))
        head = next((l for l in lines if re.search(r"\b(class|interface)\b", l) and "{" in l), "")
        # Strip generics BEFORE splitting on commas: `extends HashMap<String, AttributeValue>`
        # otherwise becomes two bogus supertypes and every inherited member looks unresolved.
        while re.search(r"<[^<>]*>", head):
            head = re.sub(r"<[^<>]*>", "", head)
        supers = []
        m = re.search(r"\bextends\s+([^{]+?)(\s+implements|\s*\{)", head)
        if m:
            supers += [s.strip() for s in m.group(1).split(",")]
        m = re.search(r"\bimplements\s+([^{]+?)\s*\{", head)
        if m:
            supers += [s.strip() for s in m.group(1).split(",")]
        return (True, frozenset(members), tuple(s.replace(".", "/") for s in supers))

    def resolves(owner, name, desc, seen=None):
        seen = seen if seen is not None else set()
        if owner in seen:
            return False
        seen.add(owner)
        ok, members, supers = describe(owner)
        if not ok:
            return False
        return (name.strip('"'), desc) in members or any(resolves(s, name, desc, seen) for s in supers)

    return describe, resolves


def class_files(artifact, workdir, depth=0):
    """-> (own class files, total class count), opening jars nested in WEB-INF/lib one level down."""
    own, total = [], 0
    with zipfile.ZipFile(artifact) as z:
        names = z.namelist()
        classes = [n for n in names if n.endswith(".class")]
        nested = [n for n in names if n.startswith("WEB-INF/lib/") and n.endswith(".jar")] if depth == 0 else []
        z.extractall(workdir, classes + nested)
    total += len(classes)
    for n in classes:
        rel = n[len("WEB-INF/classes/"):] if n.startswith("WEB-INF/classes/") else n
        if rel.startswith(OWN):
            own.append(os.path.join(workdir, n))
    for n in nested:
        sub = os.path.join(workdir, "_nested", os.path.basename(n))
        os.makedirs(sub, exist_ok=True)
        o, t = class_files(os.path.join(workdir, n), sub, depth + 1)
        own += o
        total += t
    return own, total


def scan(files):
    refs, classes = {}, {}
    for i in range(0, len(files), 200):
        txt = subprocess.run(["javap", "-v", "-p"] + files[i:i + 200], capture_output=True, text=True).stdout
        cur = None
        for line in txt.splitlines():
            if line.startswith("Classfile "):
                cur = None
            d = DECL.match(line.strip())
            if d and cur is None:
                cur = d.group(1)
            r = REF.search(line)
            if r and watched(r.group(2)):
                refs.setdefault(r.groups(), set()).add(cur)
            c = CLS.search(line)
            if c and watched(c.group(1)) and not c.group(1).startswith("["):
                classes.setdefault(c.group(1), set()).add(cur)
    return refs, classes


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--pf", action="append", default=[], metavar="DIR",
                    help="an extracted /opt/server from a PingFederate image (repeatable)")
    ap.add_argument("--lib", action="append", default=[], metavar="DIR",
                    help="a directory of PingFederate jars, for when only lib dirs were extracted (repeatable)")
    ap.add_argument("--reactor", metavar="DIR", help="check every artifact this repo ships, found under DIR")
    ap.add_argument("artifacts", nargs="*", help="built .jar / .war files to check")
    args = ap.parse_args()
    if not (args.pf or args.lib):
        ap.error("give --pf and/or --lib")
    artifacts = (reactor_artifacts(args.reactor) if args.reactor else []) + args.artifacts
    if not artifacts:
        ap.error("give --reactor DIR and/or artifact paths")

    describe, resolves = make_resolver(classpath_of(args.pf, args.lib))
    users = lambda s: ", ".join(sorted(u.split(".")[-1] for u in s if u))
    total = unchecked = 0
    for art in artifacts:
        with tempfile.TemporaryDirectory() as wd:
            files, all_classes = class_files(art, wd)
            refs, classes = scan(files)
        print(f"\n=== {art}")
        if all_classes == 0:
            print("    skipped: the archive holds no classes")
            continue
        if not files:
            print(f"    ERROR: {all_classes} classes, none under {OWN} - NOTHING WAS CHECKED")
            unchecked += 1
            continue
        bad_cls = sorted(o for o in classes if not describe(o)[0])
        bad_ref = sorted(k for k in refs if k[1] not in bad_cls and not resolves(k[1], k[2], k[3]))
        print(f"    own classes: {len(files)}   watched class refs: {len(classes)}   watched member refs: {len(refs)}")
        print(f"    UNRESOLVED classes: {len(bad_cls)}   UNRESOLVED members: {len(bad_ref)}")
        for o in bad_cls:
            print(f"      class  {o}    <- {users(classes[o])}")
        for k in bad_ref:
            print(f"      member {k[1]}.{k[2]}:{k[3]}    <- {users(refs[k])}")
        total += len(bad_cls) + len(bad_ref)
    print(f"\nTOTAL unresolved: {total}" + (f"   artifacts with nothing checked: {unchecked}" if unchecked else ""))
    return 1 if (total or unchecked) else 0


if __name__ == "__main__":
    sys.exit(main())
