#!/usr/bin/env python3
"""No direct setting read outside platform (plan item ST-6, finding F-0025).

  tools/direct-read-scan.py                     # the reactor under the current directory; exit 1 with each hit listed
  tools/direct-read-scan.py --check-allow-list  # the same, and a stale allow-list line is a failure too (CI runs this)
  tools/direct-read-scan.py --root DIR [--allow-list FILE]

build.yml's lint job runs this. From 0.6.0 every setting is read through platform.settings (plan item ST-5): the
resolver reads the environment, the system properties and a servlet's init-params in the order the setting's
catalogue entry gives, strictly, with its superseded names and its file variant. A read beside it skips all of that,
and tools/settings-scan.py, which checks that each name read is catalogued, does not care how it is read. This scan
holds the line: in the main Java code of every module in the root pom's <modules>, each of these is a hit

  System.getenv(...), System.getProperty(...), System.getProperties()   (java.lang.System's, qualified or not,
                          or statically imported and called bare), and Boolean.getBoolean, Integer.getInteger and
                          Long.getLong, which read a system property
  System::getenv, System::getProperty, System::getProperties   the process's lookup handed on as a function: what
                          receives it can read any name, so the hand-over is where the read leaves platform
  getInitParameter(...), getInitParameterNames()   on any receiver (ServletConfig, FilterConfig, ServletContext) or
                          bare, inherited from GenericServlet; and ::getInitParameter handed on. A method that
                          declares one (an implementation of ServletConfig) is not a hit

unless the file is in EXCLUDED (libs/platform, and platform-pf's settings package, whose InitParams is the one
adapter from a servlet's config to a settings source) or the allow-list admits it.

The allow-list, tools/direct-read-allow.txt, has lines of two forms, each under a `# group <name>` line:

  <module>: <why it is never shipped>                   in the group "not shipped" only: every hit in the module is
                                                        admitted. The module is in the reactor and is not one that
                                                        build/pingfederate/stage-modules.sh stages. That is the whole
                                                        of the check: a module shipped another way (a plugin or war
                                                        the release publishes, device-enrolment) is kept out of the
                                                        group by review alone
  <path> | <pattern> | <finding id, or why>             in any other group: a hit in that file whose source line,
                                                        with its comments removed, contains the pattern (whitespace
                                                        runs count as one space) is admitted. A finding id (F-NNNN or
                                                        U-NNNN) must name a file in docs/findings that is not closed:
                                                        a read its finding fixed should have gone with it

A line the scan cannot parse, a path that is not a main source of a reactor module or that EXCLUDED covers already,
a class line in a module the "not shipped" group admits, a finding id with no file or a closed one, and a line given
twice are refused on every run; with --check-allow-list a line that admits no hit (a stale line) is refused too, so
the list shrinks as the reads are converted. Each hit is printed as

  path:line: what it is, and the allow-list line that would admit it

with a GitHub annotation. The pattern suggested is the call as written on that line; the reason is for the author.

What it does not see. It reads Java only, with comments removed and string literals blanked, and matches by name: a
read through reflection, a MethodHandle or `ProcessBuilder.environment()`, a lookup handed on under another name (a
Function built from System.getenv() is seen where System.getenv() is called, not where the Function is applied), and
a class of the same simple name as System in another package are all read as they look. The plugins' relocated copies
of platform (the shade plugin's, at package time) are never in a source tree, so never scanned. Checked with fixtures
in tools/tests/test_direct_read_scan.py.

tools/outbound-scan.py loads this file for its engine (the lexer, the reactor's modules, the allow-list and the
report) and gives its own patterns, exclusions and allow-list.

Exit status: 0 when clean, 1 with a list of problems, 2 when a file cannot be read.
"""
import argparse
import os
import re
import sys

ALLOW_LIST = "tools/direct-read-allow.txt"
STAGE_MODULES = "build/pingfederate/stage-modules.sh"
FINDINGS_DIR = "docs/findings"
NOT_SHIPPED = "not shipped"

# Path prefix, relative to the root -> why nothing under it is scanned.
EXCLUDED = {
    "libs/platform/": "platform: the settings resolver, and the process-wide readers it is built on",
    "libs/platform-pf/src/main/java/com/pingidentity/ps/oidf/platform/pf/settings/":
        "platform-pf's settings package: InitParams, a servlet's or filter's init-params as a settings source",
}

MODULE_RE = re.compile(r"<module>\s*([^<\s]+)\s*</module>")
FINDING_ID = re.compile(r"\b[FU]-\d{4}\b")
MODULE_PATH = re.compile(r"[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)*")
KEYWORDS = {"return", "throw", "new", "else", "case", "yield", "assert", "do"}


# --- the lexer ----------------------------------------------------------------------------------------------------

def strip_java(text):
    """(code, bare): the source with comments blanked, and with string and char literals blanked too (their quotes
    kept). Blanking keeps every character's offset, so an offset in either view is the same in the source."""
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
            bare.append('"' + blank(text[i + 1:j - 1]) + '"' if j - i >= 2 else blank(text[i:j]))
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


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def snippet(text, bare, start, end):
    """The source from `start` to `end`, or, when the match ends at a call's opening parenthesis, to the parenthesis
    that closes it if that is on the same line. Whitespace runs are one space."""
    stop = end
    if end > 0 and bare[end - 1] == "(":
        depth = 0
        for i in range(end - 1, len(bare)):
            c = bare[i]
            if c == "\n":
                break
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    stop = i + 1
                    break
    return normalise(text[start:stop])


def normalise(s):
    return " ".join(s.split())


# --- what this scan looks for -------------------------------------------------------------------------------------

SYSTEM_CALL = re.compile(r"(?<![\w$])System\s*\.\s*(getenv|getProperty|getProperties)\s*\(")
SYSTEM_REF = re.compile(r"(?<![\w$])System\s*::\s*(getenv|getProperty|getProperties)\b")
BOXED_PROPERTY = re.compile(r"(?<![\w$])(Boolean\s*\.\s*getBoolean|Integer\s*\.\s*getInteger|Long\s*\.\s*getLong)\s*\(")
INIT_PARAM_CALL = re.compile(r"(?<![\w$])getInitParameter(Names)?\s*\(")
INIT_PARAM_REF = re.compile(r"::\s*getInitParameter(Names)?\b")
STATIC_IMPORT = re.compile(r"^\s*import\s+static\s+(?:java\.lang\.)?System\s*\.\s*(getenv|getProperty|getProperties|\*)\s*;", re.M)
BARE_CALL = r"(?<![\w$.:])({names})\s*\("

WHAT = {
    "getenv": "reads the environment",
    "getProperty": "reads a system property",
    "getProperties": "takes every system property",
}


def before(bare, offset):
    """The character before `offset`, skipping whitespace, and the identifier that ends there (or '')."""
    i = offset - 1
    while i >= 0 and bare[i] in " \t\r\n":
        i -= 1
    if i < 0:
        return "", ""
    j = i
    while j >= 0 and (bare[j].isalnum() or bare[j] in "_$"):
        j -= 1
    return bare[i], bare[j + 1:i + 1]


def is_declaration(bare, offset):
    """Whether the name at `offset` is declared there (`String getInitParameter(String name) {`), not called."""
    c, word = before(bare, offset)
    if c == ">":
        # The end of a generic return type (`Enumeration<String> getInitParameterNames()`), unless it is the arrow of
        # a lambda or a switch rule (`n -> getInitParameter(n)`, `case 1 -> getenv("X")`), which calls it.
        i = offset - 1
        while bare[i] in " \t\r\n":
            i -= 1
        return not (i > 0 and bare[i - 1] == "-")
    return bool(word) and word not in KEYWORDS and not word[0].isdigit()


def direct_reads(text):
    """Each hit in Java source as (offset, end, what)."""
    code, bare = strip_java(text)
    hits = []
    for m in SYSTEM_CALL.finditer(bare):
        name = m.group(1)
        whole = name == "getenv" and re.match(r"\s*\)", bare[m.end():])
        hits.append((m.start(), m.end(), f"System.{name} " + ("takes the whole environment" if whole else WHAT[name])))
    for m in SYSTEM_REF.finditer(bare):
        hits.append((m.start(), m.end(), f"a System::{m.group(1)} reference hands the process's lookup on"))
    for m in BOXED_PROPERTY.finditer(bare):
        hits.append((m.start(), m.end(), normalise(m.group(1)) + " reads a system property"))
    for m in INIT_PARAM_CALL.finditer(bare):
        if is_declaration(bare, m.start()):
            continue
        start = m.start()
        c, word = before(bare, start)
        if c == ".":
            # Take the receiver into the snippet: config.getInitParameter(...).
            k = start - 1
            while k >= 0 and bare[k] in " \t.":
                k -= 1
            while k >= 0 and (bare[k].isalnum() or bare[k] in "_$"):
                k -= 1
            start = k + 1
        what = "getInitParameterNames takes every init-param" if m.group(1) else "getInitParameter reads an init-param"
        hits.append((start, m.end(), what))
    for m in INIT_PARAM_REF.finditer(bare):
        k = m.start() - 1
        while k >= 0 and (bare[k].isalnum() or bare[k] in "_$"):
            k -= 1
        hits.append((k + 1, m.end(), f"a getInitParameter{m.group(1) or ''} reference hands the init-params on"))
    imported = set(STATIC_IMPORT.findall(bare))
    if imported:
        names = {"getenv", "getProperty", "getProperties"} if "*" in imported else imported
        for m in re.finditer(BARE_CALL.format(names="|".join(sorted(names))), bare):
            if is_declaration(bare, m.start()):
                continue
            hits.append((m.start(), m.end(), f"{m.group(1)} (statically imported from System) {WHAT[m.group(1)]}"))
    return sorted(set(hits))


# --- the reactor, the allow-list and the report ---------------------------------------------------------------------

class Hit:
    def __init__(self, path, line, what, pattern, source_line):
        self.path, self.line, self.what, self.pattern, self.source_line = path, line, what, pattern, source_line
        self.module = None

    def key(self):
        return (self.path, self.line, self.what)


class Line:
    """One allow-list line: a module (`module` set, `path` None) or a class line (`path` and `pattern` set)."""

    def __init__(self, number, group, reason, module=None, path=None, pattern=None, text=""):
        self.number, self.group, self.reason = number, group, reason
        self.module, self.path, self.pattern, self.text = module, path, pattern, text
        self.admitted = 0


def modules_of(root):
    with open(os.path.join(root, "pom.xml"), encoding="utf-8") as f:
        return MODULE_RE.findall(f.read())


def staged_modules(root):
    """The modules build/pingfederate/stage-modules.sh stages: they are shipped whatever a line says."""
    path = os.path.join(root, STAGE_MODULES)
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return set(re.findall(r'"\w+\s+((?:libs|servlets|plugins|services)/[\w./-]+?)/target/', text))


def module_of(path, modules):
    """The reactor module whose src/main holds `path`, the longest match, or None."""
    best = None
    for m in modules:
        if path.startswith(m + "/src/main/") and (best is None or len(m) > len(best)):
            best = m
    return best


def excluded(path, exclusions):
    return next((prefix for prefix in exclusions if path.startswith(prefix)), None)


def sources(root, modules):
    """Every .java file under each module's src/main, as a path relative to the root."""
    out = []
    for module in modules:
        base = os.path.join(root, module, "src", "main")
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames.sort()
            for name in sorted(filenames):
                if name.endswith(".java"):
                    out.append(os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/"))
    return out


def finding_status(root, fid):
    """A finding's status, or None when it has no file."""
    path = os.path.join(root, FINDINGS_DIR, fid + ".yaml")
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        m = re.search(r"^status:\s*(\S+)", f.read(), re.M)
    return m.group(1) if m else ""


def read_allow_list(root, rel):
    """(lines, problems) from the allow-list at `rel`; a missing file is an empty list."""
    path = os.path.join(root, rel)
    if not os.path.isfile(path):
        return [], []
    lines, problems, group, seen = [], [], None, {}
    with open(path, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            text = raw.strip()
            if not text:
                continue
            m = re.fullmatch(r"#\s*group\s+(.+?)\s*", text)
            if m:
                group = m.group(1)
                continue
            if text.startswith("#"):
                continue
            where = f"{rel}:{number}"
            if group is None:
                problems.append(f"{where}: the line is under no `# group` line")
            key = normalise(text)
            if key in seen:
                problems.append(f"{where}: the same line as line {seen[key]}")
            seen[key] = number
            if " | " in text:
                path_part, rest = text.split(" | ", 1)
                if " | " not in rest:
                    problems.append(f"{where}: a class line is `<path> | <pattern> | <finding id, or why>`")
                    continue
                pattern, reason = rest.rsplit(" | ", 1)
                path_part, pattern, reason = path_part.strip(), pattern.strip(), reason.strip()
                if not path_part or not pattern or not reason:
                    problems.append(f"{where}: a class line needs a path, a pattern and a reason")
                    continue
                if group == NOT_SHIPPED:
                    problems.append(f"{where}: the \"{NOT_SHIPPED}\" group takes module lines only")
                lines.append(Line(number, group, reason, path=path_part, pattern=normalise(pattern), text=text))
            else:
                module, _, reason = text.partition(":")
                module, reason = module.strip(), reason.strip()
                if not MODULE_PATH.fullmatch(module):
                    problems.append(f"{where}: {text!r} is neither a module line nor a class line")
                    continue
                if group != NOT_SHIPPED:
                    problems.append(f"{where}: a module line belongs in the \"{NOT_SHIPPED}\" group; admit a shipped"
                                    " module's reads by class, each with its finding or reason")
                if not reason:
                    problems.append(f"{where}: a not-shipped module says why it is never shipped, after a colon")
                lines.append(Line(number, group, reason, module=module, text=text))
    return lines, problems


def check_lines(root, rel, lines, modules, exclusions):
    """Problems with the allow-list's lines that do not depend on the hits."""
    problems = []
    staged = staged_modules(root)
    exempt_modules = {line.module for line in lines if line.module and line.group == NOT_SHIPPED}
    for line in lines:
        where = f"{rel}:{line.number}"
        if line.module:
            if line.module not in modules:
                problems.append(f"{where}: {line.module} is not a module of the reactor")
            elif line.module in staged:
                problems.append(f"{where}: {line.module} is staged by {STAGE_MODULES}, so it is shipped; admit its"
                                " reads by class")
            continue
        prefix = excluded(line.path, exclusions)
        module = module_of(line.path, modules)
        if prefix:
            problems.append(f"{where}: {line.path} is under {prefix}, which the scan does not read")
        elif module is None:
            problems.append(f"{where}: {line.path} is not under the src/main of a reactor module")
        elif not os.path.isfile(os.path.join(root, line.path)):
            problems.append(f"{where}: {line.path} does not exist")
        elif module in exempt_modules:
            problems.append(f"{where}: {module} is admitted whole by its \"{NOT_SHIPPED}\" line")
        for fid in FINDING_ID.findall(line.reason):
            status = finding_status(root, fid)
            if status is None:
                problems.append(f"{where}: {fid} has no file in {FINDINGS_DIR}")
            elif status == "closed":
                problems.append(f"{where}: {fid} is closed; the read it admits should have gone with it - convert"
                                " the read and delete the line")
    return problems


def scan(root, finder, exclusions, allow_rel, check_allow_list=False):
    """(hits, admitted, problems, unreadable): hits not admitted, and how many were."""
    modules = modules_of(root)
    lines, problems = read_allow_list(root, allow_rel)
    problems.extend(check_lines(root, allow_rel, lines, modules, exclusions))
    exempt = {line.module: line for line in lines if line.module and line.group == NOT_SHIPPED}
    by_path = {}
    for line in lines:
        if line.path:
            by_path.setdefault(line.path, []).append(line)
    hits, admitted, unreadable = [], 0, []
    for path in sources(root, modules):
        if excluded(path, exclusions):
            continue
        try:
            with open(os.path.join(root, path), encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as e:
            unreadable.append((path, str(e)))
            continue
        found = finder(text)
        if not found:
            continue
        code, bare = strip_java(text)
        source_lines = text.split("\n")
        code_lines = code.split("\n")
        module = module_of(path, modules)
        for start, end, what in found:
            number = line_of(text, start)
            source_line = normalise(source_lines[number - 1])
            # The pattern is matched against the line with its comments blanked, so a comment cannot admit a hit.
            code_line = normalise(code_lines[number - 1])
            hit = Hit(path, number, what, snippet(text, bare, start, end), source_line)
            hit.module = module
            admits = [line for line in by_path.get(path, []) if line.pattern in code_line]
            if module in exempt:
                exempt[module].admitted += 1
                admitted += 1
            elif admits:
                for line in admits:
                    line.admitted += 1
                admitted += 1
            else:
                hits.append(hit)
    if check_allow_list:
        for line in lines:
            if line.admitted == 0:
                what = line.module or f"{line.path} | {line.pattern}"
                problems.append(f"{allow_rel}:{line.number}: stale: {what} admits no hit; delete the line")
    return hits, admitted, problems, unreadable


def main(argv, doc, finder, exclusions, default_allow, noun, fix):
    parser = argparse.ArgumentParser(description=doc.splitlines()[0])
    parser.add_argument("--root", default=".")
    parser.add_argument("--allow-list", default=default_allow, help="relative to the root")
    parser.add_argument("--check-allow-list", action="store_true", help="a line that admits no hit is a failure")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.root)
    hits, admitted, problems, unreadable = scan(root, finder, exclusions, args.allow_list, args.check_allow_list)
    for path, error in unreadable:
        print(f"{path}: cannot read: {error}", file=sys.stderr)
    for prefix, why in sorted(exclusions.items()):
        print(f"not read: {prefix} ({why})")
    if admitted:
        print(f"admitted by {args.allow_list}: {admitted} hit(s)")
    for hit in hits:
        line = f"{hit.path} | {hit.pattern} | <finding id, or why>"
        print(f"::error file={hit.path},line={hit.line}::{hit.what}: {fix}, or admit it in {args.allow_list}")
        print(f"{hit.path}:{hit.line}: {hit.what}, and the allow-list line that would admit it: {line}",
              file=sys.stderr)
    for problem in problems:
        print(f"::error::{problem}")
        print(problem, file=sys.stderr)
    if hits or problems:
        print(f"{len(hits)} {noun} and {len(problems)} allow-list problem(s)", file=sys.stderr)
        return 1
    if unreadable:
        return 2
    print(f"clean: no {noun} the allow-list does not admit")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], __doc__, direct_reads, EXCLUDED, ALLOW_LIST,
                  "direct read(s) outside platform", "read it through platform.settings"))
