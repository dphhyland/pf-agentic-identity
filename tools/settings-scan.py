#!/usr/bin/env python3
"""Every setting the code reads is catalogued, and every catalogued setting is read (plan item ST-3).

  tools/settings-scan.py                 # the reactor under the current directory; exit 1 with each problem listed
  tools/settings-scan.py --root DIR
  tools/settings-scan.py --list          # every read the scan sees, as `kind name  module/path:line`, then exit 0

build.yml's lint job runs this. A catalogue is one JSON document per component at
src/main/resources/META-INF/oidf-settings/<component>.json in the module that reads the settings
(docs/development/settings-catalogue.md). The scan reads the main Java sources of every module in the root pom's
<modules>, and every catalogue there, and checks both ways:

  code to catalogue    every name a module reads is declared by some catalogue, in the kind it is read as - unless
                       the module is exempt (below) or the name is in NOT_SETTINGS
  catalogue to code    every name a catalogue declares is read somewhere in the reactor, and at least once in the
                       catalogue's own module; the catalogue's package has at least one of its reads
  once                 a name is declared by one catalogue only, whichever modules read it: the component that
                       owns it catalogues it, and the others read it under the same name
  well formed          each catalogue parses, names its own module and component, and has the members and shapes
                       the loader in platform.settings requires (the loader is the full check, run by ST-4's
                       generator and at run time; this is the part the scan needs to trust the names)

What counts as a read, in main Java code with comments removed:

  an OIDF_ literal      a string literal that is nothing but an environment variable's name under OIDF_, such as
                        "OIDF_PDP_MODE" - read as env. A literal is a read only when the name is the whole of it,
                        so a message that mentions a name ("set OIDF_PDP_URL") is not one, and neither is a prefix
                        ending in an underscore ("OIDF_SSF_"). The rule is the one ConfigurationDocumentedTest has
                        used since 2026-08: in main code a bare OIDF_ literal exists only to name the variable.
  a read call           System.getenv(x) (env); System.getProperty(x), Boolean.getBoolean(x), Integer.getInteger(x)
                        and Long.getLong(x) (system-property); getInitParameter(x) on anything (init-param); the
                        PingFederate plugin configuration's getFieldValue family and a FieldDescriptor's
                        constructor (plugin-field); and `env.apply(x)`, `props.apply(x)` and `initParams.apply(x)`
                        on a function whose name says which source it is (see APPLY_RECEIVERS). x is a literal, a
                        String constant (static final, in the same class, a named class or a static import, alias
                        chains followed), or a name derived by Parsers.systemPropertyName(x) - directly or through
                        a method that returns it.
  a helper's argument   a method whose parameter reaches a read call, or another helper, unchanged (or through a
                        for-each over a varargs parameter) is a helper, found by the scan to a fixpoint; a literal
                        or constant passed in that position is a read of that kind. So HostedEntityServlet's
                        setting(initParams, "openBaoUrl", "oidf.openbao.url", "OIDF_OPENBAO_URL") reads an
                        init-param, a system property and an environment variable. A helper is matched by name and
                        arity: a bare call in its own class, or Class.method(...) anywhere.
  an extended property  a literal that is "extproperties.<name>" (how PingFederate's OGNL context names a client's
                        extended property) and each element of the lists in EXTENDED_PROPERTY_LISTS (the names a
                        module writes onto a client) - read as extended-property <name>.

A read call whose argument is none of those (a local variable, an expression) is itself a problem - "a read the
scan cannot name" - so a new way of reading a setting cannot slip past; give the name a constant, or read it
through a helper whose parameter carries it.

Catalogue to code uses the same reads, with one widening: a plugin-field or extended-property entry also counts as
read when its name is the whole of a string literal in some module's main code, because a plugin's field and a
client's property are often read through a map by a constant (attestation-issuer's P_* constants) that no rule
above can tell from any other string.

The exemption file, tools/settings-scan-exemptions.txt, lists modules the scan does not hold to code-to-catalogue
yet, one per line under a `# group <name>` comment line for the package that will catalogue them, and a
"not shipped" group whose lines give a reason after a colon. A missing file means no exemptions. The scan refuses
an exemption for a module not in the reactor, for one that already has a catalogue (a stale line), for one that
reads nothing, and a "not shipped" line without a reason or naming a module build/pingfederate/stage-modules.sh
stages. The line `refuse-shipped-exemptions: yes` (ST-4 sets it) refuses every exemption outside the "not
shipped" group.

What it does not see. It reads Java only, and only the shapes above: a name built by concatenation or formatting
(servlets/ssf's param() builds its system property and environment names from the init-param's - ST3C adds that
rule), a Spring or MicroProfile binding, a read in a shell script or a Dockerfile, and a name passed through a
field or a collection other than the lists named here are not reads to it. Method matching is by name and arity,
so an overload of a helper with the same arity is taken for the helper. Checked with fixtures in
tools/tests/test_settings_scan.py.

Exit status: 0 when clean, 1 with a list of problems, 2 when a file cannot be read or parsed.
"""
import argparse
import glob
import json
import os
import re
import sys

EXEMPTIONS = "tools/settings-scan-exemptions.txt"
STAGE_MODULES = "build/pingfederate/stage-modules.sh"
CATALOGUE_DIR = "src/main/resources/META-INF/oidf-settings"
NOT_SHIPPED = "not shipped"

KINDS = ("env", "system-property", "init-param", "plugin-field", "extended-property")
SOURCE_KINDS = ("env", "system-property", "init-param")
SCOPED_KINDS = ("init-param", "plugin-field")

# Names read in main code that are not operator settings, by (kind, name) -> why. Nothing else is excused.
NOT_SETTINGS = {
    ("system-property", "oidf.registration.sweeper.owner"):
        "a JVM-wide latch: RegistrationExpirySweeper sets it so that one sweeper runs per JVM, and reads it back; an"
        " operator never sets it (one who did would stop the sweeper - F-0196)",
    ("system-property", "jdk.internal.httpclient.disableHostnameVerification"):
        "the JDK's own flag, which InsecureTls reads to report and PR-2 forbids in production; a catalogue cannot"
        " declare it, because the format's system-property names are lower case (F-0195)",
}

# Static final collections whose elements are extended-property names a module writes onto a client:
# (class simple name, field) -> why.
EXTENDED_PROPERTY_LISTS = {
    ("FederationClientParams", "EXTENDED_PARAM_NAMES"): "what pf-integration writes onto a federation client",
    ("PfIssuanceClientResolver", "PROPERTY_KEYS"): "what attestation-issuer reads off an issuance client",
}

# `<receiver>.apply(x)`: the function's name says which source it reads.
APPLY_RECEIVERS = {
    "env": "env", "environment": "env", "getenv": "env",
    "props": "system-property", "properties": "system-property", "sysProps": "system-property",
    "systemProperties": "system-property",
    "initParams": "init-param", "initParameters": "init-param",
}

# Read calls: method name -> (kind, receiver it must have, or None for any receiver).
READ_CALLS = {
    "getenv": ("env", "System"),
    "getProperty": ("system-property", "System"),
    "getBoolean": ("system-property", "Boolean"),
    "getInteger": ("system-property", "Integer"),
    "getLong": ("system-property", "Long"),
    "getInitParameter": ("init-param", None),
    "getFieldValue": ("plugin-field", None),
    "getBooleanFieldValue": ("plugin-field", None),
    "getIntFieldValue": ("plugin-field", None),
    "getLongFieldValue": ("plugin-field", None),
    "getDoubleFieldValue": ("plugin-field", None),
}
DERIVED = "derived-system-property"

OIDF_ENV_LITERAL = re.compile(r"OIDF_[A-Z0-9]+(?:_[A-Z0-9]+)*")
EXTPROPERTY_LITERAL = re.compile(r"extproperties\.([A-Za-z][A-Za-z0-9_]*)")
MODULE_RE = re.compile(r"<module>\s*([^<\s]+)\s*</module>")
PACKAGE_RE = re.compile(r"^\s*package\s+([\w.]+)\s*;", re.M)
STATIC_IMPORT_RE = re.compile(r"^\s*import\s+static\s+([\w.]+)\.(\w+)\s*;", re.M)
CONSTANT_RE = re.compile(r"((?:\b(?:public|protected|private|static|final)\s+)+)String\s+(\w+)\s*=\s*([^;]+);")
COLLECTION_RE = r"\b{field}\s*=\s*(?:(?:java\.util\.)?(?:List|Set)\.of\s*\(|\{{)"
KEYWORDS = {"if", "for", "while", "switch", "catch", "synchronized", "return", "new", "else", "try", "do", "throw",
            "super", "this", "assert", "case", "yield"}
METHOD_RE = re.compile(r"(?<![\w.$])(\w+)\s*\(")
CALL_RE = re.compile(r"(?<![\w$])(\w+)\s*\(")
IDENT = re.compile(r"[A-Za-z_$][\w$]*")
QUALIFIED_CONSTANT = re.compile(r"(?:[a-z_][\w]*\.)*([A-Z][\w$]*)\.([A-Za-z_$][\w$]*)")
LITERAL = re.compile(r'"((?:[^"\\\n]|\\.)*)"')

ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "s": " ", "0": "\0", "\\": "\\", "'": "'", '"': '"'}


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def unescape(body):
    out, i = [], 0
    while i < len(body):
        c = body[i]
        if c == "\\" and i + 1 < len(body):
            nxt = body[i + 1]
            if nxt == "u" and re.match(r"u+[0-9a-fA-F]{4}", body[i + 1:]):
                m = re.match(r"u+([0-9a-fA-F]{4})", body[i + 1:])
                out.append(chr(int(m.group(1), 16)))
                i += 1 + m.end()
                continue
            out.append(ESCAPES.get(nxt, nxt))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def lex(text):
    """(code, bare, literals): comments blanked; in `bare` string and char literals blanked too, their quotes kept;
    literals as (start, end, value) for each string literal (text blocks included, by their raw content).

    Blanking keeps every newline, so an offset means the same line in all three."""
    code, bare, literals = [], [], []
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
            literals.append((i, j, text[i + 3:max(i + 3, j - 3)]))
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
            if quote == '"':
                literals.append((i, end, unescape(text[i + 1:j])))
            i = end
        else:
            code.append(text[i])
            bare.append(text[i])
            i += 1
    return "".join(code), "".join(bare), literals


def match_close(bare, open_at, opening="(", closing=")"):
    """The offset of the bracket closing the one at `open_at`, or len(bare)."""
    depth = 0
    for i in range(open_at, len(bare)):
        c = bare[i]
        if c == opening:
            depth += 1
        elif c == closing:
            depth -= 1
            if depth == 0:
                return i
    return len(bare)


def split_top(bare, start, end):
    """The top-level comma-separated pieces of bare[start:end] as (start, end) spans; () [] {} <> nest."""
    spans, depth, begin = [], 0, start
    for i in range(start, end):
        c = bare[i]
        if c in "([{<":
            depth += 1
        elif c in ")]}>":
            depth = max(0, depth - 1)
        elif c == "," and depth == 0:
            spans.append((begin, i))
            begin = i + 1
    if bare[start:end].strip():
        spans.append((begin, end))
    return spans


class JavaFile:
    """One main source file: its package, class, constants, methods and calls."""

    def __init__(self, module, path, text):
        self.module = module
        self.path = path
        self.code, self.bare, self.literals = lex(text)
        m = PACKAGE_RE.search(self.bare)
        self.package = m.group(1) if m else ""
        self.cls = os.path.splitext(os.path.basename(path))[0]
        self.static_imports = {name: cls.rsplit(".", 1)[-1] for cls, name in STATIC_IMPORT_RE.findall(self.bare)}
        self.constants = {}
        for m in CONSTANT_RE.finditer(self.code):
            modifiers = m.group(1).split()
            if "static" in modifiers and "final" in modifiers:
                self.constants[m.group(2)] = m.group(3).strip()
        self.methods = self._methods()
        self.calls = self._calls()

    def line(self, offset):
        return line_of(self.code, offset)

    def _methods(self):
        """[(name, params, varargs, body_start, body_end)]: params as names in order."""
        methods = []
        for m in METHOD_RE.finditer(self.bare):
            name = m.group(1)
            if name in KEYWORDS:
                continue
            before = self.bare[max(0, m.start() - 200):m.start()].rstrip()
            if not before or not (before[-1].isalnum() or before[-1] in "_$>]"):
                continue
            if re.search(r"(?:\bnew|\breturn|\bthrow|\belse|\bcase|[.])\s*$", before) or re.search(r"\bnew\s+[\w.<>]+$", before):
                continue
            close = match_close(self.bare, m.end() - 1)
            after = self.bare[close + 1:close + 400]
            head = re.match(r"\s*(?:throws\s+[\w.\s,]+?)?\s*\{", after)
            if not head:
                continue
            body_start = close + 1 + head.end() - 1
            body_end = match_close(self.bare, body_start, "{", "}")
            params, varargs = [], False
            for s, e in split_top(self.bare, m.end(), close):
                piece = re.sub(r"@\w+(?:\([^)]*\))?", " ", self.bare[s:e]).strip()
                names = IDENT.findall(piece)
                if not names:
                    continue
                params.append(names[-1])
                varargs = "..." in piece
            methods.append((name, params, varargs, body_start, body_end))
        return methods

    def enclosing(self, offset):
        """The innermost method whose body holds `offset`, or None."""
        best = None
        for method in self.methods:
            if method[3] < offset < method[4] and (best is None or method[3] > best[3]):
                best = method
        return best

    def _calls(self):
        """[(name, receiver, is_new, args, offset)]: args as (text, start) with the code's text, strings kept."""
        calls = []
        for m in CALL_RE.finditer(self.bare):
            name = m.group(1)
            if name in KEYWORDS:
                continue
            before = self.bare[max(0, m.start() - 200):m.start()]
            receiver = None
            is_new = bool(re.search(r"\bnew\s+(?:[\w]+\.)*$", before))
            r = re.search(r"([\w$]+)\s*\.\s*$", before)
            if r:
                receiver = r.group(1)
            elif re.search(r"[)\]]\s*\.\s*$", before):
                receiver = "?"
            close = match_close(self.bare, m.end() - 1)
            args = [(self.code[s:e].strip(), s) for s, e in split_top(self.bare, m.end(), close)]
            calls.append((name, receiver, is_new, args, m.start()))
        return calls


class Reactor:
    def __init__(self, root):
        self.root = root
        self.files = []
        self.by_class = {}
        self.problems = []
        self.unreadable = []

    def load(self, modules):
        for module in modules:
            src = os.path.join(self.root, module, "src", "main", "java")
            for path in sorted(glob.glob(os.path.join(src, "**", "*.java"), recursive=True)):
                rel = os.path.relpath(path, self.root)
                try:
                    with open(path, encoding="utf-8", errors="replace") as f:
                        text = f.read()
                except OSError as e:
                    self.unreadable.append((rel, str(e)))
                    continue
                self.add(module, rel, text)

    def add(self, module, rel, text):
        jf = JavaFile(module, rel, text)
        self.files.append(jf)
        self.by_class.setdefault(jf.cls, []).append(jf)
        return jf

    # --- names -------------------------------------------------------------------------------------------------

    def constant(self, jf, name, seen=None):
        """The literal a constant `name` seen from `jf` holds, or None."""
        seen = seen or set()
        key = (jf.path, name)
        if key in seen:
            return None
        seen.add(key)
        if name in jf.constants:
            return literal_of(self.expression(jf, jf.constants[name], None, seen))
        if name in jf.static_imports:
            for other in self.by_class.get(jf.static_imports[name], []):
                if name in other.constants:
                    return literal_of(self.expression(other, other.constants[name], None, seen))
        return None

    def expression(self, jf, text, method, seen=None):
        """What an argument names: ("literal", value), ("param", index), ("derived", inner) or None."""
        text = text.strip()
        while text.startswith("(") and match_close(text, 0) == len(text) - 1:
            text = text[1:-1].strip()
        m = LITERAL.fullmatch(text)
        if m:
            return ("literal", unescape(m.group(1)))
        if IDENT.fullmatch(text):
            if method is not None:
                if text in method[1]:
                    return ("param", method[1].index(text))
                loop = re.search(r"\bfor\s*\(\s*(?:final\s+)?[\w.<>]+\s+" + re.escape(text) + r"\s*:\s*(\w+)\s*\)",
                                 jf.bare[method[3]:method[4]])
                if loop and loop.group(1) in method[1] and method[2] and method[1].index(loop.group(1)) == len(method[1]) - 1:
                    return ("param", method[1].index(loop.group(1)))
            value = self.constant(jf, text, seen)
            return ("literal", value) if value is not None else None
        m = QUALIFIED_CONSTANT.fullmatch(text)
        if m:
            cls, field = m.group(1), m.group(2)
            if cls == jf.cls:
                value = self.constant(jf, field, seen)
                if value is not None:
                    return ("literal", value)
            for other in self.by_class.get(cls, []):
                if field in other.constants:
                    value = self.expression(other, other.constants[field], None, seen)
                    if value is not None:
                        return value
            return None
        m = re.fullmatch(r"(?:([\w.]+)\s*\.\s*)?(\w+)\s*\((.*)\)", text, re.S)
        if m and self.derives(jf, m.group(1), m.group(2)):
            inner = self.expression(jf, m.group(3), method, seen)
            return ("derived", inner) if inner is not None else None
        return None

    def derives(self, jf, receiver, name):
        """Whether calling `name` turns an environment name into its system property (Parsers.systemPropertyName)."""
        if name == "systemPropertyName":
            return True
        if receiver not in (None, "this", jf.cls):
            return False
        for method in jf.methods:
            if method[0] == name and len(method[1]) == 1:
                body = jf.bare[method[3]:method[4]]
                if re.search(r"\breturn\s+(?:[\w.]+\.)?systemPropertyName\s*\(\s*" + re.escape(method[1][0]) + r"\s*\)\s*;", body):
                    return True
        return False

    # --- reads -------------------------------------------------------------------------------------------------

    def targets(self, jf, name, receiver, nargs):
        """The methods a call may be: (file, method) pairs, matched by name and arity."""
        if receiver in (None, "this"):
            candidates = [jf]
        elif receiver[:1].isupper():
            candidates = self.by_class.get(receiver, [])
        else:
            return []
        out = []
        for other in candidates:
            for method in other.methods:
                if method[0] != name:
                    continue
                arity = len(method[1])
                if arity == nargs or (method[2] and nargs >= arity - 1):
                    out.append((other, method))
        return out

    @staticmethod
    def position(method, index):
        """The parameter an argument at `index` lands in, for a call to `method` (varargs collect the rest)."""
        if index < len(method[1]):
            return index
        return len(method[1]) - 1 if method[2] else None

    def call_kinds(self, jf, call, helpers):
        """For one call: [(arg index, kinds)] - what each argument position reads."""
        name, receiver, is_new, args, offset = call
        out = []
        if is_new:
            if name.endswith("FieldDescriptor") and args:
                out.append((0, {"plugin-field"}))
            return out
        spec = READ_CALLS.get(name)
        if spec and args and (spec[1] is None or receiver == spec[1]):
            out.append((0, {spec[0]}))
            return out
        if name == "apply" and receiver in APPLY_RECEIVERS and len(args) == 1:
            out.append((0, {APPLY_RECEIVERS[receiver]}))
            return out
        for target, method in self.targets(jf, name, receiver, len(args)):
            positions = helpers.get((target.path, method[0], len(method[1]), method[3]), {})
            for i in range(len(args)):
                p = self.position(method, i)
                if p is not None and p in positions:
                    out.append((i, set(positions[p])))
        return out

    def helpers(self):
        """(file, method name, arity, body offset) -> {parameter index: kinds}, to a fixpoint."""
        helpers = {}
        changed = True
        while changed:
            changed = False
            for jf in self.files:
                for call in jf.calls:
                    method = jf.enclosing(call[4])
                    if method is None:
                        continue
                    for index, kinds in self.call_kinds(jf, call, helpers):
                        what = self.expression(jf, call[3][index][0], method)
                        param = None
                        if what and what[0] == "param":
                            param, add = what[1], kinds
                        elif what and what[0] == "derived" and what[1] and what[1][0] == "param":
                            param, add = what[1][1], {DERIVED} if "system-property" in kinds else set()
                        if param is None or not add:
                            continue
                        key = (jf.path, method[0], len(method[1]), method[3])
                        have = helpers.setdefault(key, {}).setdefault(param, set())
                        if not add <= have:
                            have |= add
                            changed = True
        return helpers

    def reads(self):
        """(reads, unresolved): reads as (kind, name, file, line); unresolved as (file, line, call text)."""
        helpers = self.helpers()
        reads, unresolved = [], []
        for jf in self.files:
            for call in jf.calls:
                method = jf.enclosing(call[4])
                direct = call[2] or call[0] in READ_CALLS
                for index, kinds in self.call_kinds(jf, call, helpers):
                    text, start = call[3][index]
                    what = self.expression(jf, text, method)
                    line = jf.line(start)
                    if what is None:
                        if direct and not (call[0] in READ_CALLS and READ_CALLS[call[0]][1] and call[1] != READ_CALLS[call[0]][1]):
                            unresolved.append((jf, line, f"{call[0]}({text})"))
                        continue
                    if what[0] == "param":
                        continue
                    if what[0] == "derived":
                        if what[1] and what[1][0] == "literal" and ("system-property" in kinds or DERIVED in kinds):
                            reads.append(("system-property", derive(what[1][1]), jf, line))
                        continue
                    for kind in sorted(kinds):
                        if kind == DERIVED:
                            reads.append(("system-property", derive(what[1]), jf, line))
                        else:
                            reads.append((kind, what[1], jf, line))
            for start, _end, value in jf.literals:
                if OIDF_ENV_LITERAL.fullmatch(value):
                    reads.append(("env", value, jf, jf.line(start)))
                m = EXTPROPERTY_LITERAL.fullmatch(value)
                if m:
                    reads.append(("extended-property", m.group(1), jf, jf.line(start)))
            for (cls, field) in EXTENDED_PROPERTY_LISTS:
                if cls != jf.cls:
                    continue
                m = re.search(COLLECTION_RE.format(field=re.escape(field)), jf.bare)
                if not m:
                    continue
                opening = m.end() - 1
                close = match_close(jf.bare, opening, jf.bare[opening], ")" if jf.bare[opening] == "(" else "}")
                for s, e in split_top(jf.bare, opening + 1, close):
                    if not jf.bare[s:e].strip():
                        continue
                    what = self.expression(jf, jf.code[s:e], None)
                    if what and what[0] == "literal":
                        reads.append(("extended-property", what[1], jf, jf.line(s)))
                    else:
                        unresolved.append((jf, jf.line(s), f"{field} element {jf.code[s:e].strip()}"))
        unique = {}
        for kind, name, jf, line in reads:
            unique.setdefault((kind, name, jf.path, line), (kind, name, jf, line))
        return list(unique.values()), unresolved

    def literal_names(self):
        """Every whole string literal in main code, by module."""
        out = {}
        for jf in self.files:
            out.setdefault(jf.module, set()).update(value for _s, _e, value in jf.literals)
        return out


def scope(kind, module):
    """Where a name means one thing: an init-param or a plugin field belongs to the servlets or the plugin of one
    module (three servlets read three different `signingAlgorithm`s), so it is declared and matched within the
    module; an environment variable, a system property and a client's extended property are one per process."""
    return module if kind in SCOPED_KINDS else None


def literal_of(what):
    return what[1] if what and what[0] == "literal" else None


def derive(env_name):
    """Parsers.systemPropertyName: lower case, underscores as dots."""
    return env_name.lower().replace("_", ".")


# --- catalogues ------------------------------------------------------------------------------------------------

class Catalogue:
    def __init__(self, module, path, doc):
        self.module = module
        self.path = path
        self.component = doc["component"]
        self.package = doc["package"]
        self.declared_module = doc["module"]
        self.entries = doc["settings"]
        self.removed = doc["removed"]

    def names(self):
        """[(kind, name, entry name, must be read)]: every name it declares."""
        out = []
        for entry in self.entries:
            kind = entry["kind"]
            if kind in SOURCE_KINDS:
                for source in entry["sources"]:
                    out.append((source["from"], source["name"], entry["name"], True))
                for alias in entry["aliases"]:
                    for source in alias["sources"]:
                        out.append((source["from"], source["name"], entry["name"], True))
                if entry["file"]:
                    for source in entry["sources"]:
                        out.append((source["from"], file_variant(source["from"], source["name"]), entry["name"], False))
            else:
                out.append((kind, entry["name"], entry["name"], True))
        for gone in self.removed:
            out.append((gone["from"], gone["name"], gone["name"], False))
        return out


def file_variant(kind, name):
    return {"env": name + "_FILE", "system-property": name + ".file", "init-param": name + "File"}[kind]


ENTRY_MEMBERS = {"name", "kind", "type", "default", "description", "when_wrong", "profile", "security", "sources",
                 "aliases", "file"}
TOP_MEMBERS = {"format", "component", "module", "package", "families", "settings", "removed"}
TYPES = {"bool", "int", "long", "seconds", "millis", "string", "choice", "https-url", "url", "json-object", "words",
         "path", "secret"}
RANGED = {"int", "long", "seconds", "millis"}
EFFECTS = {"doesnt-start", "first-request", "per-request", "not-checked"}
PROFILE_RE = re.compile(r"any|forbidden-in-production|required-in-production|accepted-risk:[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
NAME_RES = {"env": re.compile(r"[A-Z][A-Z0-9_]*"), "system-property": re.compile(r"[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*"),
            "init-param": re.compile(r"[A-Za-z][A-Za-z0-9_.-]*")}


def no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"member {key!r} is written twice")
        seen[key] = value
    return seen


def check_catalogue(doc, where):
    """The shape the scan relies on, as the loader in platform.settings reads it; a list of problems."""
    problems = []
    if not isinstance(doc, dict):
        return [f"{where}: not a JSON object"]
    if set(doc) != TOP_MEMBERS:
        return [f"{where}: members {sorted(set(doc) ^ TOP_MEMBERS)} are missing or unknown"]
    if doc["format"] != 1 or isinstance(doc["format"], bool):
        problems.append(f"{where}: format is not 1")
    for member in ("component", "module", "package"):
        if not isinstance(doc[member], str) or not doc[member]:
            problems.append(f"{where}: {member} is not text")
    if not isinstance(doc["families"], list) or not all(
            isinstance(f, str) and re.fullmatch(r"OIDF_([A-Z0-9]+_)+", f) for f in doc["families"]):
        problems.append(f"{where}: families are not OIDF_ prefixes ending in _")
    if not isinstance(doc["settings"], list) or not isinstance(doc["removed"], list):
        return problems + [f"{where}: settings and removed are lists"]
    for i, entry in enumerate(doc["settings"]):
        at = f"{where}: settings[{i}]"
        if not isinstance(entry, dict):
            problems.append(f"{at}: not an object")
            continue
        at += f" ({entry.get('name')})"
        extra = set(entry) - ENTRY_MEMBERS - {"min", "max", "choices"}
        missing = ENTRY_MEMBERS - set(entry)
        if extra or missing:
            problems.append(f"{at}: members {sorted(extra | missing)} are unknown or missing")
            continue
        if entry["kind"] not in KINDS:
            problems.append(f"{at}: kind {entry['kind']!r}")
            continue
        if entry["type"] not in TYPES:
            problems.append(f"{at}: type {entry['type']!r}")
        if ("min" in entry or "max" in entry) != (entry["type"] in RANGED) or (
                entry["type"] in RANGED and not ("min" in entry and "max" in entry)):
            problems.append(f"{at}: min and max go with a ranged type, and only with one")
        if ("choices" in entry) != (entry["type"] == "choice"):
            problems.append(f"{at}: choices go with a choice, and only with one")
        if not isinstance(entry["when_wrong"], dict) or set(entry["when_wrong"]) != {"effect", "detail"} or \
                entry["when_wrong"].get("effect") not in EFFECTS:
            problems.append(f"{at}: when_wrong is {{effect, detail}} with a known effect")
        if not isinstance(entry["profile"], str) or not PROFILE_RE.fullmatch(entry["profile"]):
            problems.append(f"{at}: profile {entry['profile']!r}")
        if not isinstance(entry["security"], bool) or not isinstance(entry["file"], bool):
            problems.append(f"{at}: security and file are true or false")
        if entry["type"] == "bool" and entry["default"] is None:
            problems.append(f"{at}: a switch has a default")
        if entry["type"] == "secret" and (entry["default"] is not None or entry["security"] is not True):
            problems.append(f"{at}: a secret has no default and bears on security")
        if entry["file"] and entry["type"] != "secret":
            problems.append(f"{at}: only a secret is read from a file")
        if not isinstance(entry["sources"], list) or not isinstance(entry["aliases"], list):
            problems.append(f"{at}: sources and aliases are lists")
            continue
        if entry["kind"] in SOURCE_KINDS:
            if not any(s.get("from") == entry["kind"] and s.get("name") == entry["name"] for s in entry["sources"]
                       if isinstance(s, dict)):
                problems.append(f"{at}: an {entry['kind']} entry is read from {entry['kind']} under its own name")
        elif entry["sources"] or entry["aliases"] or entry["file"]:
            problems.append(f"{at}: a {entry['kind']} has no sources, aliases or file")
        groups = [entry["sources"]] + [a.get("sources", []) if isinstance(a, dict) else None for a in entry["aliases"]]
        for group in groups:
            if not isinstance(group, list):
                problems.append(f"{at}: an alias is {{name, sources}}")
                continue
            for source in group:
                if not isinstance(source, dict) or set(source) != {"from", "name"} or source["from"] not in SOURCE_KINDS \
                        or not isinstance(source["name"], str) or not NAME_RES[source["from"]].fullmatch(source["name"]):
                    problems.append(f"{at}: source {source!r} is not {{from, name}} with a name its source can hold")
    for i, gone in enumerate(doc["removed"]):
        if not isinstance(gone, dict) or set(gone) != {"name", "from", "replacement", "release"} or \
                gone.get("from") not in SOURCE_KINDS:
            problems.append(f"{where}: removed[{i}] is {{name, from, replacement, release}}")
    return problems


def load_catalogues(root, modules):
    catalogues, problems = [], []
    for module in modules:
        for path in sorted(glob.glob(os.path.join(root, module, CATALOGUE_DIR, "*.json"))):
            rel = os.path.relpath(path, root)
            try:
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f, object_pairs_hook=no_duplicates)
            except (OSError, ValueError) as e:
                problems.append(f"{rel}: cannot be read: {e}")
                continue
            shape = check_catalogue(doc, rel)
            if shape:
                problems.extend(shape)
                continue
            catalogue = Catalogue(module, rel, doc)
            stem = os.path.splitext(os.path.basename(path))[0]
            if catalogue.component != stem:
                problems.append(f"{rel}: names its component {catalogue.component}; the file and the component are named alike")
            if catalogue.declared_module != module:
                problems.append(f"{rel}: names its module {catalogue.declared_module}, but it is in {module}")
            catalogues.append(catalogue)
    return catalogues, problems


# --- exemptions ------------------------------------------------------------------------------------------------

def read_exemptions(path):
    """(lines, refuse_shipped, problems): lines as (module, group, reason, line number)."""
    if not os.path.isfile(path):
        return [], False, []
    lines, problems, group, refuse = [], [], None, False
    with open(path, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            text = raw.strip()
            if not text:
                continue
            m = re.fullmatch(r"#\s*group\s+(.+?)\s*(?::.*)?", text)
            if m:
                group = m.group(1)
                continue
            if text.startswith("#"):
                continue
            m = re.fullmatch(r"refuse-shipped-exemptions:\s*(yes|no)", text)
            if m:
                refuse = m.group(1) == "yes"
                continue
            module, _, reason = text.partition(":")
            module, reason = module.strip(), reason.strip()
            if group is None:
                problems.append(f"{EXEMPTIONS}:{number}: {module} is under no `# group` line")
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*(/[a-z0-9][a-z0-9-]*)*", module):
                problems.append(f"{EXEMPTIONS}:{number}: {text!r} is not a module path")
                continue
            lines.append((module, group, reason, number))
    return lines, refuse, problems


def staged_modules(root):
    """The modules build/pingfederate/stage-modules.sh stages: they are shipped whatever a line says."""
    path = os.path.join(root, STAGE_MODULES)
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return set(re.findall(r'"\w+\s+((?:libs|servlets|plugins|services)/[\w./-]+?)/target/', text))


# --- the scan --------------------------------------------------------------------------------------------------

def modules_of(root):
    with open(os.path.join(root, "pom.xml"), encoding="utf-8") as f:
        return MODULE_RE.findall(f.read())


def scan(root):
    """(problems, reads, notes); problems as strings, reads for --list."""
    modules = modules_of(root)
    reactor = Reactor(root)
    reactor.load(modules)
    reads, unresolved = reactor.reads()
    catalogues, problems = load_catalogues(root, modules)
    exemptions, refuse_shipped, exemption_problems = read_exemptions(os.path.join(root, EXEMPTIONS))
    problems.extend(exemption_problems)
    notes = []

    exempt = {}
    catalogued_modules = {c.module for c in catalogues}
    reading_modules = {jf.module for _k, _n, jf, _l in reads} | {jf.module for jf, _l, _t in unresolved}
    staged = staged_modules(root)
    for module, group, reason, number in exemptions:
        where = f"{EXEMPTIONS}:{number}"
        if module not in modules:
            problems.append(f"{where}: {module} is not a module of the reactor")
        elif module in catalogued_modules:
            problems.append(f"{where}: {module} has a catalogue now; delete its exemption")
        elif module not in reading_modules:
            problems.append(f"{where}: {module} reads nothing the scan sees; delete its exemption")
        if module in exempt:
            problems.append(f"{where}: {module} is exempted twice")
        if group == NOT_SHIPPED:
            if not reason:
                problems.append(f"{where}: a not-shipped module says why it is not shipped, after a colon")
            if module in staged:
                problems.append(f"{where}: {module} is staged by {STAGE_MODULES}, so it is shipped")
        elif refuse_shipped:
            problems.append(f"{where}: {module} is exempt in group {group}, and only the {NOT_SHIPPED!r} group may be")
        exempt[module] = group

    # Declared names: (kind, name, scope) -> [(catalogue, entry, must be read)].
    declared = {}
    for catalogue in catalogues:
        for kind, name, entry, must in catalogue.names():
            declared.setdefault((kind, name, scope(kind, catalogue.module)), []).append((catalogue, entry, must))
    components = {}
    for catalogue in catalogues:
        components.setdefault(catalogue.component, []).append(catalogue)
    for component, found in components.items():
        if len(found) > 1:
            problems.append(f"component {component} is catalogued by {', '.join(c.path for c in found)}; one module owns it")
    for (kind, name, _scope), owners in sorted(declared.items(), key=lambda item: item[0][:2]):
        paths = sorted({c.path for c, _e, _m in owners})
        if len(paths) > 1:
            problems.append(f"{kind} {name} is declared by {', '.join(paths)}; a name is catalogued once, by its owner")

    # Code to catalogue.
    for jf, line, text in unresolved:
        if jf.module in exempt:
            continue
        problems.append(f"{jf.path}:{line}: {text} is a read the scan cannot name: read it by a constant, or through a"
                        " helper whose parameter carries it")
    seen_missing = set()
    for kind, name, jf, line in sorted(reads, key=lambda r: (r[2].path, r[3], r[0], r[1])):
        if jf.module in exempt or (kind, name) in NOT_SETTINGS or (kind, name, scope(kind, jf.module)) in declared:
            continue
        key = (kind, name, jf.module)
        if key in seen_missing:
            continue
        seen_missing.add(key)
        problems.append(f"{jf.path}:{line}: {kind} {name} is read but no catalogue declares it")

    # Catalogue to code.
    read_where = {}
    for kind, name, jf, _line in reads:
        read_where.setdefault((kind, name), set()).add((jf.module, jf.package))
    literals = reactor.literal_names()
    for (kind, name, in_module), owners in sorted(declared.items(), key=lambda item: item[0][:2]):
        for catalogue, entry, must in owners:
            if not must:
                continue
            where = set(read_where.get((kind, name), set()))
            if kind in ("plugin-field", "extended-property"):
                where |= {(module, None) for module, values in literals.items() if name in values}
            if in_module:
                where = {(module, package) for module, package in where if module == in_module}
            if not where:
                problems.append(f"{catalogue.path}: {kind} {name} ({entry}) is catalogued but nothing reads it")
            elif not any(module == catalogue.module for module, _p in where):
                problems.append(f"{catalogue.path}: {kind} {name} ({entry}) is read only in"
                                f" {', '.join(sorted({m for m, _p in where}))}, not in {catalogue.module}, whose catalogue it is in")
    for catalogue in catalogues:
        packages = set()
        for kind, name, _entry, must in catalogue.names():
            if must:
                packages |= {p for m, p in read_where.get((kind, name), set()) if m == catalogue.module and p}
        if catalogue.entries and not any(p == catalogue.package or p.startswith(catalogue.package + ".") for p in packages):
            problems.append(f"{catalogue.path}: package {catalogue.package} reads none of its settings; the owning package"
                            f" is one of {', '.join(sorted(packages)) or 'none'}")
    if unresolved or reads:
        notes.append(f"{len(reads)} read(s) in {len(reading_modules)} module(s), {len(catalogues)} catalogue(s),"
                     f" {len(declared)} declared name(s), {len(exempt)} exempt module(s)")
    return problems, reads, notes, reactor.unreadable


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".")
    parser.add_argument("--list", action="store_true", help="print every read the scan sees and exit 0")
    args = parser.parse_args(argv)
    root = os.path.abspath(args.root)
    problems, reads, notes, unreadable = scan(root)
    for path, error in unreadable:
        print(f"{path}: cannot read: {error}", file=sys.stderr)
    if args.list:
        for kind, name, jf, line in sorted(reads, key=lambda r: (r[0], r[1], r[2].path, r[3])):
            print(f"{kind} {name}  {jf.path}:{line}")
        return 2 if unreadable else 0
    for note in notes:
        print(note)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        print(f"{len(problems)} problem(s): catalogue what is read, delete what is not, or record why not"
              " (docs/development/settings-catalogue.md)", file=sys.stderr)
        return 1
    if unreadable:
        return 2
    print("clean: every setting read is catalogued, and every catalogued setting is read")
    return 0


if __name__ == "__main__":
    sys.exit(main())
