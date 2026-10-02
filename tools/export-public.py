#!/usr/bin/env python3
"""The public tree, built from an allow-list and checked: what ID-Partners/pf-agentic-identity receives.

  tools/export-public.py --check                        build HEAD's tree in a temporary directory, run every
                                                        guard, print the summary, remove it
  tools/export-public.py OUTDIR                         build it into OUTDIR (absent, or empty apart from .git)
  tools/export-public.py --source-ref v0.6.0 OUTDIR     from a tag's tree instead of the index
  tools/export-public.py --version 0.7.0 --docs-only OUTDIR   root and docs only; the public image/ and demo/ stay
  tools/export-public.py --source-ref v0.4.0 --docs-alone OUTDIR   root and docs, for a tree with no image/ or demo/

What goes out is tools/public-export/manifest.txt's business: one rule per line, `<class> <source-glob>
[-> <public-path>] [optional]`, first match wins. The classes root, docs, image and demo are exported; internal
is not, and a link into it from an exported document keeps its text and loses the link; refuse is never
exported: a rule of another class whose source matches a refuse rule is a manifest error, and a file a refuse
rule matches fails the no-source guard whatever rule above it matched first. Files under
tools/public-export/overlay/ exist only publicly and are templated ({{VERSION}}, {{TAG}}, {{PF_VERSION}} and
three conditional sections, `<!-- if:demo -->`, `<!-- if:staging -->` and `<!-- unless:staging -->`, each
closed by `<!-- end:demo -->` or `<!-- end:staging -->`). image/release.env is written when image/ is exported
and the version is known.

Only tracked files are read: on HEAD the index's paths, with their working-tree content; with --source-ref the
ref's tree (git ls-tree, git cat-file). An untracked or git-ignored file can never reach the tree.

The guards, each named in its failure:
  no-source   a *.java, *.kt or *.swift, a pom.xml, a src/ path segment, .github/, showcase/ or
              build/microsite/, by source or public path; a file a refuse rule matches; a symbolic link
  links       a relative Markdown link to anything neither exported nor internal (a typo, a dead file), and a
              relative HTML href or src in Markdown that would be de-linked
  urls        a dphhyland/pf-agentic-identity URL or slug the rewrite table does not cover (HEAD only; at
              --source-ref it becomes "the internal repository" and is listed)
  deny        a line matching tools/public-export/deny.txt, after the transform, overlay included
  secrets     tools/ci/secrets-scan.py's scan_text on every text file
  binaries    a binary file without an allowed extension, or over 5 MB

Exit status: 0 clean, 1 when a guard fails, 2 on a usage or manifest error.
docs/development/public-export.md is the long form.
"""
import argparse
import hashlib
import importlib.util
import os
import posixpath
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

TOOLS = os.path.dirname(os.path.abspath(__file__))
EXPORT_DIR = "tools/public-export"
PUBLIC_SLUG = "ID-Partners/pf-agentic-identity"
INTERNAL_SLUG = "dphhyland/pf-agentic-identity"
# Repositories exported documents link to that are private (gh repo view --json visibility, 2026-10-01).
# dphhyland/pf-oidf-modules is public and its links stay.
PRIVATE_REPOS = ("dphhyland/idp-agentic-demo", "dphhyland/grant-evaluation-api")
# The first release the public repository carries: earlier release links are de-linked.
FIRST_MIRRORED = (0, 3, 0)

EXPORTED = ("root", "docs", "image", "demo")
CLASSES = EXPORTED + ("internal", "refuse")
DOCS_ONLY = ("root", "docs")
BINARY_EXTENSIONS = (".png", ".webp", ".jpg", ".jpeg", ".svg")
BINARY_LIMIT = 5 * 1024 * 1024
UNKNOWN_URL_TEXT = "the internal repository"
REDACTED = "<redacted>"

NO_SOURCE = [
    (re.compile(r"\.(java|kt|swift)$"), "source code"),
    (re.compile(r"(^|/)pom\.xml$"), "a Maven build file"),
    (re.compile(r"(^|/)src/"), "a src/ directory"),
    (re.compile(r"(^|/)\.github/"), "the repository's workflows"),
    (re.compile(r"^showcase/"), "the showcase, which stays private"),
    (re.compile(r"^build/microsite/"), "the microsite, which stays private"),
]


class ManifestError(Exception):
    pass


class UsageError(Exception):
    pass


# --- the manifest ---

def glob_regex(glob):
    """A glob as a regex over repository paths: * within a segment, ** across them, ? and [...] as usual."""
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif glob.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = glob.find("]", i + 1)
            if j < 0:
                raise ManifestError(f"unclosed [ in {glob!r}")
            out.append("[" + glob[i + 1:j].replace("\\", "\\\\") + "]")
            i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def has_wildcard(s):
    return any(c in s for c in "*?[")


class Rule:
    def __init__(self, cls, glob, dest, optional, line):
        self.cls, self.glob, self.dest, self.optional, self.line = cls, glob, dest, optional, line
        self.regex = glob_regex(glob)
        parts = glob.split("/")
        literal = []
        for p in parts[:-1]:
            if has_wildcard(p):
                break
            literal.append(p)
        else:
            if not has_wildcard(parts[-1]):
                literal = parts[:-1]
        self.prefix = "/".join(literal) + "/" if literal else ""

    def matches(self, path):
        return bool(self.regex.match(path))

    def public_path(self, src):
        if self.dest is None:
            return src
        if not self.dest.endswith("/"):
            return self.dest
        if has_wildcard(self.glob):
            return self.dest + src[len(self.prefix):]
        return self.dest + posixpath.basename(src)

    def __str__(self):
        return f"manifest.txt:{self.line}: {self.cls} {self.glob}"


def parse_manifest(text):
    rules = []
    for number, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        words = line.split()
        optional = False
        if words[-1] == "optional":
            optional = True
            words = words[:-1]
        dest = None
        if "->" in words:
            k = words.index("->")
            if k != 2 or len(words) != 4:
                raise ManifestError(f"manifest.txt:{number}: expected `<class> <source-glob> -> <public-path>`")
            dest = words[3]
            words = words[:2]
        if len(words) != 2:
            raise ManifestError(f"manifest.txt:{number}: expected `<class> <source-glob> [-> <public-path>] [optional]`, got {line!r}")
        cls, glob = words
        if cls not in CLASSES:
            raise ManifestError(f"manifest.txt:{number}: unknown class {cls!r} (one of {', '.join(CLASSES)})")
        if glob.startswith("/") or ".." in glob.split("/"):
            raise ManifestError(f"manifest.txt:{number}: {glob!r} must be a path inside the repository")
        if dest is not None and (cls not in EXPORTED or dest.startswith("/") or ".." in dest.split("/")):
            raise ManifestError(f"manifest.txt:{number}: a public path is for an exported class, inside the tree")
        rules.append(Rule(cls, glob, dest, optional, number))
    refuse = [r for r in rules if r.cls == "refuse"]
    for r in rules:
        if r.cls == "refuse":
            continue
        for x in refuse:
            if x.matches(r.glob) or x.matches(r.prefix + "x") or (r.prefix and x.matches(r.prefix.rstrip("/"))):
                raise ManifestError(f"{r} - its source matches the refuse rule `{x.glob}` (line {x.line}); "
                                    f"what that rule covers is never exported")
    return rules


def classify(rules, path):
    for r in rules:
        if r.matches(path):
            return r
    return None


# --- reading tracked files ---

class Source:
    """The tracked files, with mode and content: the index (working-tree content) or a ref's tree."""

    def __init__(self, root, ref=None):
        self.root, self.ref = root, ref
        self.modes, self._blobs, self._cache = {}, {}, {}
        if ref:
            out = git(root, "ls-tree", "-r", "-z", "--full-tree", ref)
            for entry in out.split(b"\0"):
                if not entry:
                    continue
                meta, path = entry.split(b"\t", 1)
                mode, kind, sha = meta.split()
                if kind != b"blob":
                    continue
                path = path.decode("utf-8")
                self.modes[path] = mode.decode()
                self._blobs[path] = sha.decode()
        else:
            out = git(root, "ls-files", "-s", "-z")
            for entry in out.split(b"\0"):
                if not entry:
                    continue
                meta, path = entry.split(b"\t", 1)
                mode = meta.split()[0].decode()
                if mode == "160000":
                    continue
                self.modes[path.decode("utf-8")] = mode
        self.paths = sorted(self.modes)
        self._dirs = set()
        for p in self.paths:
            d = posixpath.dirname(p)
            while d and d not in self._dirs:
                self._dirs.add(d)
                d = posixpath.dirname(d)

    def is_dir(self, path):
        return path in self._dirs

    def under(self, d):
        prefix = d.rstrip("/") + "/"
        return [p for p in self.paths if p.startswith(prefix)]

    def read(self, path):
        if path in self._cache:
            return self._cache[path]
        if self.ref:
            data = git(self.root, "cat-file", "blob", self._blobs[path])
        else:
            # The index says what the file is; a working tree whose file differs in type (a tracked file turned
            # into an unstaged symbolic link, which open() would follow out of the repository) is refused.
            full = os.path.join(self.root, path)
            link = os.path.islink(full)
            if link != (self.modes[path] == "120000"):
                raise UsageError(f"{path}: the working tree has {'a symbolic link' if link else 'a regular file'} where "
                                 f"the index has {'a regular file' if link else 'a symbolic link'}; commit or restore it")
            if link:
                data = os.readlink(full).encode("utf-8")
            else:
                with open(full, "rb") as f:
                    data = f.read()
        self._cache[path] = data
        return data


def git(root, *args):
    try:
        return subprocess.run(["git", "-C", root, *args], check=True, capture_output=True).stdout
    except subprocess.CalledProcessError as e:
        raise UsageError(f"git {' '.join(args)}: {e.stderr.decode(errors='replace').strip()}")


# --- the URL and slug table ---

# GitHub owner and repository names are case-insensitive, so the owner/repo part is matched without case.
URL_RE = re.compile(r"https?://github\.com/(?i:dphhyland/pf-agentic-identity)(?P<rest>(?:/[^\s)>\]\"'`<]*)?)")
PRIVATE_URL_RE = re.compile(r"https?://github\.com/(?P<repo>(?i:" + "|".join(re.escape(r) for r in PRIVATE_REPOS)
                            + r"))(?:[/#?][^\s)>\]\"'`<]*)?")
SLUG_FLAG_RE = re.compile(r"(--repo[= ]+|-R[= ]*)(?i:" + re.escape(INTERNAL_SLUG) + r")\b")
SLUG_RE = re.compile(r"(?i:" + re.escape(INTERNAL_SLUG) + r")\b")
RELEASE_RE = re.compile(r"^/releases/(?:tag|download)/v(\d+)\.(\d+)\.(\d+)(?:[/#?].*)?$")
DELINK_RE = re.compile(r"^/(actions|compare|blob|tree|pull|pulls|issues|commit|commits)(/|$|#|\?)")


def map_url(url):
    """('rewrite', new) | ('delink', None) | ('unknown', None) for a dphhyland/pf-agentic-identity URL."""
    m = URL_RE.match(url)
    rest = m.group("rest") if m else ""
    r = RELEASE_RE.match(rest)
    if r:
        if tuple(int(x) for x in r.groups()) >= FIRST_MIRRORED:
            return "rewrite", "https://github.com/" + PUBLIC_SLUG + rest
        return "delink", None
    if re.match(r"^/releases(/latest)?/?$", rest):
        return "rewrite", "https://github.com/" + PUBLIC_SLUG + rest
    if DELINK_RE.match(rest):
        return "delink", None
    return "unknown", None


def trim_url(url):
    """A bare URL's trailing sentence punctuation is not part of it."""
    trimmed = url.rstrip(".,;:!")
    return trimmed, url[len(trimmed):]


# --- the export ---

class Export:
    def __init__(self, root, source, rules, docs_only, docs_alone=False):
        self.root, self.source, self.rules = root, source, rules
        # docs_only: only root and docs are written, into a public tree that keeps its image/ and demo/ (a
        # docs-only release), so links into them and the overlay's sections follow the full export. docs_alone:
        # the same files, into a public tree that has no image/ or demo/ (the v0.3.0-v0.5.0 mirrors), so links
        # into them are de-linked and the overlay's image and demo section goes.
        self.docs_only, self.docs_alone = docs_only or docs_alone, docs_alone
        self.at_ref = bool(source.ref)
        self.errors = []          # (guard, location, message)
        self.notes = []           # listed in the summary at --source-ref
        self.counts = {}          # public path -> {"rewritten": n, "internal": n, "private": n}
        self.files = {}           # public path -> (mode, bytes, source path or None)
        self.public_of = {}       # source path -> public path, for every exported file
        self.full_public_of = {}  # the same, as a full export would have it (for docs-only link classes)
        self.missing = []

    def error(self, guard, location, message):
        self.errors.append((guard, location, message))

    def count(self, pub, kind):
        self.counts.setdefault(pub, {"rewritten": 0, "internal": 0, "private": 0})[kind] += 1

    # selection
    def select(self):
        matched = {id(r): 0 for r in self.rules}
        refuse = [r for r in self.rules if r.cls == "refuse"]
        for path in self.source.paths:
            rule = classify(self.rules, path)
            if rule is None:
                continue
            matched[id(rule)] += 1
            if rule.cls not in EXPORTED:
                continue
            # refuse holds whatever a rule above it says: parse_manifest catches a glob that reaches a refuse
            # rule's glob, and this catches the file a broader glob would still carry past a narrower refuse.
            barred = next((x for x in refuse if x.matches(path)), None)
            if barred is not None and not any(pattern.search(path) for pattern, _ in NO_SOURCE):
                # (a path NO_SOURCE names is reported by guard() in its own words)
                self.error("no-source", path, f"matches the refuse rule `{barred.glob}` (manifest.txt:{barred.line}) "
                           f"and is never exported, although {rule} matches it first")
                continue
            pub = rule.public_path(path)
            self.full_public_of[path] = pub
            if self.docs_only and rule.cls not in DOCS_ONLY:
                continue
            if pub in self.files:
                raise ManifestError(f"{rule}: {path} and {self.files[pub][2]} both land at {pub}")
            self.public_of[path] = pub
            self.files[pub] = (self.source.modes[path], None, path)
        # what a docs-only export leaves in place in the public tree, laid out as the full export lays it out
        self.kept_public_of = {} if self.docs_alone else {
            p: q for p, q in self.full_public_of.items() if p not in self.public_of}
        for r in self.rules:
            if r.cls in EXPORTED and not matched[id(r)]:
                if r.optional:
                    self.missing.append(f"{r.glob} (optional, not present)")
                elif self.at_ref:
                    self.missing.append(r.glob)
                else:
                    raise ManifestError(f"{r} matches no tracked file (mark it optional if another change adds it)")

    # the link target classes
    def target(self, src, pub, raw, line):
        """('keep', new_target) or ('delink', kind) for one link target, or None after recording an error."""
        target = raw[1:-1] if raw.startswith("<") and raw.endswith(">") else raw
        if not target or target.startswith("#"):
            return "keep", raw
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            if URL_RE.match(target):
                action, new = map_url(target)
                if action == "rewrite":
                    self.count(pub, "rewritten")
                    return "keep", new
                if action == "delink":
                    self.count(pub, "internal")
                    return "delink", "internal"
                if self.at_ref:
                    self.notes.append(f"{pub}:{line}: {target} -> link dropped ({UNKNOWN_URL_TEXT})")
                    self.count(pub, "internal")
                    return "delink", "internal"
                self.error("urls", f"{src}:{line}", f"{target} is not in the rewrite table (releases at the "
                           f"public repository, or a run/compare/blob/tree/pull/issues link to de-link)")
                return None
            if PRIVATE_URL_RE.match(target):
                self.count(pub, "private")
                return "delink", "private"
            return "keep", raw
        if target.startswith("/"):
            self.error("links", f"{src}:{line}", f"{target} is an absolute path; write it relative to the file")
            return None
        path, sep, anchor = target.partition("#")
        rel = urllib.parse.unquote(path)
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(src), rel))
        if resolved.startswith("../") or resolved == "..":
            self.error("links", f"{src}:{line}", f"{target} leaves the repository")
            return None
        new_path = None
        if resolved in self.public_of:
            new_path = self.public_of[resolved]
        elif resolved in self.kept_public_of:
            new_path = self.kept_public_of[resolved]
        elif self.source.is_dir(resolved):
            inside = self.source.under(resolved)
            for p in inside:
                if p in self.public_of:
                    suffix = p[len(resolved):]
                    if self.public_of[p].endswith(suffix):
                        new_path = self.public_of[p][:-len(suffix)] or "."
                        break
            if new_path is None:
                for p in inside:
                    if p in self.kept_public_of:
                        suffix = p[len(resolved):]
                        if self.kept_public_of[p].endswith(suffix):
                            new_path = self.kept_public_of[p][:-len(suffix)] or "."
                            break
            if new_path is None:
                classes = {getattr(classify(self.rules, p), "cls", None) for p in inside}
                if classes & {"internal", "refuse"} or any(p in self.full_public_of for p in inside):
                    self.count(pub, "internal")
                    return "delink", "internal"
        elif resolved in self.source.modes:
            rule = classify(self.rules, resolved)
            if rule is not None and (rule.cls in ("internal", "refuse") or resolved in self.full_public_of):
                self.count(pub, "internal")
                return "delink", "internal"
            self.error("links", f"{src}:{line}", f"{target} -> {resolved}, which the manifest does not "
                       f"classify; export it or class it internal")
            return None
        if new_path is None:
            if self.at_ref:
                self.notes.append(f"{pub}:{line}: {target} -> link dropped (no such file at {self.source.ref})")
                self.count(pub, "internal")
                return "delink", "internal"
            self.error("links", f"{src}:{line}", f"{target} -> {resolved}, which does not exist")
            return None
        new = posixpath.relpath(new_path, posixpath.dirname(pub) or ".")
        if path.endswith("/") and not new.endswith("/"):
            new += "/"
        if "%" in path:
            new = urllib.parse.quote(new, safe="/")
        new += sep + anchor
        if raw.startswith("<"):
            new = "<" + new + ">"
        if new != raw:
            self.count(pub, "rewritten")
        return "keep", new

    def overlay_target(self, pub, raw, line):
        """An overlay file is written for the public layout: its relative links must resolve there."""
        target = raw.strip("<>")
        if not target or target.startswith("#") or re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            return "keep", raw
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(pub),
                                                       urllib.parse.unquote(target.split("#", 1)[0])))
        present = set(self.files) | set(self.kept_public_of.values())
        if resolved in present or any(p.startswith(resolved.rstrip("/") + "/") for p in present):
            return "keep", raw
        if self.at_ref:
            self.notes.append(f"{pub}:{line}: {target} -> link dropped (not in the tree at {self.source.ref})")
            return "delink", "internal"
        self.error("links", f"{EXPORT_DIR}/overlay/{pub}:{line}", f"{target} -> {resolved}, which the public tree "
                   f"does not have")
        return None


# --- Markdown ---

FENCE_RE = re.compile(r"^ {0,3}(```+|~~~+)")
INLINE_CODE_RE = re.compile(r"(`+)(.+?)\1")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
LINK_RE = re.compile(r"(!?)\[((?:[^\[\]\\]|\\.|\[(?:[^\[\]\\]|\\.)*\])*)\]\(\s*(<[^>\n]*>|[^)\s]+)"
                     r"((?:\s+(?:\"[^\"\n]*\"|'[^'\n]*'))?)\s*\)")
REF_DEF_RE = re.compile(r"^( {0,3})\[([^\]\n]+)\]:[ \t]*(<[^>\n]*>|\S+)([^\n]*)$", re.M)
HTML_ATTR_RE = re.compile(r"""\b(?:href|src)[ \t]*=[ \t]*(["'])([^"'\n]*)\1""", re.I)
REF_USE_RE = re.compile(r"(!?)\[((?:[^\[\]\\]|\\.|\[(?:[^\[\]\\]|\\.)*\])*)\]\[([^\]\n]*)\]")


def split_fences(text):
    """[(is_code, chunk)] in order; fenced blocks are code."""
    out, buf, fence = [], [], None
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if fence:
            buf.append(line)
            if m and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) and not line.strip()[len(m.group(1)):].strip():
                out.append((True, "\n".join(buf)))
                buf, fence = [], None
            continue
        if m:
            if buf:
                out.append((False, "\n".join(buf)))
            buf, fence = [line], m.group(1)
            continue
        buf.append(line)
    if buf:
        out.append((bool(fence), "\n".join(buf)))
    return out


def masked(chunk):
    """The chunk with inline code and HTML comments blanked, offsets kept, so a link is found only in prose."""
    lines = [INLINE_CODE_RE.sub(lambda m: m.group(1) + " " * len(m.group(2)) + m.group(1), ln)
             for ln in chunk.split("\n")]
    text = "\n".join(lines)
    return HTML_COMMENT_RE.sub(lambda m: "".join("\n" if c == "\n" else " " for c in m.group(0)), text)


def transform_markdown(text, decide, html_delink=None):
    """Each link target in prose through decide(raw_target, line) -> ('keep', new) | ('delink', kind) | None.
    An HTML href or src in prose goes through decide too; one it would de-link cannot lose its element cleanly,
    so html_delink(raw_target, line) is told instead."""
    chunks = split_fences(text)
    out, line_base = [], 1
    for is_code, chunk in chunks:
        if is_code:
            out.append(chunk)
            line_base += chunk.count("\n") + 1
            continue
        mask = masked(chunk)
        edits = []      # (start, end, replacement)
        dropped = set()
        for m in REF_DEF_RE.finditer(mask):
            label = m.group(2)
            if label.startswith("^"):
                continue
            line = line_base + chunk.count("\n", 0, m.start())
            verdict = decide(chunk[m.start(3):m.end(3)], line)
            if verdict is None:
                continue
            if verdict[0] == "delink":
                dropped.add(label.strip().lower())
                end = m.end() + 1 if m.end() < len(chunk) else m.end()
                edits.append((m.start(), end, ""))
            elif verdict[1] != chunk[m.start(3):m.end(3)]:
                edits.append((m.start(3), m.end(3), verdict[1]))
        for m in LINK_RE.finditer(mask):
            line = line_base + chunk.count("\n", 0, m.start())
            verdict = decide(chunk[m.start(3):m.end(3)], line)
            if verdict is None:
                continue
            if verdict[0] == "delink":
                edits.append((m.start(), m.end(), chunk[m.start(2):m.end(2)]))
            elif verdict[1] != chunk[m.start(3):m.end(3)]:
                edits.append((m.start(3), m.end(3), verdict[1]))
        for m in HTML_ATTR_RE.finditer(mask):
            line = line_base + chunk.count("\n", 0, m.start())
            raw = chunk[m.start(2):m.end(2)]
            verdict = decide(raw, line)
            if verdict is None:
                continue
            if verdict[0] == "delink":
                if html_delink is not None:
                    html_delink(raw, line)
            elif verdict[1] != raw:
                edits.append((m.start(2), m.end(2), verdict[1]))
        if dropped:
            for m in REF_USE_RE.finditer(mask):
                label = (m.group(3) or m.group(2)).strip().lower()
                if label in dropped and not any(s <= m.start() < e for s, e, _ in edits):
                    edits.append((m.start(), m.end(), chunk[m.start(2):m.end(2)]))
        edits.sort()
        result, pos = [], 0
        for s, e, rep in edits:
            if s < pos:
                continue
            result.append(chunk[pos:s])
            result.append(rep)
            pos = e
        result.append(chunk[pos:])
        out.append("".join(result))
        line_base += chunk.count("\n") + 1
    return "\n".join(out)


# --- bare URLs and slugs, in every text file ---

def transform_bare(text, export, src, pub):
    def line_at(t, offset):
        return t.count("\n", 0, offset) + 1

    def url(m):
        found, tail = trim_url(m.group(0))
        opened = m.group(0).startswith("<")
        if opened:
            found = found[1:]
        action, new = map_url(found)
        if action == "rewrite":
            export.count(pub, "rewritten")
            return ("<" if opened else "") + new + tail
        if action == "delink":
            export.count(pub, "internal")
            return UNKNOWN_URL_TEXT + tail.rstrip(">")
        if export.at_ref:
            export.notes.append(f"{pub}:{line_at(text, m.start())}: {found} -> {UNKNOWN_URL_TEXT}")
            export.count(pub, "internal")
            return UNKNOWN_URL_TEXT + tail.rstrip(">")
        export.error("urls", f"{src}:{line_at(text, m.start())}", f"{found} is not in the rewrite table")
        return m.group(0)

    text = re.sub(r"<?" + URL_RE.pattern + r">?", url, text)

    def private(m):
        found, tail = trim_url(m.group(0))
        export.count(pub, "private")
        return m.group("repo").split("/")[1] + tail

    text = PRIVATE_URL_RE.sub(private, text)

    def flag(m):
        export.count(pub, "rewritten")
        return m.group(1) + PUBLIC_SLUG

    text = SLUG_FLAG_RE.sub(flag, text)

    def slug(m):
        if export.at_ref:
            export.notes.append(f"{pub}:{line_at(text, m.start())}: {INTERNAL_SLUG} -> {UNKNOWN_URL_TEXT}")
            return UNKNOWN_URL_TEXT
        export.error("urls", f"{src}:{line_at(text, m.start())}", f"{INTERNAL_SLUG} outside a URL or a "
                     f"gh --repo/-R flag; name {PUBLIC_SLUG} or nothing")
        return m.group(0)

    return SLUG_RE.sub(slug, text)


# --- the overlay ---

def template(text, values, conditions):
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    pattern = re.compile(r"<!-- (if|unless):(\w+) -->\n?(.*?)<!-- end:\2 -->\n?", re.S)
    while True:
        m = pattern.search(text)
        if not m:
            break
        kind, name, body = m.groups()
        if name not in conditions:
            raise ManifestError(f"unknown overlay condition {name!r} (one of {', '.join(sorted(conditions))})")
        keep = conditions[name] if kind == "if" else conditions["un" + name]
        text = text[:m.start()] + (body if keep else "") + text[m.end():]
    left = re.search(r"\{\{\w+\}\}|<!-- (if|unless|end):", text)
    if left:
        raise ManifestError(f"the overlay has an unresolved {left.group(0)!r}")
    return text


def env_value(data, key):
    for line in data.decode("utf-8", errors="replace").split("\n"):
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return None


# --- guards over the final tree ---

def load_secrets_scan():
    path = os.path.join(TOOLS, "ci", "secrets-scan.py")
    spec = importlib.util.spec_from_file_location("secrets_scan", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_deny(path):
    """[(regex, reason, line)]: one regex per line, `<regex> # <reason>`, case-insensitive."""
    deny = []
    with open(path, encoding="utf-8") as f:
        for number, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if " # " not in line:
                raise ManifestError(f"deny.txt:{number}: expected `<regex> # <reason>`")
            pattern, reason = line.split(" # ", 1)
            try:
                deny.append((re.compile(pattern.strip(), re.I), reason.strip(), number))
            except re.error as e:
                raise ManifestError(f"deny.txt:{number}: {e}")
    return deny


def redact(pattern, line):
    """A deny hit in a tag's file, which cannot be edited: the match, with the name it ends (the run of name
    characters before it, so a host's first label goes too), becomes REDACTED."""
    out, pos = [], 0
    for m in pattern.finditer(line):
        start = m.start()
        while start > pos and re.match(r"[A-Za-z0-9-]", line[start - 1]):
            start -= 1
        out.append(line[pos:start])
        out.append(REDACTED)
        pos = m.end()
    out.append(line[pos:])
    return "".join(out)


def is_text(data):
    if b"\0" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def where(export, pub):
    src = export.files[pub][2]
    return src if src else pub


def guard(export, deny, scan_text):
    for pub in sorted(export.files):
        mode, data, src = export.files[pub]
        for path in filter(None, (src, pub)):
            for pattern, why in NO_SOURCE:
                if pattern.search(path):
                    export.error("no-source", path, f"{why} is never exported")
                    break
        if mode == "120000":
            export.error("no-source", src or pub, "a symbolic link; export the file it points at")
        if not is_text(data):
            if not pub.lower().endswith(BINARY_EXTENSIONS):
                export.error("binaries", src or pub, f"a binary file; only {', '.join(BINARY_EXTENSIONS)} are exported")
            elif len(data) > BINARY_LIMIT:
                export.error("binaries", src or pub, f"{len(data)} bytes, over the {BINARY_LIMIT} byte limit")
            continue
        text = data.decode("utf-8")
        lines = text.split("\n")
        for number, line in enumerate(lines, 1):
            for pattern, reason, _ in deny:
                if not pattern.search(line):
                    continue
                if export.at_ref:
                    line = redact(pattern, line)
                    export.notes.append(f"{pub}:{number}: matches `{pattern.pattern}` ({reason}) -> {REDACTED}")
                    continue
                export.error("deny", f"{pub}:{number}" + (f" (from {src})" if src and src != pub else ""),
                             f"matches `{pattern.pattern}` - {reason}")
            lines[number - 1] = line
        if export.at_ref and lines != text.split("\n"):
            text = "\n".join(lines)
            export.files[pub] = (mode, text.encode("utf-8"), src)
        for number, kind in scan_text(text):
            export.error("secrets", f"{pub}:{number}" + (f" (from {src})" if src and src != pub else ""), kind)


# --- the whole run ---

def build(root, ref=None, version=None, docs_only=False, docs_alone=False):
    export_dir = os.path.join(root, EXPORT_DIR)
    try:
        with open(os.path.join(export_dir, "manifest.txt"), encoding="utf-8") as f:
            rules = parse_manifest(f.read())
    except OSError as e:
        raise ManifestError(f"cannot read the manifest: {e}")
    deny = read_deny(os.path.join(export_dir, "deny.txt"))
    source = Source(root, ref)
    export = Export(root, source, rules, docs_only, docs_alone)
    if version is None and ref:
        m = re.match(r"^v?(\d+\.\d+\.\d+)$", ref)
        version = m.group(1) if m else None
    export.version = version
    export.select()

    for pub in sorted(export.files):
        mode, _, src = export.files[pub]
        data = source.read(src)
        if is_text(data) and mode != "120000":
            text = data.decode("utf-8")
            if pub.endswith(".md"):
                text = transform_markdown(
                    text, lambda raw, line, s=src, p=pub: export.target(s, p, raw, line),
                    lambda raw, line, s=src: export.error("links", f"{s}:{line}", f"{raw} in an HTML href or src "
                                                          f"would be de-linked; write it as a Markdown link"))
            text = transform_bare(text, export, src, pub)
            data = text.encode("utf-8")
        export.files[pub] = (mode, data, src)

    # the overlay and image/release.env
    pf_version = None
    if "build/pf-version.env" in source.modes:
        pf_version = env_value(source.read("build/pf-version.env"), "PF_VERSION")
    full = set(export.full_public_of.values())
    demo = any(p.startswith("demo/") for p in full)
    staging = "image/stage-from-release.sh" in full
    conditions = {"demo": demo and not docs_alone, "staging": staging and not docs_alone,
                  "unstaging": demo and not staging and not docs_alone}
    values = {"VERSION": version or "<version>", "TAG": f"v{version}" if version else "v<version>",
              "PF_VERSION": pf_version or "<PingFederate version>"}
    # The overlay is this checkout's, whatever the source ref, and only its tracked files: an untracked file
    # dropped into the directory never reaches the tree.
    overlay_prefix = EXPORT_DIR + "/overlay/"
    tracked = git(root, "ls-files", "-s", "-z", "--", overlay_prefix)
    overlay = []
    for entry in sorted(e for e in tracked.split(b"\0") if e):
        meta, path = entry.split(b"\t", 1)
        rel = path.decode("utf-8")
        pub = rel[len(overlay_prefix):]
        if pub in export.files:
            raise ManifestError(f"the overlay's {pub} and the manifest's {export.files[pub][2]} both land there")
        with open(os.path.join(root, rel), encoding="utf-8") as f:
            text = template(f.read(), values, conditions)
        mode = "100755" if meta.split()[0] == b"100755" else "100644"
        export.files[pub] = (mode, text.encode("utf-8"), None)
        overlay.append(pub)
    overlay.sort()
    if version and any(p.startswith("image/") for p in export.files):
        export.files["image/release.env"] = (
            "100644", f"PFAI_RELEASE={version}\nPFAI_RELEASE_REPO={PUBLIC_SLUG}\n".encode("utf-8"), None)
    for pub in overlay:
        if pub.endswith(".md"):
            mode, data, _ = export.files[pub]
            text = transform_markdown(
                data.decode("utf-8"), lambda raw, line, p=pub: export.overlay_target(p, raw, line),
                lambda raw, line, p=pub: export.error("links", f"{EXPORT_DIR}/overlay/{p}:{line}", f"{raw} in an "
                                                      f"HTML href or src does not resolve in the public tree"))
            export.files[pub] = (mode, text.encode("utf-8"), None)

    guard(export, deny, load_secrets_scan().scan_text)
    return export


def write_tree(export, out):
    for pub in sorted(export.files):
        mode, data, _ = export.files[pub]
        path = os.path.join(out, pub)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        os.chmod(path, 0o755 if mode == "100755" else 0o644)


def tree_digest(export):
    h = hashlib.sha256()
    for pub in sorted(export.files):
        mode, data, _ = export.files[pub]
        h.update(f"{'100755' if mode == '100755' else '100644'} {pub}\0".encode("utf-8"))
        h.update(hashlib.sha256(data).digest())
    return h.hexdigest()


def summary(export):
    lines = []
    ref = export.source.ref or "HEAD (the index)"
    lines.append(f"public tree from {ref}: {len(export.files)} files, tree sha256 {tree_digest(export)}"
                 + (" (docs alone)" if export.docs_alone else " (docs only)" if export.docs_only else ""))
    totals = {"rewritten": 0, "internal": 0, "private": 0}
    for pub in sorted(export.counts):
        c = export.counts[pub]
        for k in totals:
            totals[k] += c[k]
        lines.append(f"  {pub}: {c['rewritten']} rewritten, {c['internal']} de-linked (internal), "
                     f"{c['private']} de-linked (private)")
    lines.append(f"links: {totals['rewritten']} rewritten, {totals['internal']} de-linked (internal), "
                 f"{totals['private']} de-linked (private)")
    for m in export.missing:
        lines.append(f"not present: {m}")
    for n in export.notes:
        lines.append(f"listed: {n}")
    return lines


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("outdir", nargs="?", help="where to write the tree (absent, or empty apart from .git)")
    ap.add_argument("--check", action="store_true", help="build in a temporary directory, guard, summarise, remove")
    ap.add_argument("--source-ref", metavar="REF", help="export this ref's tree (a tag) instead of the index")
    ap.add_argument("--version", help="the release version, for the overlay and image/release.env")
    ap.add_argument("--docs-only", action="store_true", help="write only the root and docs classes and the overlay, "
                    "for a public tree that keeps its image/ and demo/")
    ap.add_argument("--docs-alone", action="store_true", help="as --docs-only, for a public tree with no image/ or "
                    "demo/: links into them are de-linked and the overlay leaves them out")
    ap.add_argument("--root", default=os.path.normpath(os.path.join(TOOLS, "..")),
                    help="the repository root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    if args.check == bool(args.outdir):
        print("error: give an output directory or --check, not both or neither", file=sys.stderr)
        return 2
    if args.version and not re.match(r"^v?\d+\.\d+\.\d+$", args.version):
        print(f"error: --version {args.version!r} is not a release version (0.7.0)", file=sys.stderr)
        return 2
    version = args.version.lstrip("v") if args.version else None
    root = os.path.abspath(args.root)
    if args.outdir:
        out = os.path.abspath(args.outdir)
        if os.path.exists(out) and (not os.path.isdir(out) or set(os.listdir(out)) - {".git"}):
            print(f"error: {args.outdir} exists and is not empty", file=sys.stderr)
            return 2
    try:
        export = build(root, args.source_ref, version, args.docs_only, args.docs_alone)
    except (ManifestError, UsageError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for line in summary(export):
        print(line)
    if export.errors:
        for guard_name, location, message in export.errors:
            print(f"error: [{guard_name}] {location}: {message}", file=sys.stderr)
        print(f"error: {len(export.errors)} guard failure(s); nothing was written", file=sys.stderr)
        return 1
    if args.check:
        tmp = tempfile.mkdtemp(prefix="public-export-")
        try:
            write_tree(export, tmp)
        finally:
            shutil.rmtree(tmp)
        print("ok: every guard passed")
        return 0
    staging = tempfile.mkdtemp(prefix="public-export-", dir=os.path.dirname(out) if os.path.isdir(os.path.dirname(out)) else None)
    try:
        write_tree(export, staging)
        os.makedirs(out, exist_ok=True)
        for name in sorted(os.listdir(staging)):
            shutil.move(os.path.join(staging, name), os.path.join(out, name))
    finally:
        shutil.rmtree(staging, ignore_errors=True)
    print(f"ok: written to {args.outdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
