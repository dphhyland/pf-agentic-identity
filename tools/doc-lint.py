#!/usr/bin/env python3
"""House style, checked: em dashes, American spellings, scaffolding phrases and broken relative links, in
every tracked Markdown document.

  tools/doc-lint.py                       every tracked .md, judged against docs/development/doc-lint-baseline.txt
  tools/doc-lint.py docs/releases/0.4.0.md   these files only, against the same baseline
  tools/doc-lint.py --update-baseline     rewrite the baseline from what the tree has now

The rules are the style guide's (docs/development/style-guide.md), the ones a machine can check:

  em-dash      an em dash (U+2014) anywhere in prose; the house style is a spaced hyphen, " - ".
  en-dash      an en dash (U+2013) used as a dash: between spaces, or between letters. A range of numbers
               (2026-2027 written with an en dash) is left alone.
  spelling     a short, explicit list of American spellings whose British form the repo uses (artefact,
               behaviour, catalogue, ...). OAuth's own words are not on it: "authorization server" and
               `authorization_details` are the specification's spelling and stay.
  scaffolding  "let's dive", "in conclusion", "I hope this helps", "delve".
  link         a relative link whose target does not exist (checked after the fragment is removed; a link to
               a directory counts when the directory exists).

What is left alone: fenced code blocks, inline code, HTML comments, URLs and link destinations (for the
spelling rule), and text in double quotes - a verbatim quotation keeps whatever it was written with. Files under
a .claude/ directory are instructions to an assistant, not documentation, and are skipped.

The baseline: what the tree already had when the check arrived, per file and rule, as counts. A file may not
gain a hit above its count; fixing one lowers the count it can carry, and --update-baseline writes the lower
number. A file that is not in the baseline may carry nothing. That is a ratchet rather than a block: the
check never fails on a document someone else wrote until they touch it, and it never lets a document get worse.

Exit status: 0 when every hit is within the baseline, 1 when one is not (or a file is unreadable), 2 for a
usage error.
"""
import argparse
import datetime
import os
import re
import subprocess
import sys
import urllib.parse

BASELINE = "docs/development/doc-lint-baseline.txt"
EXCLUDED = re.compile(r"(^|/)\.claude/")
RULES = ("em-dash", "en-dash", "spelling", "scaffolding", "link")

# American spelling -> the form the repo writes. Explicit and small on purpose: a word goes on this list
# when the British form is the one the repo uses and the American one has no other meaning here.
AMERICAN = {}
for _pairs in (
    ("behavior behaviour", "behaviors behaviours", "color colour", "colors colours", "colored coloured",
     "center centre", "centers centres", "centered centred", "favor favour", "favors favours",
     "favorite favourite", "honor honour", "honors honours", "honored honoured",
     "organize organise", "organizes organises", "organized organised", "organizing organising",
     "organization organisation", "organizations organisations",
     "recognize recognise", "recognizes recognises", "recognized recognised", "recognizing recognising",
     "initialize initialise", "initializes initialises", "initialized initialised", "initializing initialising",
     "initialization initialisation", "serialize serialise", "serialized serialised", "serialization serialisation",
     "deserialize deserialise", "deserialized deserialised", "deserialization deserialisation",
     "normalize normalise", "normalized normalised", "normalization normalisation",
     "optimize optimise", "optimized optimised", "optimization optimisation",
     "minimize minimise", "minimized minimised", "maximize maximise", "maximized maximised",
     "customize customise", "customized customised", "customization customisation",
     "summarize summarise", "summarized summarised", "summarizes summarises",
     "finalize finalise", "finalized finalised", "prioritize prioritise", "prioritized prioritised",
     "standardize standardise", "standardizes standardises", "standardized standardised",
     "standardization standardisation", "utilize utilise", "utilized utilised",
     "realize realise", "realized realised", "characterize characterise", "characterized characterised",
     "characterization characterisation", "sanitize sanitise", "sanitized sanitised",
     "synchronize synchronise", "synchronized synchronised", "synchronization synchronisation",
     "randomize randomise", "randomized randomised", "categorize categorise", "categorized categorised",
     "analyze analyse", "analyzed analysed", "analyzes analyses", "analyzing analysing",
     "catalog catalogue", "catalogs catalogues", "cataloged catalogued",
     "defense defence", "offense offence", "gray grey", "fulfill fulfil", "fulfills fulfils",
     "modeled modelled", "modeling modelling", "canceled cancelled", "canceling cancelling",
     "labeled labelled", "labeling labelling", "artifact artefact", "artifacts artefacts"),
):
    for _pair in _pairs:
        _a, _b = _pair.split()
        AMERICAN[_a] = _b

SCAFFOLDING = [
    (re.compile(r"let'?s dive", re.I), "let's dive"),
    (re.compile(r"\bin conclusion\b", re.I), "in conclusion"),
    (re.compile(r"i hope this helps", re.I), "I hope this helps"),
    (re.compile(r"\bdelv(e|es|ed|ing)\b", re.I), "delve"),
]

FENCE_RE = re.compile(r"^ {0,3}(```|~~~)")
INLINE_CODE_RE = re.compile(r"(`+)(.+?)\1")
HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)
QUOTED_RE = re.compile(r"\"[^\"\n]*\"|“[^”\n]*”")
URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s)>\]]+")
LINK_RE = re.compile(r"\]\(\s*(<[^>]*>|[^)\s]+)(\s+(\"[^\"]*\"|'[^']*'))?\s*\)")
REFERENCE_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*(\S+)", re.M)
WORD_RE = re.compile(r"[A-Za-z]+")
TOKEN_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./@-")


class Hit:
    def __init__(self, path, line, col, rule, message):
        self.path, self.line, self.col, self.rule, self.message = path, line, col, rule, message

    def __str__(self):
        return f"{self.path}:{self.line}:{self.col}: {self.rule}: {self.message}"


def blank(match):
    """The match replaced by spaces, newlines kept, so every offset after it still means the same line."""
    return "".join("\n" if c == "\n" else " " for c in match.group(0))


def without_code(text):
    """Fenced blocks and inline code blanked out."""
    out = []
    in_fence = None
    for line in text.split("\n"):
        m = FENCE_RE.match(line)
        if in_fence:
            out.append(" " * len(line))
            if m and m.group(1).startswith(in_fence):
                in_fence = None
            continue
        if m:
            in_fence = m.group(1)
            out.append(" " * len(line))
            continue
        out.append(INLINE_CODE_RE.sub(blank, line))
    text = "\n".join(out)
    return HTML_COMMENT_RE.sub(blank, text)


def without_quotes(text):
    return QUOTED_RE.sub(blank, text)


def without_urls_and_links(text):
    text = LINK_RE.sub(lambda m: "](" + " " * (len(m.group(0)) - 3) + ")", text)
    text = REFERENCE_RE.sub(lambda m: m.group(0)[:m.start(1) - m.start(0)] + " " * len(m.group(1)), text)
    return URL_RE.sub(blank, text)


def position(text, offset):
    line = text.count("\n", 0, offset) + 1
    col = offset - (text.rfind("\n", 0, offset) + 1) + 1
    return line, col


def token_around(text, start, end):
    """The run of identifier characters the word sits in, so `artifactId`, `upload-artifact@v7`,
    `file.artifact` and `x_artifact` are seen as identifiers and not as prose."""
    a, b = start, end
    while a > 0 and text[a - 1] in TOKEN_CHARS:
        a -= 1
    while b < len(text) and text[b] in TOKEN_CHARS:
        b += 1
    return text[a:b]


def looks_like_identifier(token, word):
    if any(c in token for c in "_/@"):
        return True
    if any(c.isdigit() for c in token):
        return True
    if re.search(r"\.[A-Za-z]", token):
        return True
    if word[1:] != word[1:].lower():     # camelCase or ALLCAPS
        return True
    return False


def check_text(path, text):
    """Every hit in one document."""
    hits = []
    prose = without_code(text)
    unquoted = without_quotes(prose)
    for m in re.finditer("—", unquoted):
        line, col = position(text, m.start())
        hits.append(Hit(path, line, col, "em-dash", "em dash (U+2014); write a spaced hyphen, ' - '"))
    for m in re.finditer(r" – |(?<=[A-Za-z])–|–(?=[A-Za-z])", unquoted):
        line, col = position(text, m.start())
        hits.append(Hit(path, line, col, "en-dash", "en dash (U+2013) used as a dash; write a spaced hyphen, ' - '"))
    spelling_text = without_urls_and_links(unquoted)
    for m in WORD_RE.finditer(spelling_text):
        word = m.group(0)
        british = AMERICAN.get(word.lower())
        if not british:
            continue
        token = token_around(spelling_text, m.start(), m.end())
        if looks_like_identifier(token, word):
            continue
        line, col = position(text, m.start())
        hits.append(Hit(path, line, col, "spelling", f"'{word}': the repo writes {british}"))
    for pattern, label in SCAFFOLDING:
        for m in pattern.finditer(unquoted):
            line, col = position(text, m.start())
            hits.append(Hit(path, line, col, "scaffolding", f"'{label}' is scaffolding; say the thing"))
    hits.extend(check_links(path, prose))
    hits.sort(key=lambda h: (h.line, h.col, h.rule))
    return hits


def check_links(path, prose):
    hits = []
    base = os.path.dirname(path)
    targets = [(m.start(1), m.group(1)) for m in LINK_RE.finditer(prose)]
    targets += [(m.start(1), m.group(1)) for m in REFERENCE_RE.finditer(prose)]
    for offset, target in targets:
        raw = target.strip("<>")
        if not raw or raw.startswith("#") or re.match(r"[a-z][a-z0-9+.-]*:", raw, re.I):
            continue
        rel = urllib.parse.unquote(raw.split("#", 1)[0])
        if not rel:
            continue
        resolved = os.path.normpath(os.path.join(base, rel))
        if not os.path.exists(resolved):
            line, col = position(prose, offset)
            hits.append(Hit(path, line, col, "link", f"{raw} does not resolve ({resolved} does not exist)"))
    return hits


def tracked_documents(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z", "*.md"], capture_output=True, text=True, check=True).stdout
    return sorted(p for p in out.split("\0") if p and not EXCLUDED.search(p))


def walked_documents(root):
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in (".git", "node_modules", "target"))
        for name in filenames:
            if name.endswith(".md"):
                rel = os.path.relpath(os.path.join(dirpath, name), root)
                if not EXCLUDED.search(rel):
                    found.append(rel)
    return sorted(found)


def read_baseline(path):
    """{(file, rule): count}. A line is `file rule count`; blank lines and # comments are ignored."""
    entries = {}
    if not os.path.isfile(path):
        return entries
    with open(path, encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) != 3 or parts[1] not in RULES or not parts[2].isdigit():
                raise SystemExit(f"error: {path}:{number}: expected `file rule count`, got {line!r}")
            entries[(parts[0], parts[1])] = int(parts[2])
    return entries


def write_baseline(path, counts, today):
    lines = [
        "# tools/doc-lint.py's baseline: the hits each tracked document already carried when the check arrived,",
        "# per rule, as counts. A document may not go above its count; fixing a hit lets the count come down.",
        "# Regenerate with `python3 tools/doc-lint.py --update-baseline` after fixing some, and never to admit new",
        f"# ones. Written {today}.",
    ]
    for (file, rule), count in sorted(counts.items()):
        if count:
            lines.append(f"{file} {rule} {count}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def run(root, files, baseline_path, update, today):
    hits_by_file = {}
    unreadable = []
    for rel in files:
        full = os.path.join(root, rel)
        try:
            with open(full, encoding="utf-8") as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            unreadable.append(f"{rel}: {e}")
            continue
        hits_by_file[rel] = check_text(full, text)
    counts = {}
    for rel, hits in hits_by_file.items():
        for h in hits:
            counts[(rel, h.rule)] = counts.get((rel, h.rule), 0) + 1
    if update:
        old = read_baseline(baseline_path)
        raised = [(k, old.get(k, 0), v) for k, v in counts.items() if v > old.get(k, 0)]
        write_baseline(baseline_path, counts, today)
        print(f"wrote {os.path.relpath(baseline_path, root)}: {sum(counts.values())} hits in {len({k[0] for k in counts})} documents")
        for (file, rule), was, now in sorted(raised):
            print(f"  warning: {file} {rule} went up, {was} -> {now}; a new hit was admitted rather than fixed")
        return 0 if not unreadable else 1
    baseline = read_baseline(baseline_path)
    failed = 0
    improved = []
    for rel in sorted(hits_by_file):
        by_rule = {}
        for h in hits_by_file[rel]:
            by_rule.setdefault(h.rule, []).append(h)
        for rule, hits in sorted(by_rule.items()):
            allowed = baseline.get((rel, rule), 0)
            if len(hits) > allowed:
                failed += len(hits) - allowed
                print(f"{rel}: {len(hits)} {rule} hit{'s' if len(hits) != 1 else ''}, baseline {allowed}:", file=sys.stderr)
                for h in hits:
                    print(f"  {os.path.relpath(h.path, root)}:{h.line}:{h.col}: {h.message}", file=sys.stderr)
            elif len(hits) < allowed:
                improved.append(f"{rel} {rule}: {len(hits)} of {allowed} allowed; --update-baseline can lower it")
    for (rel, rule), allowed in sorted(baseline.items()):
        if rel in hits_by_file and not any(h.rule == rule for h in hits_by_file[rel]):
            improved.append(f"{rel} {rule}: 0 of {allowed} allowed; --update-baseline can drop it")
    for line in unreadable:
        print(f"error: {line}", file=sys.stderr)
    for line in improved:
        print(f"note: {line}")
    total = sum(len(h) for h in hits_by_file.values())
    if failed or unreadable:
        print(f"error: {failed} hit{'s' if failed != 1 else ''} above the baseline in {len(files)} documents", file=sys.stderr)
        return 1
    print(f"ok: {len(files)} documents, {total} hit{'s' if total != 1 else ''} all within the baseline "
          f"({len(baseline)} entries)")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("files", nargs="*", help="documents to check (default: every tracked .md)")
    ap.add_argument("--baseline", metavar="PATH", help=f"the baseline file (default: {BASELINE} under the root)")
    ap.add_argument("--update-baseline", action="store_true", help="rewrite the baseline from the hits found now")
    ap.add_argument("--no-git", action="store_true", help="walk the root for .md files instead of asking git")
    ap.add_argument("--today", help="the date written into an updated baseline (default: today)")
    ap.add_argument("--root", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."),
                    help="the repository root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)
    if args.files:
        files = []
        for f in args.files:
            rel = os.path.relpath(os.path.abspath(f), root)
            if rel.startswith(".."):
                ap.error(f"{f} is outside {root}")
            files.append(rel)
    elif args.no_git:
        files = walked_documents(root)
    else:
        files = tracked_documents(root)
    baseline_path = os.path.abspath(args.baseline) if args.baseline else os.path.join(root, BASELINE)
    today = args.today or datetime.date.today().isoformat()
    return run(root, files, baseline_path, args.update_baseline, today)


if __name__ == "__main__":
    sys.exit(main())
