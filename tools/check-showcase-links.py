#!/usr/bin/env python3
"""Every file:line box on the showcase pages points at a file in this repository, and at lines it has.

The pages promise a boxed link to the file behind each statement. This keeps the mechanical half of that
promise: each `src` in showcase/index.html's DATA, and each link from showcase/federation.html into the
repository, names a tracked file, and every line it names exists in that file. It can't tell whether the lines
still say what the statement says - that is a reading job, for whoever changes the code - but it catches the file
that moved and the line past the end. A reference into a sibling repository (`pf-oidf-modules:path`) is not
checked here. Every `#doc:` link, and every document the documentation index lists, must name a document the
page carries.

    python3 tools/check-showcase-links.py
"""
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "showcase" / "index.html"
PAGES = [ROOT / "showcase" / "federation.html"]
HREF_RE = re.compile(r'<a\b[^>]*\bhref="([^"]+)"[^>]*>')
LINES_RE = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
DOC_LINK_RE = re.compile(r"#doc:([^\s\"'()#`<>\]]+)")


def constant(page, name):
    """The JSON value of `const NAME = ...;` on one line of the page."""
    start = page.index(f"const {name} = ") + len(f"const {name} = ")
    return json.loads(page[start:page.index("\n", start)].rstrip().rstrip(";"))


def siblings(page):
    start = page.index("const SIBLINGS = ")
    return set(re.findall(r"'([a-z-]+)':", page[start:page.index("\n", start)]))


def sources(node):
    """Every `src` value in DATA, as strings."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "src":
                yield from ([value] if isinstance(value, str) else [v for v in value if isinstance(v, str)])
            else:
                yield from sources(value)
    elif isinstance(node, list):
        for value in node:
            yield from sources(value)


def problems(reference, tracked, directories, sibling_repos, line_counts):
    """What is wrong with one `src` value, which may name several files separated by semicolons."""
    found = []
    for segment in (s.strip() for s in reference.split(";")):
        if not segment:
            continue
        prefix = segment.split(":", 1)[0]
        if prefix in sibling_repos:
            continue
        # As the page reads it: the path runs to the first colon or space; after a colon come the lines; anything
        # after a space is a note for the reader.
        path = re.split(r"[:\s]", segment, maxsplit=1)[0]
        rest = segment[len(path):]
        lines = re.split(r"\s", rest[1:], maxsplit=1)[0] if rest.startswith(":") else ""
        if path not in tracked:
            if path.rstrip("/") in directories and not lines:
                continue
            found.append(f"{segment}: {path} is not a tracked file")
            continue
        if not lines:
            continue
        if not LINES_RE.match(lines):
            found.append(f"{segment}: '{lines}' is not a line or range")
            continue
        count = line_counts(path)
        for part in lines.split(","):
            first, _, last = part.partition("-")
            first, last = int(first), int(last or first)
            if first < 1 or last < first or last > count:
                found.append(f"{segment}: {path} has {count} lines, not {part}")
    return found


def page_links(page, docs, tracked, directories, sibling_repos, line_counts):
    """The links from another showcase page: into the repository (with any data-lines), and into index.html's documents."""
    found = []
    name = page.relative_to(ROOT)
    for tag in HREF_RE.finditer(page.read_text(encoding="utf-8")):
        href = tag.group(1)
        lines = re.search(r'\bdata-lines="([^"]+)"', tag.group(0))
        if href.startswith("index.html#doc:"):
            target = href[len("index.html#doc:"):].split("#")[0]
            if target not in docs:
                found.append(f"{href} (in {name}): the page carries no such document")
        elif href.startswith("../"):
            reference = href[3:].split("#")[0] + (":" + lines.group(1) if lines else "")
            found.extend(f"{problem} (in {name})" for problem in problems(reference, tracked, directories, sibling_repos, line_counts))
    return found


def main():
    page = PAGE.read_text(encoding="utf-8")
    data = constant(page, "DATA")
    docs = constant(page, "DOCS_HTML")
    tracked = set(subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.split("\n"))
    tracked.discard("")
    directories = {str(Path(p).parent) for p in tracked}
    directories |= {str(parent) for p in tracked for parent in Path(p).parents}
    sibling_repos = siblings(page)
    counts = {}

    def line_counts(path):
        if path not in counts:
            counts[path] = len((ROOT / path).read_text(encoding="utf-8", errors="replace").splitlines())
        return counts[path]

    failures = []
    references = list(sources(data))
    for reference in references:
        failures.extend(problems(reference, tracked, directories, sibling_repos, line_counts))
    for group in data.get("docs", []):
        for item in group.get("items", []):
            if item.get("path") not in docs:
                failures.append(f"{item.get('path')} (in the documentation index): the page carries no such document")
    for other in PAGES:
        failures.extend(page_links(other, docs, tracked, directories, sibling_repos, line_counts))
    data_text = json.dumps(data)
    for target in sorted(set(DOC_LINK_RE.findall(data_text))):
        if target not in docs:
            failures.append(f"#doc:{target} (in DATA): the page carries no such document")
    for doc, rendered in docs.items():
        for target in sorted(set(DOC_LINK_RE.findall(rendered["html"]))):
            if target not in docs:
                failures.append(f"#doc:{target} (in {doc}): the page carries no such document")

    if failures:
        print(f"showcase/index.html: {len(failures)} of its references point nowhere:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"showcase/index.html: all {len(references)} source references and every #doc: link resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
