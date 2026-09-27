#!/usr/bin/env python3
"""Release-note fragments: checked on every pull request, folded into a release's notes when it is cut.

A pull request that changes what a consumer must do adds docs/releases/unreleased/<ID>.md, named for its
package (S1B.md, HYG.md). A fragment has four headings, in this order:

    # <title>
    ## Changelog            bullets for CHANGELOG.md's Unreleased section
    ## Before you deploy    a numbered list; every item opens with a bold title
    ## Notes                what changed, how it was verified, the residual risk

An item is referred to by its bold title, never by its number: folding renumbers the fragment's items
after the ones already on the release page, so "item 3" would point at the wrong thing.

    python3 tools/release-notes.py check              # every fragment well formed; CI runs this
    python3 tools/release-notes.py assemble 0.4.0     # fold them into docs/releases/0.4.0.md and CHANGELOG.md

`assemble` appends each fragment's "Before you deploy" items after the page's own and numbers them on,
puts its Notes before "## Findings closed" as "## Package <ID>: <title>", appends its Changelog bullets to
CHANGELOG.md's Unreleased section, rewrites relative links for their new place, and deletes the fragment.
It checks everything before it writes anything, refuses a malformed fragment, and never renumbers an item
already on the page. Fragments fold in file-name order. Standard library only.
"""
import argparse
import os
import posixpath
import re
import sys

UNRELEASED = os.path.join("docs", "releases", "unreleased")
HEADINGS = ["Changelog", "Before you deploy", "Notes"]
# A list item at the left margin: "12. text".
ITEM = re.compile(r"^(\d+)\. (.*)$")
# An item's opening: a bold title, "**...**".
BOLD_TITLE = re.compile(r"^\*\*[^*\n]+\*\*")
# A reference to a list item by its number: "item 3", "items 4 and 5", "item 17's".
ITEM_BY_NUMBER = re.compile(r"\bitems?\s+\d", re.IGNORECASE)
# A Markdown inline link's target: "](target)" or "](target#anchor)".
LINK = re.compile(r"\]\(([^)\s]+)\)")
FENCE = re.compile(r"^\s*(```|~~~)")


class FragmentError(Exception):
    """A fragment, a page or the changelog is not in the shape this tool folds."""


def fragment_paths(root):
    folder = os.path.join(root, UNRELEASED)
    if not os.path.isdir(folder):
        return []
    return sorted(
        os.path.join(folder, name)
        for name in os.listdir(folder)
        if name.endswith(".md") and name != "README.md"
    )


def _unfenced(lines):
    """Yield (index, line) for every line outside a fenced code block."""
    fenced = False
    for i, line in enumerate(lines):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield i, line


def parse_fragment(path):
    """Read one fragment into {'id', 'title', 'Changelog', 'Before you deploy', 'Notes'}, or raise
    FragmentError naming every problem found."""
    rel = UNRELEASED_POSIX + "/" + os.path.basename(path)
    with open(path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    problems = []
    frag_id = os.path.basename(path)[:-3]
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9-]*", frag_id):
        problems.append(f"{rel}: the file name must be the package id in capitals (S1B.md, HYG.md)")

    body = list(_unfenced(lines))
    first = next(((i, l) for i, l in body if l.strip()), None)
    if first is None or not first[1].startswith("# "):
        problems.append(f"{rel}: the first line must be the title, '# <title>'")
        title = None
    else:
        title = first[1][2:].strip()
    for i, line in body:
        if line.startswith("# ") and (first is None or i != first[0]):
            problems.append(f"{rel}:{i + 1}: a second title; a fragment has one '# ' heading")

    h2 = [(i, line[3:].strip()) for i, line in body if line.startswith("## ")]
    names = [name for _, name in h2]
    if names != HEADINGS:
        problems.append(
            f"{rel}: the headings must be exactly {', '.join('## ' + h for h in HEADINGS)}, in that order; "
            f"found {', '.join('## ' + n for n in names) or 'none'}"
        )
    for i, line in body:
        if ITEM_BY_NUMBER.search(line):
            problems.append(
                f"{rel}:{i + 1}: refers to an item by its number; name it by its bold title, because "
                f"folding renumbers the items"
            )
    if problems:
        raise FragmentError("\n".join(problems))

    sections = {}
    bounds = [i for i, _ in h2] + [len(lines)]
    for n, name in enumerate(HEADINGS):
        sections[name] = _trim(lines[bounds[n] + 1:bounds[n + 1]])

    for name in ("Changelog", "Notes"):
        if not sections[name]:
            problems.append(f"{rel}: '## {name}' is empty")
    if sections["Changelog"] and not sections["Changelog"][0].startswith("- "):
        problems.append(f"{rel}: '## Changelog' must be a bulleted list ('- ...')")
    raw = lines[bounds[1] + 1:bounds[2]]
    lead = next((n for n, l in enumerate(raw) if l.strip()), 0)
    problems.extend(f"{rel}: {p}" for p in _check_items(sections["Before you deploy"], bounds[1] + 2 + lead))
    if problems:
        raise FragmentError("\n".join(problems))
    return {"id": frag_id, "title": _package_title(title, frag_id), "path": path, **sections}


def _trim(lines):
    while lines and not lines[0].strip():
        lines = lines[1:]
    while lines and not lines[-1].strip():
        lines = lines[:-1]
    return list(lines)


def _check_items(section, first_line_no):
    """The "Before you deploy" section: a numbered list from 1, each item opening with a bold title, and
    nothing at the left margin between the items."""
    problems = []
    if not section:
        return ["'## Before you deploy' is empty; a fragment with nothing for a consumer to do says 'None.'"]
    if section == ["None."]:
        return []
    expected = 1
    fenced = False
    for offset, line in enumerate(section):
        where = f"line {first_line_no + offset}"
        if FENCE.match(line):
            fenced = not fenced
        if fenced or not line.strip() or line.startswith(" "):
            continue
        m = ITEM.match(line)
        if not m:
            problems.append(f"{where}: text at the left margin that is not a numbered item; indent it into its item")
            continue
        if int(m.group(1)) != expected:
            problems.append(f"{where}: item numbered {m.group(1)}, expected {expected}")
        if not BOLD_TITLE.match(m.group(2)):
            problems.append(f"{where}: item {m.group(1)} does not open with a bold title, '**...**'")
        expected = int(m.group(1)) + 1
    if expected == 1:
        problems.append("'## Before you deploy' has no numbered item")
    return problems


def _package_title(title, frag_id):
    """The fragment's title without the package id it may carry: "S4A - the ..." or "... (S1b)"."""
    t = re.sub(r"^" + re.escape(frag_id) + r"\s*[-:]\s*", "", title, flags=re.IGNORECASE)
    t = re.sub(r"\s*\(" + re.escape(frag_id) + r"\)$", "", t, flags=re.IGNORECASE)
    return t


def items(section):
    """Split a "Before you deploy" list into items: each a list of lines, the first "N. ...". Blank lines
    between items are dropped; blank lines inside one are kept."""
    out = []
    for line in section:
        if ITEM.match(line):
            out.append([line])
        elif out:
            out[-1].append(line)
    return [_trim(item) for item in out]


def renumber(item, number):
    """The item as number `number`: the marker changed and every indented line moved by the marker's change
    in width, so continuation lines and nested lists stay inside the item."""
    m = ITEM.match(item[0])
    old_width = len(m.group(1)) + 2
    new_marker = f"{number}. "
    shift = len(new_marker) - old_width
    out = [new_marker + m.group(2)]
    for line in item[1:]:
        if line.startswith(" ") and shift > 0:
            out.append(" " * shift + line)
        elif line.startswith(" " * old_width) and shift < 0:
            out.append(line[-shift:])
        else:
            out.append(line)
    return out


def rebase_links(lines, src_dir, dest_dir):
    """Rewrite each relative link target, written relative to src_dir, to be relative to dest_dir (both
    relative to the repository root). URLs, anchors and absolute paths are left alone."""

    def fix(m):
        target = m.group(1)
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.IGNORECASE) or target.startswith(("#", "/")):
            return m.group(0)
        path, sep, anchor = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(src_dir, path))
        new = posixpath.relpath(resolved, dest_dir or ".")
        if path.endswith("/") and not new.endswith("/"):
            new += "/"
        return "](" + new + sep + anchor + ")"

    out, fenced = [], False
    for line in lines:
        if FENCE.match(line):
            fenced = not fenced
        out.append(line if fenced else LINK.sub(fix, line))
    return out


def _section_bounds(lines, heading_re, what, where):
    """(start, end) of the section whose heading matches: start is the heading's index, end the index of
    the next heading of the same level, or the end of the file."""
    starts = [i for i, _ in _unfenced(lines) if re.match(heading_re, lines[i])]
    if len(starts) != 1:
        raise FragmentError(f"{where}: expected one {what} heading, found {len(starts)}")
    start = starts[0]
    end = next((i for i, l in _unfenced(lines) if i > start and l.startswith("## ")), len(lines))
    return start, end


def fold_page(page_lines, fragments, page_dir):
    """The release page with every fragment folded in."""
    lines = list(page_lines)
    where = "the release page"
    start, end = _section_bounds(lines, r"^## Before you deploy\s*$", "'## Before you deploy'", where)
    existing = [int(ITEM.match(lines[i]).group(1)) for i, _ in _unfenced(lines[:end]) if i > start and ITEM.match(lines[i])]
    number = max(existing, default=0)
    added = []
    for frag in fragments:
        if frag["Before you deploy"] == ["None."]:
            continue
        for item in items(rebase_links(frag["Before you deploy"], UNRELEASED_POSIX, page_dir)):
            number += 1
            added.extend(renumber(item, number))
    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    if added:
        lines[insert_at:insert_at] = added
        end += len(added)

    f_start, _ = _section_bounds(lines, r"^## Findings closed\b", "'## Findings closed'", where)
    packages = []
    for frag in fragments:
        packages.append(f"## Package {frag['id']}: {frag['title']}")
        packages.append("")
        packages.extend(rebase_links(frag["Notes"], UNRELEASED_POSIX, page_dir))
        packages.append("")
    lines[f_start:f_start] = packages
    return lines


def fold_changelog(changelog_lines, fragments):
    """CHANGELOG.md with every fragment's Changelog bullets at the end of its Unreleased section."""
    lines = list(changelog_lines)
    start, end = _section_bounds(lines, r"^## \[Unreleased\]", "'## [Unreleased]'", "CHANGELOG.md")
    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1
    added = []
    for frag in fragments:
        added.append("")
        added.extend(rebase_links(frag["Changelog"], UNRELEASED_POSIX, ""))
    lines[insert_at:insert_at] = added
    return lines


UNRELEASED_POSIX = UNRELEASED.replace(os.sep, "/")


def check(root):
    paths = fragment_paths(root)
    errors = []
    for path in paths:
        try:
            parse_fragment(path)
        except FragmentError as e:
            errors.append(str(e))
    return paths, errors


def assemble(root, version):
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise FragmentError(f"'{version}' is not a release version (0.4.0)")
    paths = fragment_paths(root)
    if not paths:
        return []
    fragments = [parse_fragment(p) for p in paths]  # raises on the first malformed one
    page_rel = f"docs/releases/{version}.md"
    page = os.path.join(root, page_rel)
    if not os.path.isfile(page):
        raise FragmentError(f"{page_rel} does not exist; start the release page first")
    changelog = os.path.join(root, "CHANGELOG.md")
    with open(page, encoding="utf-8") as f:
        page_lines = f.read().splitlines()
    with open(changelog, encoding="utf-8") as f:
        changelog_lines = f.read().splitlines()
    new_page = fold_page(page_lines, fragments, "docs/releases")
    new_changelog = fold_changelog(changelog_lines, fragments)
    with open(page, "w", encoding="utf-8") as f:
        f.write("\n".join(new_page) + "\n")
    with open(changelog, "w", encoding="utf-8") as f:
        f.write("\n".join(new_changelog) + "\n")
    for frag in fragments:
        os.remove(frag["path"])
    return fragments


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", default=os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")),
                        help="the repository root (default: the parent of tools/)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="check every fragment under docs/releases/unreleased")
    fold = sub.add_parser("assemble", help="fold the fragments into docs/releases/<version>.md and CHANGELOG.md")
    fold.add_argument("version")
    args = parser.parse_args(argv)

    if args.command == "check":
        paths, errors = check(args.root)
        if errors:
            print("\n".join(errors), file=sys.stderr)
            print(f"release-notes: {len(errors)} of {len(paths)} fragments malformed", file=sys.stderr)
            return 1
        print(f"release-notes: {len(paths)} fragments well formed")
        return 0

    try:
        folded = assemble(args.root, args.version)
    except FragmentError as e:
        print(str(e), file=sys.stderr)
        print("release-notes: nothing written", file=sys.stderr)
        return 1
    if not folded:
        print("release-notes: no fragments to fold")
        return 0
    print(f"release-notes: folded {', '.join(f['id'] for f in folded)} into docs/releases/{args.version}.md "
          f"and CHANGELOG.md, and deleted the fragments")
    return 0


if __name__ == "__main__":
    sys.exit(main())
