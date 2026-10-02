#!/usr/bin/env python3
"""The body of a release on ID-Partners/pf-agentic-identity: a summary of the release page, never the page.

  tools/public-release-body.py VERSION --tree DIR [--source-ref REF] [--sums FILE]
                               [--mirrored [--date YYYY-MM-DD]] [--omit ASSET[=REASON]]... [-o FILE]

GitHub refuses a release body over 125,000 characters ("body is too long (maximum is 125000 characters)", the
error the API returns, quoted in cli/cli issue 7705, 2023-07-15; U-0465), and docs/releases/0.6.0.md alone is
348,293. So the body carries:

  - the release page's text before its first `##` heading, its relative links made absolute at the tag;
  - the bold titles of its "Before you deploy" items, as a list, with a link to that section at the tag;
  - how to verify and consume the assets: anonymous download, `sha256sum -c SHA256SUMS`, and recording
    PROVENANCE.txt's commit and tag;
  - the PingFederate line, from build/pf-version.env at --source-ref (or the working tree);
  - the demo-only simulator warning when SHA256SUMS lists demo-only-ciba-sim.jar;
  - for a mirrored release (--mirrored), when and how it was mirrored, that its PROVENANCE.txt's `run:` line
    names a workflow run in the private source repository, and one line per --omit'd asset.

--tree is the exported public tree (tools/export-public.py's output): its docs/releases/VERSION.md is the page
as the public repository has it, with links into what stays private already de-linked. --sums is the
release's SHA256SUMS. The body goes to stdout, or to -o FILE. Exit status: 0 written, 1 when the body would
pass GitHub's limit or the page is missing, 2 on a usage error.
"""
import argparse
import datetime
import os
import posixpath
import re
import subprocess
import sys

PUBLIC_SLUG = "ID-Partners/pf-agentic-identity"
PUBLIC_URL = f"https://github.com/{PUBLIC_SLUG}"
# GitHub's limit on a release body (U-0465).
BODY_LIMIT = 125_000
SIMULATOR = "demo-only-ciba-sim.jar"
# Why an asset of an original release is left out of its mirror; --omit ASSET=REASON names another.
OMIT_REASONS = {
    "pf.plugins.ciba-sim.jar": "the 0.3.0 CIBA simulator runs on `OIDF_CIBA_SIM_ENABLED` alone",
}

LINK = re.compile(r"(\]\()([^)\s]+)(\))")
ITEM = re.compile(r"^(\d+)\.\s+(.*)$")
CODE_SPAN = re.compile(r"`[^`]*`")


class BodyError(Exception):
    pass


def split_page(text):
    """The page's text before its first `##` heading (its `#` title dropped), and the "Before you deploy"
    section's lines (None when the page has none)."""
    lines = text.splitlines()
    opening, section, where = [], None, "opening"
    for line in lines:
        if line.startswith("## "):
            if line.strip() == "## Before you deploy":
                where, section = "deploy", []
            else:
                where = "after"
            continue
        if where == "opening":
            if line.startswith("# ") and not any(x.strip() for x in opening):
                continue
            opening.append(line)
        elif where == "deploy":
            section.append(line)
    return "\n".join(opening).strip("\n"), section


def bold_titles(section):
    """The bold title each numbered item opens with, joined across the lines it is wrapped over."""
    items, current = [], None
    for line in section:
        m = ITEM.match(line)
        if m:
            current = [m.group(2).strip()]
            items.append(current)
        elif current is not None and line.startswith((" ", "\t")) and line.strip():
            current.append(line.strip())
        elif current is not None and not line.strip():
            continue
        else:
            current = None
    titles = []
    for parts in items:
        text = " ".join(parts)
        if not text.startswith("**"):
            raise BodyError(f"a \"Before you deploy\" item does not open with a bold title: {text[:80]!r}")
        end = text.find("**", 2)
        if end < 0:
            raise BodyError(f"a \"Before you deploy\" item's bold title is not closed: {text[:80]!r}")
        titles.append(text[2:end].strip())
    return titles


def absolute_links(text, version, page_dir="docs/releases"):
    """Relative Markdown links made absolute at the tag, so they resolve on the release page."""
    def fix(m):
        target = m.group(2)
        if re.match(r"^[a-z][a-z0-9+.-]*:", target, re.I):
            return m.group(0)
        if target.startswith("#"):
            return f"{m.group(1)}{PUBLIC_URL}/blob/v{version}/{page_dir}/{version}.md{target}{m.group(3)}"
        path, _, anchor = target.partition("#")
        resolved = posixpath.normpath(posixpath.join(page_dir, path))
        if resolved.startswith("../") or resolved == "..":
            raise BodyError(f"the link {target!r} leaves the repository")
        kind = "tree" if path.endswith("/") else "blob"
        url = f"{PUBLIC_URL}/{kind}/v{version}/{resolved}{'/' if path.endswith('/') and resolved != '.' else ''}"
        return f"{m.group(1)}{url}{'#' + anchor if anchor else ''}{m.group(3)}"
    out = []
    in_fence = False
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append(line)
            continue
        if in_fence:
            out.append(line)
            continue
        # Leave code spans as they are: a `](x)` inside backticks is not a link.
        pieces, last = [], 0
        for c in CODE_SPAN.finditer(line):
            pieces.append(LINK.sub(fix, line[last:c.start()]))
            pieces.append(c.group(0))
            last = c.end()
        pieces.append(LINK.sub(fix, line[last:]))
        out.append("".join(pieces))
    return "\n".join(out)


def read_sums(path):
    names = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            m = re.match(r"^[0-9a-f]{64} [ *](.+)$", line)
            if not m:
                raise BodyError(f"{path}: not a sha256sum line: {line[:80]!r}")
            names.append(m.group(1))
    return names


def pf_env(root, ref):
    if ref:
        try:
            data = subprocess.run(["git", "-C", root, "show", f"{ref}:build/pf-version.env"], check=True,
                                  capture_output=True, text=True).stdout
        except subprocess.CalledProcessError as e:
            raise BodyError(f"cannot read build/pf-version.env at {ref}: {e.stderr.strip()}")
    else:
        path = os.path.join(root, "build", "pf-version.env")
        try:
            with open(path, encoding="utf-8") as f:
                data = f.read()
        except OSError as e:
            raise BodyError(f"cannot read {path}: {e.strerror}")
    values = {}
    for line in data.splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        values[k.strip()] = v.strip()
    if not values.get("PF_VERSION"):
        raise BodyError("build/pf-version.env names no PF_VERSION")
    return values


def parse_omits(omits, sums):
    out = []
    for o in omits:
        asset, _, reason = o.partition("=")
        reason = reason.strip() or OMIT_REASONS.get(asset)
        if not reason:
            raise BodyError(f"--omit {asset}: no reason recorded for it; write --omit {asset}=<reason>")
        if sums is not None and asset not in sums:
            raise BodyError(f"--omit {asset}: SHA256SUMS does not list it")
        out.append((asset, reason))
    return out


BLOCK_START = re.compile(r"^\s*([-*+]\s|\d+[.)]\s|#|\||>|```|~~~)")


def unwrap(text):
    """Joins the hard-wrapped lines of each paragraph and list item, since GitHub renders a newline in a
    release body as a line break. Fenced code, headings, tables and quotes are left as they are."""
    out, fenced = [], False
    for line in text.split("\n"):
        if line.lstrip().startswith(("```", "~~~")):
            fenced = not fenced
            out.append(line)
            continue
        if fenced or not out or not line.strip() or not out[-1].strip() or BLOCK_START.match(line) \
                or out[-1].lstrip().startswith(("#", "|", "```", "~~~")) or out[-1].endswith("  "):
            out.append(line)
            continue
        out[-1] = out[-1].rstrip() + " " + line.strip()
    return "\n".join(out)


def body(version, page, pf, sums=None, mirrored=False, date=None, omits=(), image_from_source=False):
    opening, section = split_page(page)
    page_url = f"{PUBLIC_URL}/blob/v{version}/docs/releases/{version}.md"
    download = f"{PUBLIC_URL}/releases/download/v{version}"
    out = [unwrap(absolute_links(opening, version)), ""]

    out.append("## Before you deploy")
    out.append("")
    if section is None:
        out.append(f"The [release page]({page_url}) has no \"Before you deploy\" section.")
    else:
        titles = bold_titles(section)
        if titles:
            out.append(f"The release page lists {len(titles)} item{'s' if len(titles) != 1 else ''} to do or check "
                       f"before you deploy. Their titles are below; each says why, how to tell and what to "
                       f"change in [Before you deploy]({page_url}#before-you-deploy).")
            out.append("")
            out.extend(f"- {absolute_links(t, version)}" for t in titles)
        else:
            out.append(f"Nothing: [Before you deploy]({page_url}#before-you-deploy) on the release page says so.")
    out.append("")

    out.append("## Verify and consume")
    out.append("")
    out.append("Download the assets anonymously, check every file against `SHA256SUMS` before you use it, and "
               "record the commit and tag `PROVENANCE.txt` names:")
    out.append("")
    out.append("```sh")
    out.append(f"curl -fsSLO {download}/SHA256SUMS")
    out.append(f"curl -fsSLO {download}/PROVENANCE.txt")
    out.append(f"curl -fsSLO {download}/<asset>")
    out.append("sha256sum -c --ignore-missing SHA256SUMS      # macOS: shasum -a 256 -c --ignore-missing SHA256SUMS")
    out.append("grep -E '^(commit|tag):' PROVENANCE.txt >> VENDORED.txt")
    out.append("```")
    out.append("")
    out.append(f"or all of them with `gh release download v{version} -R {PUBLIC_SLUG}` and "
               "`sha256sum -c SHA256SUMS`. Do not copy jars from a checkout or another deployment without "
               "recording which release they came from.")
    out.append("")
    image = pf.get("PF_IMAGE")
    digest = pf.get("PF_IMAGE_DIGEST")
    pinned = f" (`{image}@{digest}`)" if image and digest else (f" (`{image}`)" if image else "")
    line = ".".join(pf["PF_VERSION"].split(".")[:2])
    out.append(f"PingFederate: built and link-checked against PingFederate {pf['PF_VERSION']}{pinned}, a "
               f"`jakarta.servlet` build for the PingFederate {line}.x line.")
    if sums is not None and SIMULATOR in sums:
        out.append("")
        out.append(f"**`{SIMULATOR}` is not a deployable.** It is the conformance rig's CIBA simulator, which only "
                   "the conformance profile stages; it refuses every request outside "
                   "`OIDF_DEPLOYMENT_PROFILE=development`. Never put it in a production deploy directory.")
    if image_from_source:
        out.append("")
        out.append("`image/` and `demo/` at this tag are the release's files as they were tagged: they build from "
                   "the private source repository, not from these assets. From v0.7.0 the image and the demo run "
                   "from this repository alone.")
    if mirrored:
        out.append("")
        out.append("## Mirrored")
        out.append("")
        out.append(f"Mirrored on {date} from the original release; every {'mirrored ' if omits else ''}asset is "
                   "byte for byte the original and "
                   "`SHA256SUMS` is unchanged. The `run:` line of its `PROVENANCE.txt` names a workflow run in the "
                   "private source repository, which is not public; record the `commit:` and `tag:` lines.")
        for asset, reason in omits:
            out.append(f"- `{asset}` is not mirrored: {reason}; verify with `sha256sum -c --ignore-missing`.")
    out.append("")
    out.append(f"The full notes: [docs/releases/{version}.md]({page_url}).")
    text = "\n".join(out).rstrip("\n") + "\n"
    if len(text) > BODY_LIMIT:
        raise BodyError(f"the body is {len(text)} characters, over GitHub's {BODY_LIMIT} (U-0465)")
    return text


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("version", help="the release version, 0.7.0 (a leading v is dropped)")
    ap.add_argument("--tree", required=True, help="the exported public tree (tools/export-public.py's output)")
    ap.add_argument("--source-ref", metavar="REF", help="read build/pf-version.env at this ref (default: the "
                    "working tree)")
    ap.add_argument("--sums", metavar="FILE", help="the release's SHA256SUMS")
    ap.add_argument("--mirrored", action="store_true", help="a mirror of a release first published internally")
    ap.add_argument("--date", help="the mirror's date, YYYY-MM-DD (default: today, UTC)")
    ap.add_argument("--omit", action="append", default=[], metavar="ASSET[=REASON]",
                    help="an asset of the original release the mirror leaves out (with --mirrored)")
    ap.add_argument("-o", "--output", metavar="FILE", help="write the body here instead of stdout")
    ap.add_argument("--root", default=os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")),
                    help="the repository root (default: the parent of tools/)")
    args = ap.parse_args(argv)
    version = args.version[1:] if args.version.startswith("v") else args.version
    if not re.match(r"^\d+\.\d+\.\d+$", version):
        print(f"error: {args.version!r} is not a release version (0.7.0)", file=sys.stderr)
        return 2
    if args.omit and not args.mirrored:
        print("error: --omit is for a mirrored release (--mirrored)", file=sys.stderr)
        return 2
    date = args.date or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", date):
        print(f"error: --date {date!r} is not YYYY-MM-DD", file=sys.stderr)
        return 2
    page_path = os.path.join(args.tree, "docs", "releases", f"{version}.md")
    try:
        try:
            with open(page_path, encoding="utf-8") as f:
                page = f.read()
        except OSError as e:
            raise BodyError(f"the release page {page_path}: {e.strerror}")
        sums = read_sums(args.sums) if args.sums else None
        omits = parse_omits(args.omit, sums)
        pf = pf_env(args.root, args.source_ref)
        image_from_source = (os.path.isdir(os.path.join(args.tree, "demo"))
                             and not os.path.isfile(os.path.join(args.tree, "image", "stage-from-release.sh")))
        text = body(version, page, pf, sums, args.mirrored, date, omits, image_from_source)
    except BodyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"ok: {len(text)} characters (GitHub's limit is {BODY_LIMIT}) written to {args.output}",
              file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
