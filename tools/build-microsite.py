#!/usr/bin/env python3
"""Assemble the showcase into a self-contained site that can be hosted away from the repository.

Served from the repository root, the pages reach the code with relative links (`../servlets/...`). Hosted on
its own, there is no repository beside them, so this rewrites every such link to the file on GitHub at one
commit - lines and all, because the pages label each link with the lines behind the statement. The images the
pages use are copied in instead, since a link to a blob page would not render.

    python3 tools/build-microsite.py                 # build/microsite/, pinned to HEAD
    python3 tools/build-microsite.py --ref main      # pin to a branch instead
    python3 tools/build-microsite.py --out /tmp/site

The result is a directory Railway builds with showcase/deploy/Dockerfile: nginx, the three pages, the console
screens and the logo. Nothing here runs at request time.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHOWCASE = ROOT / "showcase"
DEPLOY = SHOWCASE / "deploy"
PAGES = ["index.html", "federation.html", "conformance.html"]
REMOTE = "https://github.com/dphhyland/pf-agentic-identity"
# An image has to be a file the browser can draw, so these are copied rather than linked.
ASSET_RE = re.compile(r'"\.\./(docs/assets/[^"]+)"')
LINK_RE = re.compile(r'"\.\./([^"]+)"')
REPO_CONST_RE = re.compile(r"const REPO = '\.\./';")


def git(*args):
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True, capture_output=True, text=True).stdout.strip()


def anchor_for(lines):
    """#L12-L20 from a data-lines attribute, matching what the page's own src() builds."""
    if not lines:
        return ""
    span = re.match(r"^(\d+)(?:-(\d+))?", lines)
    if not span:
        return ""
    return f"#L{span.group(1)}-L{span.group(2)}" if span.group(2) else f"#L{span.group(1)}"


def rewrite(html, blob_base):
    """Point every repository link at the code host, and every image at its copy beside the page."""
    assets = set()

    def asset(match):
        assets.add(match.group(1))
        return '"assets/' + match.group(1).split("/")[-1] + '"'

    html = ASSET_RE.sub(asset, html)
    # federation.html and conformance.html carry the lines in data-lines; fold them into the href.
    def anchored(match):
        whole, href, lines = match.group(0), match.group(1), match.group(2)
        return whole.replace(f'href="{href}"', f'href="{blob_base}{href[3:]}{anchor_for(lines)}"')

    html = re.sub(r'<a\b[^>]*\bhref="(\.\./[^"]+)"[^>]*\bdata-lines="([^"]+)"[^>]*>', anchored, html)
    html = LINK_RE.sub(lambda m: f'"{blob_base}{m.group(1)}"', html)
    # index.html builds its links in JavaScript from this one constant.
    html = REPO_CONST_RE.sub(f"const REPO = '{blob_base}';", html)
    return html, assets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", default=None, help="commit or branch to pin links to (default: HEAD)")
    ap.add_argument("--out", default=str(ROOT / "build" / "microsite"))
    args = ap.parse_args()

    ref = args.ref or git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain", "--", "showcase", "docs", "conformance")
    if dirty and not args.ref:
        print("warning: uncommitted changes; links will point at a commit that does not carry them:\n" + dirty, file=sys.stderr)
    blob_base = f"{REMOTE}/blob/{ref}/"

    out = Path(args.out)
    site = out / "site"
    if out.exists():
        shutil.rmtree(out)
    (site / "assets").mkdir(parents=True)

    assets = set()
    for name in PAGES:
        html, used = rewrite((SHOWCASE / name).read_text(), blob_base)
        (site / name).write_text(html)
        assets |= used
    for rel in sorted(assets):
        shutil.copy2(ROOT / rel, site / "assets" / Path(rel).name)
    shutil.copytree(SHOWCASE / "screens", site / "screens")
    for f in ("Dockerfile", "nginx.conf", "railway.toml"):
        shutil.copy2(DEPLOY / f, out / f)

    left = sum(len(LINK_RE.findall((site / p).read_text())) for p in PAGES)
    print(f"built {out} from {ref[:12]}: {len(PAGES)} pages, {len(assets)} images, "
          f"{len(list((site / 'screens').iterdir()))} screens, {left} unresolved ../ links")
    return 1 if left else 0


if __name__ == "__main__":
    sys.exit(main())
