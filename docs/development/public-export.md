# The public tree

`ID-Partners/pf-agentic-identity` is generated from this repository at each release. It carries what a consumer
uses - the release assets, the documentation an operator needs, the specifications, the image build and the demo -
and none of the source. `tools/export-public.py` builds that tree from an allow-list and checks it; the Build
workflow's `lint` job runs `python3 tools/export-public.py --check` on every pull request, so a change that would
break the public tree fails there rather than at release, and release.yml's publishing job runs the same tool.

## What is exported, and why

Only what a consumer reads or runs. The decisions behind the layout:

- **Consumer-facing only.** The specifications, the architecture documents, `docs/configuration/`,
  `docs/operator/`, `docs/federation/`, the release notes and `CHANGELOG.md`, the gm-api integration guide, the
  PingFederate image build (`image/`) and the demo (`demo/`: the conformance rig, the PingAuthorize authoring
  scripts and the gm-api examples). Findings, developer documentation, the device design notes, source READMEs,
  tests, workflows, the showcase and the microsite stay here.
- **An allow-list, not a deny-list.** A file is exported only when a manifest rule names it, so a new file stays
  private until someone decides otherwise.
- **The data lives in `tools/public-export/`, not `dist/public/`.** release.yml stages assets in `dist/` and
  checksums every file in it; a tracked directory there would break that step.
- **Links into what stays here are de-linked, not failed.** About 300 relative links in exported files point at
  findings, developer documents and source READMEs, and a mirrored tag cannot be edited. The link text stays and
  the link goes. A link to anything the manifest neither exports nor classes `internal` is an error: that is what
  catches a typo or a deleted file.
- **The public layout is `image/` and `demo/`.** The rig scripts find the image directory through
  `conformance/layout.sh`, which knows both layouts.

## The manifest

`tools/public-export/manifest.txt`, one rule per line, `#` for comments:

```
<class> <source-glob> [-> <public-path>] [optional]
```

- `source-glob` is relative to the repository root; `*` matches within one directory, `**` across them,
  `[0-9]` a character class.
- `public-path` is where it lands. One ending in `/` is a directory the rest of the glob is laid out under
  (`services/gm-api/docs/*.md -> docs/gm-api/`); without one the file keeps its source path.
- `optional` lets a rule match nothing, for a file another pull request is adding. Without it, a rule that matches
  no tracked file is a manifest error on HEAD. Remove the marker once the file has landed.
- Rules are read in order and the first match wins, so an exclusion goes above the glob it narrows
  (`internal conformance/fail-soft-matrix.sh` above `demo conformance/** -> demo/`).

The classes:

| Class | Exported | Meaning |
|---|---|---|
| `root` | yes | top-level files: `LICENSE`, `NOTICE`, `CHANGELOG.md` |
| `docs` | yes | documentation, under `docs/` |
| `image` | yes | the PingFederate image build, under `image/` |
| `demo` | yes | the rig and examples, under `demo/` |
| `internal` | no | stays here; a link into it keeps its text and loses the link |
| `refuse` | never | `showcase/**`, `build/microsite/**`, `**/src/**`, `**/*.java`, `**/pom.xml`, `.github/**`; a rule of another class whose source matches one is a manifest error, and a file a broader rule above would export fails the no-source guard |

`--docs-only` writes only `root` and `docs`, for a release that keeps the public repository's `image/` and `demo/`
until a release's jars catch up with them: links into those directories are rewritten as the full export lays
them out, and the overlay keeps its image and demo sections. `--docs-alone` writes the same files for a public
tree that has no `image/` or `demo/` (the v0.3.0 to v0.5.0 mirrors): links into them are de-linked and the
overlay's image and demo section goes.

The overlay, `tools/public-export/overlay/`, holds files that exist only publicly: `README.md`, `SECURITY.md` and
`.gitignore`. Only tracked files there are exported. They are templated: `{{VERSION}}`, `{{TAG}}` and
`{{PF_VERSION}}` (from the ref's `build/pf-version.env`), and three conditional sections:

- `<!-- if:demo -->` ... `<!-- end:demo -->`, kept when `demo/` is exported;
- `<!-- if:staging -->` ... `<!-- end:staging -->`, kept when `image/stage-from-release.sh` is;
- `<!-- unless:staging -->` ... `<!-- end:staging -->`, kept when `demo/` is exported without it (v0.6.0, whose
  image and demo build from the source).

When `image/` is exported and the version is known, the tool also writes `image/release.env`
(`PFAI_RELEASE=<version>` and `PFAI_RELEASE_REPO=ID-Partners/pf-agentic-identity`), which the staging scripts read.

The overlay is written for the public layout, so `tools/doc-lint.py`'s `link` rule skips it; the export checks
its links in the tree they are written for. The other doc-lint rules apply to it as to any document.

## Running it

```sh
python3 tools/export-public.py --check                          # HEAD, every guard, nothing written
python3 tools/export-public.py OUTDIR                           # write HEAD's tree (OUTDIR absent or empty)
python3 tools/export-public.py --version 0.7.0 OUTDIR           # with the overlay's version filled in
python3 tools/export-public.py --source-ref v0.6.0 --check      # a tag's tree
python3 tools/export-public.py --docs-only --version 0.7.0 OUTDIR
python3 tools/export-public.py --source-ref v0.4.0 --docs-alone OUTDIR
```

It reads tracked files only: on HEAD the index's paths with their working-tree content, at `--source-ref` the
ref's tree. An untracked or git-ignored file never reaches the tree. Traversal is sorted, modes are 0644 or 0755
from git's, content is copied byte for byte apart from the link transform, and nothing records a time, so two
runs give the same tree (the summary prints its sha256). Exit status: 0 clean, 1 on a guard failure, 2 on a
usage or manifest error.

## The guards

Each failure names its guard, the file and the line. A hit is fixed at its source, or the target is classified
in the manifest; an exception is never added to the deny list.

**no-source.** A `*.java`, `*.kt` or `*.swift` file, a `pom.xml`, a `src/` path segment, `.github/`,
`showcase/` or `build/microsite/`, by source or public path; a file a `refuse` rule matches, whatever rule above
it matched first; a symbolic link. On HEAD a tracked file whose working-tree copy has turned into a symbolic link
(or the other way round) stops the export with a usage error, so `open()` never follows a link out of the
repository.

```
error: [no-source] docs/guide/Main.java: source code is never exported
error: [no-source] docs/secret/plan.md: matches the refuse rule `docs/secret/**` (manifest.txt:9) and is never exported, although manifest.txt:3: docs docs/** matches it first
```

Fix: narrow the glob that reached it, or put an `internal` rule above it.

**links.** A relative Markdown link (`[text](target)` or a reference definition `[id]: target`, outside fenced
code) is resolved against the source file. If the target is exported, the link is rewritten relative to the
public path of the file it sits in, anchor kept: `services/gm-api/docs/INTEGRATING.md`'s `../examples` becomes
`../../demo/gm-api` under `docs/gm-api/`. If the target is `internal`, the text stays and the link
goes. A relative `href` or `src` in HTML inside a Markdown file goes through the same classes; one that would be
de-linked fails instead, because an HTML element cannot lose its link cleanly, so write it as a Markdown link.
Anything else fails:

```
error: [links] docs/operator/x.md:12: ../gone.md -> docs/gone.md, which does not exist
error: [links] docs/operator/x.md:14: ../../other/x.md -> other/x.md, which the manifest does not classify; export it or class it internal
```

Fix: correct the link, or classify the target.

**urls.** Every exported file, Markdown or not, goes through the rewrite table for
`https://github.com/dphhyland/pf-agentic-identity` and the bare slug, matched without regard to case as GitHub
matches owner and repository names:

| Internal | Public |
|---|---|
| `.../releases/tag/v<x>` and `.../releases/download/v<x>/...`, x at or above 0.3.0 | the same path at `ID-Partners/pf-agentic-identity` |
| the same for an earlier version | de-linked (the text stays) |
| `.../releases`, `.../releases/latest` | the same path at `ID-Partners/pf-agentic-identity` |
| `.../actions/...`, `compare`, `blob`, `tree`, `pull`, `issues`, `commit` | de-linked |
| `gh ... --repo dphhyland/pf-agentic-identity`, `-R dphhyland/pf-agentic-identity` | `ID-Partners/pf-agentic-identity` |
| a link to `dphhyland/idp-agentic-demo` or `dphhyland/grant-evaluation-api` (private, checked 2026-10-01) | de-linked |

`dphhyland/pf-oidf-modules` is public and its links stay. Anything the table does not cover fails on HEAD:

```
error: [urls] build/pingfederate/Dockerfile:120: https://github.com/dphhyland/pf-agentic-identity is not in the rewrite table
```

That is why the image's `org.opencontainers.image.source` label names `https://github.com/ID-Partners/pf-agentic-identity`.
The label key `io.github.dphhyland.pf-agentic-identity.staging-profile` is a name, not a URL, and stays.

**deny.** `tools/public-export/deny.txt`: one regex per line with a `# reason`, case-insensitive, applied to every
exported text file after the transform, overlay included. It starts with a home-directory path
(`/(Users|home)/<name>/`, which leaves SCIM's `/Users/{id}` alone), `railway.internal` and `.up.railway.app`.
Customer names go there when David supplies them (U-0456).

```
error: [deny] docs/gm-api/INTEGRATING.md:273: matches `\.up\.railway\.app` - a Railway host names a running deployment
```

**secrets.** `tools/ci/secrets-scan.py`'s `scan_text` on every text file, imported rather than run: an age
identity, a PEM private key or a private JWK, overlay included.

**binaries.** A binary file passes only as `.png`, `.webp`, `.jpg`, `.jpeg` or `.svg`, and under 5 MB.

## Old tags

`--source-ref <tag>` builds a tag's tree with today's manifest, overlay and deny list. A tag cannot be edited, so
what HEAD refuses is tolerated and listed in the summary instead of failing: a missing manifest path, a link to a
file the tag does not have, an unmapped `dphhyland/pf-agentic-identity` URL or slug (replaced by "the internal
repository"), and a deny-list hit (replaced by `<redacted>`). The no-source, secrets and binaries guards still fail.
On 2026-10-01 v0.3.0, v0.4.0, v0.5.0 and v0.6.0 each pass `--check`; v0.6.0 lists three lines (the Dockerfile's
source label and the gm-api guide's two demo hosts).

## Adding a document to the public set

1. Add a rule to `tools/public-export/manifest.txt` in the right class, above any broader rule that would match it
   first.
2. Run `python3 tools/export-public.py --check`. Fix each link it names: point it at an exported file, or class
   the target `internal` if the text is enough without it.
3. If a document must not be read publicly in full, it is not exported; there is no partial export.
