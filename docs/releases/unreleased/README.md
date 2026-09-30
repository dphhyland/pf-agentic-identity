# Release-note fragments

A pull request that changes what a consumer must do, or that a release's notes should describe, adds one file
here: `<ID>.md`, named for its package in capitals (`S1B.md`, `HYG.md`). When a release is cut,
`python3 tools/release-notes.py assemble <version>` folds every fragment into
`docs/releases/<version>.md` and `CHANGELOG.md` and deletes it. The Docs workflow runs
`python3 tools/release-notes.py check` on every pull request.

A fragment has four headings, in this order:

```markdown
# <title of the package, as its section on the release page will read>

## Changelog

- One or more bullets for CHANGELOG.md's Unreleased section.

## Before you deploy

1. **A bold title that says what to do.** Why, how to tell, what to change.
2. **Another.** ...

## Notes

What changed, how it was verified and when, and the residual risk.
```

The rules `check` enforces:

- The four headings, and no other `#` or `##` heading.
- "Before you deploy" is a numbered list from 1, every item opening with a bold title; lines that continue an
  item are indented into it. A package with nothing for a consumer to do writes `None.` there instead.
- No reference to an item by its number, anywhere in the fragment: the fold numbers a fragment's items on from
  the release page's last, so "item 2" would point at someone else's. Name an item by its bold title.

What `assemble` does with each part:

- **Changelog**: the bullets go at the end of CHANGELOG.md's `## [Unreleased]` section, one group per fragment.
- **Before you deploy**: the items go after the release page's own, numbered on from its last. Items already on
  the page are never renumbered.
- **Notes**: a `## Package <ID>: <title>` section before the page's `## Findings closed` section.

Relative links are written relative to this directory, as for any document here; the fold rewrites them for the
page and the changelog. Fragments fold in file-name order. A fragment that says something about the release page
as it stands - a statement there that the package makes untrue - says so in its Notes, and whoever cuts the release
corrects the page and removes that paragraph before folding.
