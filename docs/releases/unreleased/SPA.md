# The public tree is generated from an allow-list and checked on every pull request

## Changelog

- `tools/export-public.py` builds the tree `ID-Partners/pf-agentic-identity` receives from an allow-list
  (`tools/public-export/manifest.txt`), rewrites or de-links its links, and fails on source code, a dead link, an
  unmapped internal URL, a deny-list hit, a private key or an unexpected binary.
- The Build workflow's `lint` job runs `python3 tools/export-public.py --check` on every pull request.
- The image's `org.opencontainers.image.source` label names the public repository,
  `https://github.com/ID-Partners/pf-agentic-identity`, and the release-download commands in
  `build/pingfederate/README.md` and `docs/operator/preflight.md` use it.

## Before you deploy

None.

## Notes

What is exported: `LICENSE`, `NOTICE`, `CHANGELOG.md`, the two specifications, the architecture documents,
`docs/configuration/`, `docs/operator/`, `docs/federation/`, the release pages, `docs/assets/` and the gm-api
guides (`docs/`); the PingFederate image build (`image/`); and the conformance rig, the PingAuthorize authoring
scripts and the gm-api examples (`demo/`). Source code, tests, workflows, findings, developer documents, the
showcase and the microsite are not. `docs/development/public-export.md` describes the manifest and the guards:
no-source, links, urls, deny, secrets and binaries.

Links from exported files into what stays private keep their text and lose the link. On 2026-10-01 the check over
HEAD de-links 310 links and rewrites 29 across 134 files; `docs/releases/0.6.0.md` loses 47 links and
`CHANGELOG.md` 29. The mirrored tags v0.3.0, v0.4.0, v0.5.0 and v0.6.0 each pass the check. F-0445 records what a
public reader sees as a result; U-0456 that the deny list names no customer yet.

The image label changes: from 0.7.0 an operator who reads `org.opencontainers.image.source` from the image sees
the public repository rather than the private one. The label `io.github.dphhyland.pf-agentic-identity.staging-profile`
keeps its name.
