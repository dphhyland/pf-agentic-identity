# Releases are published to ID-Partners/pf-agentic-identity

## Changelog

- `release.yml` publishes every release to the public repository `ID-Partners/pf-agentic-identity` as well as
  here: a `public-preflight` job first proves `PUBLIC_REPO_TOKEN` can push there and that private vulnerability
  reporting is on (a real release with no usable token stops before the internal draft exists), and a
  `publish-public` job, after the release job, commits the public tree `tools/export-public.py` builds as
  `Release <version>`, tags it, creates the public release from the same `dist/` bytes, and downloads every asset
  with no credentials to check it against `SHA256SUMS`. A dry run uploads the tree and the body as artefacts and
  pushes nothing. Nothing on the public side is ever force-pushed; a commit there this workflow did not make is a
  stop.
- A `docs_only` dispatch publishes only the root and docs of `main` or a `v*` tag to the public repository, for
  corrections to released documentation: no build, no tag, no release.
- `tools/public-release-body.py` writes a public release's body: the release page's opening, the "Before you
  deploy" titles linking to the page at its tag, how to verify, the PingFederate line, and the simulator warning,
  within GitHub's release-body limit (U-0465).
- `tools/mirror-releases.sh` mirrors v0.3.0 to v0.6.0 onto the public repository once, by hand, byte for byte,
  with unchanged `SHA256SUMS`; v0.3.0's `pf.plugins.ciba-sim.jar` is not mirrored (F-0120).
- `PROVENANCE.txt`'s `run:` line names the run id, not a URL in this repository.

## Before you deploy

1. **Download releases from `ID-Partners/pf-agentic-identity`.** From 0.7.0 the public repository is where
   releases are published for consumers; 0.3.0 to 0.6.0 are mirrored there with unchanged checksums. A vendor
   script that runs `gh release download -R dphhyland/pf-agentic-identity` changes the slug to
   `ID-Partners/pf-agentic-identity`, or downloads from
   `https://github.com/ID-Partners/pf-agentic-identity/releases/download/v<version>/<asset>`; the assets and
   `SHA256SUMS` are the same bytes. GitHub Packages stays on this repository, for consumers with access.
2. **`PROVENANCE.txt` no longer carries a workflow-run URL.** Its `run:` line is `<run id> (Release workflow of
   the private source repository)`. A script that parsed the URL reads the id instead; the `commit:` and `tag:`
   lines are unchanged and are what to record.

## Notes

`PUBLIC_REPO_TOKEN` is a fine-grained personal access token scoped to the public repository with Contents read
and write (F-0456 records its expiry and rotation). Until it is set, a real release fails at `public-preflight`
with nothing published, by design (the plan's cutover step 2 sets it); a dry run warns and still builds the public
tree. Verified locally on 2026-10-03: `tools/tests/test_public_token_scope.py` holds the token to the two public
jobs against the real workflows, actionlint and shellcheck pass on `release.yml` and `tools/mirror-releases.sh`,
and `tools/mirror-releases.sh --dry-run` is to be run against the four internal releases at cutover step 3 (the
public repository does not exist yet). The release dry run on a throwaway 0.7.0 branch is recorded in the pull
request.
