# Release notes

One page per release, named for its version: what it was for, what changed for clients, the federation and
operators, what was verified and when, and the known gaps. Every page has a "Before you deploy" section: the
things a consumer must change, each naming the commit or pull request it came from. That section is written as
the release is built - any pull request that changes what a consumer must do adds its note there - so nobody
assembles it from memory at the end. While a release is in progress, each pull request writes its part as a
fragment under [unreleased/](unreleased/README.md), and `tools/release-notes.py assemble` folds the fragments
into the page when the release is cut.

- [0.3.0.md](0.3.0.md) - the first release for PingFederate 13.1.3, and OpenID Federation complete.
- [0.4.0.md](0.4.0.md) - Phase 1 of the production programme: the blockers closed or mitigated, the guard rails
  up, and one PingFederate node only until 0.7.0.
- [0.5.0.md](0.5.0.md) - Phase 2: foundations - every module on the shared platform libraries, the configuration
  reference generated from the settings catalogues, PostgreSQL only, and the image built and scanned in CI.
- [0.6.0.md](0.6.0.md) - Phase 3: secure by default - the production profile enforced, operator OAuth, components
  that fail soft, attestation policy on the filter path, every high targeted at 0.6.0 closed; with its upgrade guide,
  [0.5.0-to-0.6.0.md](../operator/upgrading/0.5.0-to-0.6.0.md).

[CHANGELOG.md](../../CHANGELOG.md) is the one-paragraph-per-version history and links here; the operator guides
for moving between releases are under [docs/operator/upgrading](../operator/upgrading/).
