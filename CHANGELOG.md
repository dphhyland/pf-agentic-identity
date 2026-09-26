# Changelog

Every release of pf-agentic-identity, newest first, in the shape [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
describes: one heading per version with its date, and a few lines on what the version was for. A version is a
tag of this repository (`git tag -l 'v*'`); the dates are the tags' own. Where a version has release notes
under [docs/releases](docs/releases/), the heading links to them. The convention for the version in progress:
it sits under `Unreleased` with the version the poms declare (a `-SNAPSHOT`), and the heading becomes
`[<version>] - <date>` when David tags it.

## [Unreleased] - 0.4.0-SNAPSHOT, the poms' version since 2026-09-27

Phase 1 of the production programme: the review's blockers closed or mitigated, the findings register, CI
hygiene. Nothing has landed yet.

## [0.3.0] - 2026-09-27

The first release for PingFederate 13.1.3, and the release that completes OpenID Federation. Notes:
[docs/releases/0.3.0.md](docs/releases/0.3.0.md); the move from v0.1.5:
[docs/operator/upgrading/0.1.5-to-0.3.0.md](docs/operator/upgrading/0.1.5-to-0.3.0.md).

- **PingFederate 13.1.3 and `jakarta.servlet`** - the 0.2.0 cut-over, folded in: every servlet, filter and war is
  compiled against 13.1.3 and does not load on 13.0.x; the RAR plugin reads `getJakartaRequest()` and no longer
  links on 13.0 (PR #7); `pf-13.0` is frozen at v0.1.5, with no backports; upgrades are supported from 0.3.0
  onward.
- **OpenID Federation 1.0, complete** (PR #5): trust chains checked as the Final text says, against pinned anchor
  keys; automatic registration at the token, authorization and PAR endpoints and explicit registration, every
  registration ending with its chain; the token endpoint fail-closed; Trust Marks verified, required and issued;
  every federation endpoint; a policy engine asked over AuthZEN; decisions logged as events.
- **The rig** - `conformance/up.sh` runs a configured PingFederate 13.1.3 from a clone, and the FAPI 2.0, SSF,
  CAEP, FAPI-CIBA and both OpenID Federation plans have been run against it (results in
  [conformance/README.md](conformance/README.md)).
- **Shared Signals** - streams belong to the receiver that created them; SET expiry is enforced; SCIM
  provisioning takes its own scope; the transmitter emits what the CAEP Interop Profile asks.
- **Attestation** - each client bound to the attesters that may vouch for it; the bridge assertion addressed to
  the issuer alone, as a string; the bank's self-signed agents and their mission (PR #6); App Attest on macOS 27
  (PR #9).
- **Release hygiene** - one PingFederate version in `build/pf-version.env` with the image pinned by digest, one
  project version across the reactor with gm-api in the lockstep, and a release workflow that publishes the
  build it verified, with a dry run (PR #10); the docs describe 13.1.3 (PR #8).

## 0.2.0 - 2026-09-24, never tagged

The modules moved to `jakarta.servlet` and PingFederate 13.1.3 became the base (commit `12626ec`). It was the
working version of `main` until 0.3.0 and was never released; everything it held is in 0.3.0. Plan and evidence:
[docs/pf-13_1-jakarta-migration-plan.md](docs/pf-13_1-jakarta-migration-plan.md).

## [v0.1.5] - 2026-09-24

The last `javax.servlet` release, for PingFederate 13.0.x, on the `pf-13.0` branch: everything up to and
including the FAPI-CIBA rig, built on 13.0.3. Supersedes v0.1.4, which was cut before the CAEP Interop and CIBA
work. A 13.0.x consumer pins here; the branch is frozen from 2026-09-26.

## [v0.1.4] - 2026-09-23

The last release built against `javax.servlet` when it was cut, with the assemble script refusing a war whose
staged jars are compiled against the wrong servlet namespace, the FAPI 2.0 profile filter and the SSF
transmitter conformance work, and SSF stream ownership. `PROVENANCE.txt` began stating which PingFederate line
a build targets.

## [v0.1.3] - 2026-08-30

The agent attestation profile with executable conformance, the coverage pass, and the dormant-defect fixes.

## [v0.1.2] - 2026-08-22

Per-client bridge signing, verified-context claims, and no bundled attester trust - the released artefact stopped
being the vulnerable one.

## [v0.1.1] - 2026-08-22

The first complete published build: the PF module set, wars and plugin jars, with `SHA256SUMS` and
`PROVENANCE.txt` recording the commit, so a consumer can pin a build and tell when it is behind. Carries the
Tier 0/1/2 security work. Supersedes v0.1.0.

## [v0.1.0] - 2026-08-22

The release workflow, so a consumer could tell when it was behind. It published its Maven artefacts and then
failed before creating a release; nothing consumed it.

[Unreleased]: https://github.com/dphhyland/pf-agentic-identity/compare/v0.1.5...main
[v0.1.5]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.5
[v0.1.4]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.4
[v0.1.3]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.3
[v0.1.2]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.2
[v0.1.1]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.1
[v0.1.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.0
