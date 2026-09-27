# Changelog

Every release of pf-agentic-identity, newest first, in the shape [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
describes: one heading per version with its date, and a few lines on what the version was for. A version is a
tag of this repository (`git tag -l 'v*'`); the dates are the tags' own. Where a version has release notes
under [docs/releases](docs/releases/), the heading links to them. The convention for the version in progress:
it sits under `Unreleased` with the version the poms declare (a `-SNAPSHOT`), and the heading becomes
`[<version>] - <date>` when David tags it.

## [Unreleased] - 0.4.0-SNAPSHOT, the poms' version since 2026-09-27

Phase 1 of the production programme: the review's blockers closed or mitigated, the findings register, CI
hygiene. Notes: [docs/releases/0.4.0.md](docs/releases/0.4.0.md).

- **R-I1 Staging profiles** - `stage-modules.sh --profile production|conformance` (production, the default, leaves
  the CIBA simulator out), a v2 `MANIFEST` naming the profile, a section per module group and a sha256 per jar,
  and an assembler and Dockerfile (`STAGING_PROFILE`, recorded as an image label) that refuse a stage made for
  the other profile.
- **R-I4 Entrypoint hardening** - `umask 077` first; `PF_ARCHIVE_AGE_KEY_FILE` preferred, the inline key piped and
  both variables unset before PingFederate starts; `PF_ARCHIVE_SHA256` checked before the archive is decrypted or
  imported; `PF_ARCHIVE_FILE`, binary or armored age; a plaintext archive refused unless
  `OIDF_DEPLOYMENT_PROFILE=development`; the tmpfs claim corrected; `test-entrypoint.sh`.
- **X-D02 ciba-sim conformance-only** - the decision endpoint (404) and the authenticator (`OOBAuthGeneralException`)
  refuse every request unless `OIDF_CIBA_SIM_ENABLED=true`, `OIDF_DEPLOYMENT_PROFILE=development` and
  `OIDF_CIBA_SIM_DIR` is an existing private directory the plugin owns; the rig sets all three.
- **Information architecture and style** (D-1) - `docs/{operator,configuration,reference,security,development,findings,releases}`
  each with a README saying what belongs there; `SECURITY.md`, `CONTRIBUTING.md` and a pull request template;
  the house style in `docs/development/style-guide.md`, with `tools/doc-lint.py` checking what a machine can
  against a dated baseline, in a new `docs.yml` workflow.
- **Findings register** (D-2) - one YAML file per finding under `docs/findings` (`F-` defects, `U-` unverified
  assumptions), seeded from the 2026-09-26 review, the reviewer reports, the plan's "Found while designing"
  list and `docs/unverified.md`; `tools/findings.py --check` in CI, `--gate` for a release, `list` and `index`
  on demand.
- **CI hygiene** (R-CI1 to R-CI4) - every action pinned to a commit with least-privilege tokens; actionlint,
  zizmor, shellcheck and `terraform validate` in the lint job; the secrets guard's content scan extended to private
  JWKs and every PEM kind, with gitleaks over the whole history beside it; CodeQL for Java, Actions, Python and
  JavaScript; Dependabot; the rig's Terraform lock file committed; CODEOWNERS.

- **Generated files leave git** (plan decision 18; R-CI5's publish step, brought forward from Phase 2):
  `docs/coverage-dashboard.md` and `.html` and the showcase's rendered documents (now `showcase/docs.js`) are
  generated and git-ignored; a CI Build whose reactor build completes publishes them as its `coverage-dashboard`
  and `showcase` artefacts (a run that fails in `mvn verify` publishes neither); `tools/coverage-report.py` is
  strict by default and exits 1 for a build that left a module without its reports; the Build's `java` job runs
  device-instance's Postgres suite against a service container.
- **Redis verified and tri-state** (S3a) - `rediss://` checks the server's certificate and name and
  completes the handshake before `AUTH`, an optional `OIDF_REDIS_CA_FILE`, `redis://` refused under the
  production profile, a URL's userinfo never quoted in a message; store verdicts are
  `FIRST_USE | REPLAY | STORE_UNAVAILABLE` and `CONSUMED | UNKNOWN | STORE_UNAVAILABLE`, an outage answered
  503 `temporarily_unavailable` and never "replay"; keys under `oidf:as:*`, `oidf:cas:*`,
  `oidf:fed:endpoint:*` and `oidf:admin:dpop:*`. The store interfaces' abstract methods are now `record` and
  `consumeChallenge`.
- **Evidence digested and bound** (S3b) - the attestation carries `workload.instance_attestation_sha256`,
  `_type` and `_exp` and never the evidence (`workload.svid` and `workload.instance_attestation` are gone);
  the digest is the SHA-256 of the evidence's JWS Signing Input, so a re-encoded token is the same evidence;
  evidence binds to the first instance key and client that present it, a second presenter is 401
  `instance_attestation_bound` and an `attestation.evidence.conflict` audit event naming both keys; evidence
  lifetime, whole and remaining, capped at a day in production, the attestation's `exp` never past the
  evidence's.
- **CIMD refused outside development** (M-1) - `OIDF_ATTESTER_CIMD_URL` is honoured only under
  `OIDF_DEPLOYMENT_PROFILE=development`; elsewhere the source is left out with an ERROR naming it, and the CAS
  document does not list `cimd` among its metadata sources.

- **RAR containment model** (S1a) - `libs/rar-model`, JDK only: per-type field rules (`set`, `set_of_values`, `limit`
  with a paired unit, `amount`, `instant_limit`, `equal`, `string`, `object`, `forbidden`), alternatives for a thing
  a type can say two ways, the built-in `sales_agent`, `payment_initiation` and `account_information` models, more
  from `OIDF_RAR_MODELS_FILE` / `OIDF_RAR_MODELS`, strict `contains`, `authorize` with inheritance, and the meet
  `intersect`, over lists held to fixed limits (numbers by the digits they would write); a SHA-256 fingerprint of
  the effective model and the library's semantics; 244 vectors in a test-jar and seeded property tests. The
  library only: the authenticator, the issuer and the plugin move onto it in wave 2 (S1b, S1c), and B1 stays open
  until then.

- **S2a, S2b RAR plugin: fail-open and the principal** (blocker B3, F-0003; the "fail-open catches everything"
  high, F-0016) - fail-open is confined to a connection refused or reset, an unresolved name, a deadline, or HTTP
  429/502/503/504, so a 401 from a wrong secret, a body that is not a JSON object, a status line or header the
  client cannot parse (F-0093) and a TLS failure deny; a governance answer's `authorised` must be a boolean;
  "Deny unless PERMIT" is gone and the decision is always deny-unless-PERMIT; the shared secret is an encrypted
  field under the same name (the upgrade from v0.3.0 rehearsed on the rig); the PDP URL must be https and "Skip
  TLS verification" is inert unless `OIDF_DEPLOYMENT_PROFILE=development`; the governance-engine request writes
  the server's attributes last and refuses a field that names one, every `req_`/`att_` mirror included (F-0073);
  `principal_source` is resolved per flow from the user key PingFederate 13.1.3 passes (client credentials
  `client`, refresh and the code flow `authenticated`, CIBA `identity_hint`, token exchange `none` until the
  filter publishes a verified subject, F-0074), and `login_hint` / `_principal_sub` are development-only;
  `payment_initiation` and `account_information` are refused before any PDP call without an authenticated
  principal; the PDP request carries the attester `iss`; logs carry the principal hashed;
  `conformance/verify-rar-principal.sh` drives the flows on the rig.

- **SSF push is no longer starved by paused, disabled or poll backlogs, and no single POST holds it past
  10 s** (S10-0, the B5 stopgap) - the stores select only enabled push streams' SETs; a stream whose delivery
  fails waits out its first SET's backoff as a whole, so the SET that failed goes first and the rest follow
  by `issuedAt`, SETs of the same second by `jti` rather than in the order they were generated (F-0095); the
  POST has deadlines (connect 2 s, exchange 10 s, body read to 4 KiB) and its connection is closed at the
  deadline; the loop starts from the load-on-startup servlet; a store that is down at boot is logged, without
  its `jdbcUrl`, and retried every 30 s instead of failing `pf-runtime.war`; and the stores' push selection
  runs against Postgres in CI (`SsfStoresOnPostgresTest`). An enabled stream with 500 due SETs older than
  another's still fills the batch, and a slow receiver still holds the one thread for up to 10 s a SET, until
  S-10.
- **device-enrolment's unauthenticated `POST /compliance` is gone** (M-2, the B4 mitigation) - compliance
  reaches the registry through a verified SET at PingFederate's SSF receiver and nowhere else; the README
  says why the device path is not production-usable until Phase 6.
- **IOM schema v2 proposed** (X-A03) - [docs/device/iom-schema-v2-proposal.md](docs/device/iom-schema-v2-proposal.md),
  the MAY attributes, view, roles, lease attributes and start-up check the device path needs, written as a
  diff against the model as it is, for David to raise in idp-scim-service.

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

[Unreleased]: https://github.com/dphhyland/pf-agentic-identity/compare/v0.3.0...main
[0.3.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.3.0
[v0.1.5]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.5
[v0.1.4]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.4
[v0.1.3]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.3
[v0.1.2]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.2
[v0.1.1]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.1
[v0.1.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.0
