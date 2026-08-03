# Provenance — where every path came from

Assembled 2026-07-19 by history-preserving absorption (`git subtree add` for whole repos,
`git filter-repo` path extraction for pieces of the monolith). **This monorepo is canonical.**
The source repos remain live for link-continuity, but changes flow back only as deliberate
backports — never as parallel development.

| Path here | Source | How | Notes |
|---|---|---|---|
| `libs/oidf-jose` | [dphhyland/oidf-jose](https://github.com/dphhyland/oidf-jose) `main` | subtree (full history) | foundation JOSE SDK |
| `libs/client-attestation` | [dphhyland/client-attestation](https://github.com/dphhyland/client-attestation) `main` | subtree (full history) | canonical home of the challenge/replay classes |
| `libs/openid-federation` | [dphhyland/openid-federation](https://github.com/dphhyland/openid-federation) **`draft-10-pop-methods`** | subtree (full history) | absorbed the *ahead* branch (draft-10 metadata), not `main` |
| `servlets/pf-integration` | [dphhyland/pf-integration](https://github.com/dphhyland/pf-integration) `main` | subtree (full history) | pom gained the `pingfederate-sdk` provided dep (it never compiled standalone without it) |
| `plugins/rar-paz-plugin` | local `~/Source/pf-rar-paz-plugin` `main` | subtree (full history) | tracked `target/` pruned; the copy inside pf-oidf-modules was identical at absorb time |
| `servlets/attestation-issuer` | pf-oidf-modules (tracked `com/**` + `src/test`) | filter-repo path extraction | + same-package closure classes and test helpers (`LocalJwkSigner`, `TestJwts`, `FakeBaoServer`) copied at HEAD; 3 challenge/replay classes deduped in favour of client-attestation |
| `servlets/ssf` | pf-oidf-modules (tracked `com/**` + `src/test`) | filter-repo path extraction | Kafka publishing is reflection-based — no compile-time Kafka dep |
| `services/gm-api` | local `~/Source/idp-gm-api` `main` | subtree (full history) | PF servlet (`gm-api.war`) + `/mcp` add-on. The AS-agnostic **Go** Grant-Evaluation service was later extracted to [grant-evaluation-api](https://github.com/dphhyland/grant-evaluation-api); `idp-gm-api` is now a pointer. |
| `deploy/` + `.github/workflows/deploy-*` | pf-oidf-modules | filter-repo path extraction | `deploy-demo.yml` stayed behind (the demo lives in pf-oidf-modules); triggers retargeted: push-to-main → staging, production via workflow_dispatch |

## 2026-08-04 — CAS metadata endpoint + custom-claims enforcement

The implementation flagged as not-yet-ported in the 2026-08-01 CAS-draft entry above, from
`pf-oidf-modules@sd-jwt-rar-paz` `41c7dd1` (a WIP safety-net commit on that non-canonical branch).
It depended on the fork's `client_id`-taking `AttestationIssuanceServlet.issue()`; ported here against
this repo's reverse-mapping version instead (adjusting the enforcement step's numbering and the
default-registry wiring to match, not a straight copy):

- `ClientAttestationServiceMetadataServlet` — new, serves the spec's own
  `GET /.well-known/client-attestation-service` (see `docs/openid-client-attestation-service-1_0.md`
  §5). Deliberately separate from `AttesterConfigurationServlet`'s `/.well-known/client-attester`,
  which is this deployment's own richer discovery surface (resolver plugins, per-client config,
  PoP audience) — the two documents serve different purposes and neither replaces the other.
- `AttestationIssuanceServlet` — enforces `customClaimsRequired` (init-param /
  `OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED`) against the instance-key proof's claims; the same
  configuration drives what the metadata servlet advertises as `custom_claims_required`, so
  advertisement and enforcement cannot drift apart.
- `InstanceKeyProofValidator.Result` — carries the proof's full claim map now, so the servlet can
  read arbitrary custom claims rather than only the fields the record used to name explicitly.

`InstanceAttestationValidators.formats()`, which the fork's WIP commit also added, already existed
here (from the 2026-07-31 reconciliation) with the same purpose — no change needed.

## What deliberately did NOT move

- **The demo UI / harness** (`harness/ui`, agent-workload) — stays in
  [pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules), which lives on as the demo +
  ops repo (its `deploy-demo.yml` keeps deploying `pf-demo-ui`).
- **The CFR-decompiled PF source** — never tracked anywhere, never absorbed.
- **client-attestation-sdk-polyglot** — the *client/builder* side (Java/Python/TS/Go); paired by
  wire protocol, not by source. Stays its own repo.
- **idp-pingfed-ssf-servelet** — a docker-compose *demo* consuming this repo's SSF artifacts.

## Drift rules

1. New work lands **here**. The absorbed repos get no direct commits.
2. If something must go back (e.g. a fix someone needs from `dphhyland/client-attestation`),
   cherry-pick/backport deliberately and say so in the commit message.
3. The same `com.pingidentity.ps.oidf.*` FQCNs exist in the old repos — never mix old artifacts
   with monorepo artifacts on one classpath.
