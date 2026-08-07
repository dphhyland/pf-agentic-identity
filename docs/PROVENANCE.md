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

## The 2026-07-31 reconciliation

The drift rules below were written on 19 July and broke within three days. Between 22 and 24 July,
five commits landed on `pf-oidf-modules@sd-jwt-rar-paz` — two of them **features touching the same
attester classes this repo was independently changing on 24 and 28 July**. Neither side had the
other's work, and both had edited `AttestationIssuanceServlet`, `AttestationIssuanceConfig` and
`AttestationMinter`. It was a merge, not a fast-forward.

Reconciled in this direction, because this repo is canonical:

| Came here | From | Notes |
|---|---|---|
| `InstanceIdentity`, `InstanceAttestationValidator(s)`, `SpiffeInstanceAttestationValidator`, `WalletInstanceAttestationValidator` | `pf-oidf-modules@sd-jwt-rar-paz` `05df5ac` | folded into the evidence-type registry rather than kept as a parallel dispatch axis |
| `FederationWalletProviderKeyResolver` | same branch, `6612272` | landed in `servlets/pf-integration`, beside its `FederationAttesterKeyResolver` sibling |

**Kept from here**, where this repo was ahead: the reverse-mapping `issue()` that takes no
`client_id`, `RemoteJwksCache`, `CimdMapping`'s single `fromProperties` path, `IssuanceClientResolver`
with `pluginId()`, and the `*ClientResolver` names. The fork's `fromEntityMetadata` was **not**
ported — `CimdMapping` already does that job and supports evidence types too.

**Not ported, and deliberately:** the three demo/docs commits (`demo/spiffe-bootstrap`,
`docs/explainers/*.html`) stay with the demos.

The fork tip is preserved as tag **`pre-reconcile-sd-jwt-rar-paz`** (→ `78f676e`), pushed to
`pf-oidf-modules`, so nothing is lost if the merge turns out to have missed something.

## 2026-08-01 — the CAS specification draft

`docs/openid-client-attestation-service-1_0.md` ("OpenID Client Attestation Service for AI Agents 1.0
— draft 00") copied here from `pf-oidf-modules@sd-jwt-rar-paz`, where it existed **uncommitted**
alongside an implementation (`ClientAttestationServiceMetadataServlet` and five modified attester
classes) discovered mid-reconciliation of that fork — non-mine, in-progress work that this document's
move does not resolve. The document has no code dependency and no merge conflict with anything here,
so it moves on its own timeline: onto this repo's canonical `docs/`, off a branch this repo has
already declared non-canonical. **The implementation is not ported by this commit** — it depends on
the fork's `client_id`-taking `AttestationIssuanceServlet.issue()`, which diverges from this repo's
reverse-mapping version, and porting it is a separate three-way merge, not yet attempted. The
pf-oidf-modules working tree is untouched otherwise.

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

## 2026-08-08 — device-instance-identity joins main

Merged in two halves by two concurrent sessions, converging on identical resolutions
(`749f955` + `17c8906` from the domain-authority session, `88ee7c4` bringing in the branch's
`aa46c22` reconciliation). What landed:

- **The Azure leg of the cross-cloud chain**: `AksWorkloadIdentityValidator` +
  `AzureManagedIdentityValidator` instance-attestation validators, the
  `AssertedContext`/`AssertedContextResolver` seam with `EntraDirectoryAssertedContextResolver`,
  and the `deploy/azure-aks-demo` + cross-cloud-chain Azure deploy leg.
- **Trust-chain reconciliation**: main's recursive `extendRoute`/`walkRoute` walk with
  `metadata_policy` application is canonical; the branch's self-signed Entity-Configuration
  verification fast path (kills a live cross-cloud re-fetch per token request) is grafted into the
  verification loop. The gateway adds `iss=` to `federation_fetch_endpoint` URLs (OIDF 1.0 §8.1) —
  the test fixtures were updated to match, not the gateway.
- **FederationService union**: `federationBasePath` endpoint prefixing (war context path in
  advertised `/federation/*` endpoints) AND the hosted-subordinate lookup/list seams, one canonical
  constructor. `OpenIdFederationServlet` passes both and keeps the subordinate prewarm.
- **Backports from pf-oidf-modules** (per drift rule 2, both said so in their commit messages):
  the SD-JWT attestation-encoding drop (`c23f471` — verifier rejects `~` presentations;
  `SdJwt`/`SdJwtException` remain in `oidf-jose` as library primitives) and OIDF §12.1 automatic
  registration (`b312460` — `RegistrationService.automaticRegister`,
  `TokenEndpointAutoRegistrationFilter`, `RegisteredClientsServlet`, previously only in that repo's
  gitignored build tree).

The two sessions resolved the same six files independently and every resolution was semantically
identical (same walk union, same §8.1 fixture fixes, same `CompactJws` overloads — only formatting
and constructor-parameter order differed). Reassuring for the code; another data point for the
"prose rules decay" section below all the same. `device-instance-identity` is level with main as of
`88ee7c4`.

## Written here, not absorbed from anywhere

Everything below is net-new to this repo and has no upstream. Recorded so a future provenance
question has an answer other than silence.

| Path | What it is |
|---|---|
| `libs/app-attest` | Apple App Attest verification (attestation + assertion) to Apple's pinned root |
| `libs/device-instance` | the agent instance registry and the device Client Attestation minter |
| `libs/agent-registry` | mints/resolves the pseudonymous per-instance `agent_id` (random, never derived) |
| `services/device-enrolment` | the agent platform backend — the Client Attester for on-device agents |
| `services/demo-rs` | a resource server validating DPoP sender-constraint and the RFC 8693 `act` chain |
| `plugins/instance-registry-datasource` | a PF `CustomDataSourceDriver` over the instance registry |
| `libs/oidf-jose` → `JwsSigner`, `LocalJwkSigner`, `CompactJws` | `JwsSigner`/`LocalJwkSigner` **moved** here from `servlets/attestation-issuer` (a library cannot depend on a servlet module); `CompactJws` is new |
| `libs/openid-federation` → `MetadataPolicy` | OIDF `metadata_policy` composition and application — did not exist before |
| `libs/openid-federation` → `com.pingidentity.ps.oidf.authority` | the Domain Authority hosted-entity registry, OpenBao signing, and enrolment surface (Phase 1) |

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

### Rule 1 is prose, and prose did not hold

It was written on 19 July and broken by 22 July, by someone reading the same README that says this
repo is canonical. Two hundred lines of duplicated design and a three-way merge later, the lesson is
that a convention nobody's tooling enforces is a convention that decays.

So it is being made mechanical rather than restated more firmly:

- a CI check in `pf-oidf-modules` that fails if `com/**/*.java` reappears there;
- this repo's README naming it as the only home for module code.

Both are tracked as part of retiring the fork. Until the check exists, rule 1 is still only prose.

### A standing hazard while both repos have deploy trees

`pf-oidf-modules` still carries `deploy/{fedhost,lighthouse,pingfederate}` and its own
`deploy-{fedhost,lighthouse,pingfederate}.yml`, already diverged from this repo's — 
`deploy-pingfederate.yml` by 109 lines. **Both repos can therefore deploy to the same Railway
services from different definitions.** Nothing fires accidentally today (path-filtered or
`workflow_dispatch`), but the two keep drifting, and the failure mode is a deploy that silently
undoes the other repo's.
