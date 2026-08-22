# client-attestation

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from [`dphhyland/client-attestation`](https://github.com/dphhyland/client-attestation) on 2026-07-21; that repo is backports-only and its copy still uses the pre-split `.common` package. See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

AS-side **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)):
the verifier and supporting machinery an Authorization Server uses to authenticate a client that
presents a Client Attestation plus a proof of possession. Package
`com.pingidentity.ps.oidf.clientattestation` (the challenge servlet in its `.servlet` subpackage).
Depends on `oidf-jose` and the servlet API (provided) — no PingFederate. The issuing side lives in
`servlets/attestation-issuer` and `libs/device-instance`; PingFederate's token-endpoint hook and the
federation-backed key resolver live in `servlets/pf-integration`.
The whole pipeline end to end — plus standards alignment, test coverage and the open gaps — is
[docs/client-attestation-architecture.md](../../docs/client-attestation-architecture.md).

## What's here

- **`ClientAttestationVerifier`** — verifies attestation + proof of possession end to end for
  `attest_jwt_client_auth` in both draft-10 PoP methods: `attestation_pop_jwt` (headers
  `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`) and `dpop_combined`
  (`OAuth-Client-Attestation` + `DPoP`, where the DPoP key must equal the attestation `cnf` key).
  Authenticates first, then authorises the request's RFC 9396 `authorization_details` against the
  attested entitlement. Failures are a `ClientAttestationException` carrying the draft's OAuth error
  code: `invalid_client`, `use_attestation_challenge`, `use_fresh_attestation`,
  `invalid_authorization_details`, `access_denied`, `insufficient_disclosure`.
- **`ClientAttestationConfig`** — the verification policy: accepted algorithms per JWT (attestation /
  PoP / DPoP), clock skew (60 s) and max-age windows (300 s), expected PoP audiences, DPoP `htm`/`htu`,
  whether a challenge is mandatory, and `requiredDisclosedClaims` (`workload`, `authorization_details`)
  this AS insists an attestation carry.
- **`ClientAttestation` / `ClientAttestationResult`** — the parsed attestation (`iss`, `sub` =
  `client_id`, `cnf.jwk`, `authorization_details`, `workload`, `agent_id`) and the authenticated outcome
  (client id, confirmed key, PoP mode, attester, entitled vs granted details).
- **`DpopProofValidator` / `DpopProof`** — RFC 9449 proof validation for combined mode: `dpop+jwt`,
  self-signature under the `jwk` header, algorithm allowlist, `htm`/`htu`, `iat` freshness, `jti`
  required. Replay and challenge binding are the caller's.
- **`AttesterKeyResolver`** — how an attester's signing keys are trusted; must throw, never return
  empty. `StaticAttesterKeyResolver` (pre-registered keys, dev/test only) is here; the production
  `FederationAttesterKeyResolver` (trust-chain resolved) is in `servlets/pf-integration`.
- **`AttestationChallengeService` / `AttestationReplayCache`** — one-time challenges and `jti` replay
  detection. `InMemory*` per node; `RedisAttestationStore` for a cluster (one instance implements both).
  `AttestationSupport` holds the process-wide singletons so the challenge endpoint and the token-endpoint
  hook share state even when loaded by different classloaders.
- **`RedisAttestationStore` / `MiniRedisClient`** — the shared store over a dependency-free RESP client
  (`redis://` and `rediss://`, small bounded pool). Issue is `SET … EX`, consume is `DEL`, first-seen is
  `SET … NX EX`; unreachable Redis fails closed.
- **`RarEntitlement`** — RFC 9396 containment: each requested detail must sit within an attested detail
  of the same `type`, with the set-valued fields (`actions`, `locations`, `datatypes`, `privileges`,
  `sales_regions`) compared as subsets.
- **`ClientAttestationChallengeServlet`** (`…clientattestation.servlet`) — `POST /federation/attestation-challenge`
  returns `{"attestation_challenge", "expires_in"}` (draft §6.1); advertised as `challenge_endpoint`.
- **`ChallengeRateLimiter`** — per-caller fixed-window cap on the (necessarily unauthenticated) challenge
  endpoint. The endpoint itself can't be resource-exhausted (it only ever writes into a bounded cache);
  the attack this stops is a flood evicting legitimate clients' challenges before they're redeemed, which
  presents as intermittent attestation failures rather than as an outage. Default 60 requests/caller/60s;
  the limiter's own caller map is itself bounded.

## Configuration

| Setting | Read by | Effect |
|---|---|---|
| `oidf.redis.url` (system property), then `OIDF_REDIS_URL`, then `REDIS_URL` (env) | `AttestationSupport` | Set: challenge + replay state lives in Redis, cluster-wide. Unset: per-node in-memory |
| `challengeCacheMaxEntries`, `challengeTtlSeconds`, `replayCacheMaxEntries` (servlet init-params) | `ClientAttestationChallengeServlet` | Sizing/TTL of the stores (defaults 8192 entries / 300 s). With Redis, only the TTL applies |

Everything else is a `ClientAttestationConfig.builder()` call by the host.

## Security posture

- `typ` is enforced: `oauth-client-attestation+jwt`, `oauth-client-attestation-pop+jwt`, `dpop+jwt`.
  Asymmetric algorithms only by default (no `none`, no MACs).
- `cnf.jwk` must be public-only; a `client_id` parameter must equal the attestation `sub`; PoP `iss`,
  when present, must equal `sub`.
- Both proof headers at once, or neither, is `invalid_client`. SD-JWT (`~`) presentations are refused —
  that encoding was retired; only plain attestation JWTs are accepted.
- Replay is keyed on `(client_id, jti)` with TTL = max-age + skew. A required-but-missing or unknown
  challenge is `use_attestation_challenge`; an expired attestation is `use_fresh_attestation`.
- Store failures fail closed — availability is never traded for a replayable credential.

## Build

```sh
mvn -pl libs/client-attestation -am package     # or `mvn package` at the repo root; tests run with the build
```

Versions come from `bom/pom.xml`. Consumers, by pom: `servlets/pf-integration`,
`servlets/attestation-issuer`, `services/device-enrolment` (reuses the challenge/replay stores),
`services/demo-rs` (DPoP validation), `services/harness` (attestation issuance/flow harnesses). Ships
into PingFederate via `build/pingfederate/stage-modules.sh` (pf-runtime.war merge) and inside `oidf.war`
(`servlets/oidf-war`). The client/builder side is the separate client-attestation-sdk-polyglot repo,
paired by wire protocol rather than source.
