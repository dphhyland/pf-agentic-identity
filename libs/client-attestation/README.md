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
- **`AttestationChallengeService` / `AttestationReplayCache` / `EvidenceBindingStore`** — one-time
  challenges, `jti` replay detection, and the binding of instance evidence to the first key that presents
  it. `InMemory*` per node; `RedisAttestationStore` for a cluster (one instance implements all three).
  `AttestationSupport` holds the process-wide singletons so the challenge endpoint, the token-endpoint hook
  and the attester share state even when loaded by different classloaders. Every verdict is three-valued:
  `FIRST_USE | REPLAY | STORE_UNAVAILABLE`, `CONSUMED | UNKNOWN | STORE_UNAVAILABLE`,
  `BOUND | CONFLICT | STORE_UNAVAILABLE`. A store that cannot answer is `STORE_UNAVAILABLE`, which every
  caller turns into 503 `temporarily_unavailable` (RFC 6749 defines the code in §4.1.2.1, for the
  authorization endpoint; answering it with a 503 at the token, challenge and attester endpoints is plan
  item S3a's decision), and never into a replay, an unknown challenge or a conflict - those are findings
  about the client. The boolean views `firstSeen` and
  `consume` remain for callers written against them and throw `StoreUnavailableException` (an
  `IllegalStateException`) for an outage rather than answering `false`.
- **`RedisAttestationStore` / `MiniRedisClient`** — the shared store over a dependency-free RESP client
  (`redis://` and `rediss://`, small bounded pool). Issue is `SET … EX`, consume is `DEL`, first-seen is
  `SET … NX EX`, bind is `SET … NX PX` then `GET` and compare. `rediss://` verifies the server the way a
  browser does - its certificate chains to a trusted CA (the JVM's, or `OIDF_REDIS_CA_FILE`) and names the
  URL's host (the HTTPS endpoint identification algorithm), with the host sent as SNI - and the handshake
  completes before `AUTH` is encoded, so the password never travels before the peer is verified. Under
  the production profile `redis://` is refused. Keys live under a `StoreNamespace`, one per surface:
  `oidf:as:*` (the token endpoint's challenges and proof jtis), `oidf:cas:*` (the attester's proof jtis and
  evidence bindings), `oidf:fed:endpoint:*` (spent client assertions at the federation endpoints) and
  `oidf:admin:dpop:*` (reserved for the operator API, S-8). The layout under each: `:challenge:<value>`,
  `:jti:<client> <jti>`, `:evidence:<sha256>`.
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

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `oidf.redis.url` (system property), then `OIDF_REDIS_URL`, then `REDIS_URL` (env) | unset | Set: challenge, replay and evidence-binding state lives in Redis, cluster-wide, under the namespaces above. Unset: per-node in-memory, which a clustered deployment must not run | Not a `redis://` or `rediss://` URL with a host: first request, every store accessor throws, so the token endpoint answers 500 `server_error` to attested clients and the challenge endpoint and the attester answer 500 - a configuration error, not an outage, so not a 503. `redis://` under the production profile: the same, with a message naming `OIDF_DEPLOYMENT_PROFILE` - the password would cross the network in the clear |
| `OIDF_REDIS_CA_FILE` (`oidf.redis.ca.file`) | unset (the JVM's CAs) | A PEM file of one or more CA certificates to trust for `rediss://`, the shape managed Redis providers publish | Missing, unreadable or holding no certificate: first request, as above, naming the variable |
| `OIDF_DEPLOYMENT_PROFILE` | unset (production) | `development` allows a plaintext `redis://` store; unset, `production` or anything else is production. Read directly from the environment until plan item PR-1 centralises it | Not checked beyond that: a typo is production |
| `challengeCacheMaxEntries`, `challengeTtlSeconds`, `replayCacheMaxEntries` (servlet init-params) | 8192 / 300 / 8192 | Sizing and TTL of the authorization server's stores. With Redis, only the TTL applies | Not an integer: per request, the value is ignored with a warning and the default used |

Everything else is a `ClientAttestationConfig.builder()` call by the host.

**Upgrading from 0.3.0.** Keys were `oidf:challenge:*` and `oidf:jti:*`; nothing reads those prefixes from
0.4.0 on, so they are orphaned until their own TTL expires them - 300 s for a challenge, 360 s for a proof
jti (max-age plus skew), 600 s for a federation client assertion. For that long after the first 0.4.0 node
starts, a proof `jti` spent on a 0.3.0 node is not known to a 0.4.0 node and could be presented to it once
more: replay protection across the two versions is per version during a rolling upgrade. Either drain the
0.3.0 nodes before starting the first 0.4.0 one (nothing to flush; the old keys expire on their own), or
accept the window. Flushing is not needed and `FLUSHDB` would also drop unconsumed challenges. A
production deployment whose URL is `redis://` must move to `rediss://` first, or it will not start
attestation: see `docs/releases/0.4.0.md`.

**The live tests.** `RedisLiveTest` runs the stores against a real Redis and skips, naming the variables,
when `OIDF_TEST_REDIS_URL` is unset. Locally, with the ports of your choice:

```sh
docker run -d --rm --name redis-plain -p 127.0.0.1:56373:6379 redis:7-alpine redis-server --requirepass s3cr3t
# a self-signed CA and a certificate for localhost (openssl req -x509 ... -subj /CN=localhost with subjectAltName=DNS:localhost)
docker run -d --rm --name redis-tls -p 127.0.0.1:56374:6379 -v "$PWD/tls:/tls:ro" redis:7-alpine \
  redis-server --port 0 --tls-port 6379 --tls-cert-file /tls/server.pem --tls-key-file /tls/server.key \
  --tls-ca-cert-file /tls/ca.pem --tls-auth-clients no --requirepass s3cr3t
OIDF_TEST_REDIS_URL=redis://:s3cr3t@127.0.0.1:56373 \
OIDF_TEST_REDIS_TLS_URL=rediss://:s3cr3t@localhost:56374 OIDF_TEST_REDIS_CA_FILE="$PWD/tls/ca.pem" \
mvn -o -pl libs/client-attestation -am verify
```

The TLS URL must name the host the certificate names (`localhost`), because one test connects by address
instead and expects the handshake to fail before `AUTH`. In CI the Redis service is plan item R-CI5; until
it lands these tests skip there, and the fake in-process server covers everything but the handshake.

## Security posture

- `typ` is enforced: `oauth-client-attestation+jwt`, `oauth-client-attestation-pop+jwt`, `dpop+jwt`.
  Asymmetric algorithms only by default (no `none`, no MACs).
- `cnf.jwk` must be public-only; a `client_id` parameter must equal the attestation `sub`; PoP `iss`,
  when present, must equal `sub`.
- Both proof headers at once, or neither, is `invalid_client`. SD-JWT (`~`) presentations are refused —
  that encoding was retired; only plain attestation JWTs are accepted.
- Replay is keyed on `(client_id, jti)` with TTL = max-age + skew. A required-but-missing or unknown
  challenge is `use_attestation_challenge`; an expired attestation is `use_fresh_attestation`.
- Store failures fail closed — availability is never traded for a replayable credential - and are reported
  as what they are: 503 `temporarily_unavailable` at the token endpoint, the challenge endpoint and the
  attester, never as a replay. The automatic-registration filter still takes the boolean view and answers
  500 `server_error` for an outage; the federation endpoints read the verdict and answer 503.

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
