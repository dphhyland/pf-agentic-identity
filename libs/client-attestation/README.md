# client-attestation

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from [`dphhyland/client-attestation`](https://github.com/dphhyland/client-attestation) on 2026-07-21; that repo is backports-only and its copy still uses the pre-split `.common` package. See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

AS-side **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)):
the verifier and supporting machinery an Authorization Server uses to authenticate a client that
presents a Client Attestation plus a proof of possession. Package
`com.pingidentity.ps.oidf.clientattestation` (the challenge servlet in its `.servlet` subpackage).
Depends on `oidf-jose`, [`rar-model`](../rar-model/README.md) and the servlet API (provided) - no PingFederate. The issuing side lives in
`servlets/attestation-issuer` and `libs/device-instance`; PingFederate's token-endpoint hook and the
federation-backed key resolver live in `servlets/pf-integration`.
The whole pipeline end to end — plus standards alignment, test coverage and the open gaps — is
[docs/client-attestation-architecture.md](../../docs/client-attestation-architecture.md).

## What's here

- **`ClientAttestationVerifier`** — verifies attestation + proof of possession end to end for
  `attest_jwt_client_auth` in both draft-10 PoP methods: `attestation_pop_jwt` (headers
  `OAuth-Client-Attestation` + `OAuth-Client-Attestation-PoP`) and `dpop_combined`
  (`OAuth-Client-Attestation` + `DPoP`, where the DPoP key must equal the attestation `cnf` key).
  Authenticates first, then checks the request's RFC 9396 `authorization_details` against the attestation's
  ([the token gate](#the-token-gate)). Failures are a `ClientAttestationException` carrying the OAuth error
  code: `invalid_client`, `use_attestation_challenge`, `use_fresh_attestation`,
  `invalid_authorization_details`, `insufficient_disclosure`, `temporarily_unavailable`. Built with
  `new ClientAttestationVerifier(...)`, it checks with this classloader's model set (`AttestationRarModels`);
  `ClientAttestationVerifier.withRarModels(...)` takes the set a component loaded at start-up.
- **`ClientAttestationConfig`** — the verification policy: accepted algorithms per JWT (attestation /
  PoP / DPoP), clock skew (60 s) and max-age windows (300 s), the one PoP audience this server answers to
  (`expectedAudience`: an AS's issuer identifier; it replaced a set of accepted audiences in 0.4.0), the
  DPoP `htm` and `htu` (the endpoint's URL from configuration, never from the `Host` header), whether a
  challenge is mandatory, and `requiredDisclosedClaims` (`workload`, `authorization_details`) this AS
  insists an attestation carry. A PoP whose `aud` is anything but that audience - as a string or as the one
  member of an array - is `invalid_client` (draft-10 §5.1 and §7.2, item 7), and so is DPoP combined mode
  when neither the config nor the caller names the endpoint's URL.
- **`ClientAttestation` / `ClientAttestationResult`** — the parsed attestation (`iss`, `sub` =
  `client_id`, `cnf.jwk`, `authorization_details`, `workload`, `agent_id`) and the authenticated outcome
  (client id, confirmed key, PoP mode, attester, entitled vs granted details, and the fingerprint of the model
  set that checked the request).
- **`DpopProofValidator` / `DpopProof`** (in oidf-jose, `com.pingidentity.ps.oidf.jose.dpop`, since 0.6.0: F-0225) —
  RFC 9449 proof validation, used here for combined mode: `dpop+jwt`,
  self-signature under the `jwk` header, algorithm allowlist, `htm` compared exactly (RFC 9110 §9.1: F-0226),
  `htu`, `iat` freshness, `jti` required. The `htu` is compared after RFC 3986 syntax- and scheme-based normalisation (RFC 9449 §4.3):
  scheme and host in lower case, a default or empty port dropped, percent-encoded unreserved characters
  decoded, dot-segments removed, query and fragment ignored; the user information, the path's case and a
  trailing slash still count, and an `htu` that is not an absolute http or https URI is refused. Given no
  expected URL it skips the `htu` check, so the verifier never calls it without one. Replay and challenge
  binding are the caller's.
- **`AttesterKeyResolver`** — how an attester's signing keys are trusted; must throw, never return
  empty. `StaticAttesterKeyResolver` (pre-registered keys, dev/test only) is here; the production
  `FederationAttesterKeyResolver` (trust-chain resolved) is in `servlets/pf-integration`.
- **`AttestationChallengeService` / `AttestationReplayCache` / `EvidenceBindingStore`** — one-time
  challenges, `jti` replay detection, and the binding of instance evidence to the first key that presents
  it. `InMemory*` per node; `RedisAttestationStore` for a cluster (one instance implements all three).
  `AttestationSupport` holds the process-wide singletons so the challenge endpoint, the token-endpoint hook
  and the attester share state even when loaded by different classloaders. Every verdict is three-valued:
  `FIRST_USE | REPLAY | STORE_UNAVAILABLE` (and `STALE` for a replay retention already past, which the store
  answers without being asked), `CONSUMED | UNKNOWN | STORE_UNAVAILABLE`,
  `BOUND | CONFLICT | STORE_UNAVAILABLE`, where `bind` returns a `Result` that also names, on a conflict,
  the key and client that hold the binding. A store that cannot answer is `STORE_UNAVAILABLE`, never a
  replay, an unknown challenge or a conflict - those are findings about the client. The token-endpoint
  filter, the challenge endpoint, the attester and the federation endpoints answer it with 503
  `temporarily_unavailable` (RFC 6749 defines the code in §4.1.2.1, for the authorization endpoint; the
  503 at the token, challenge and attester endpoints is plan item S3a's decision, and OpenID Federation 1.0
  §8.9 defines it for the federation endpoints). Two callers do not: an OGNL issuance criterion built on
  `ClientAttestationUtils` fails, as it does for any refusal, and the automatic-registration filter answers
  500 `server_error`. The boolean views `firstSeen` and `consume` remain for callers written against them
  and throw `StoreUnavailableException` (an `IllegalStateException`) for an outage rather than answering
  `false`.
- **`RedisAttestationStore`** — the shared store over libs/platform's dependency-free Redis client
  (`platform.redis.RedisClient`, plan item C-2, which is 0.4.0's `MiniRedisClient` moved there with a bounded
  pool, a deadline on every command and Sentinel - [its section](../platform/README.md#redis)). Issue is
  `SET … PX`, consume is `DEL`, first-seen is `SET … NX PX`, bind is `SET … NX PX` then `GET` and compare.
  `rediss://` verifies the server the way a browser does - its certificate chains to a trusted CA (the JVM's,
  or `OIDF_REDIS_CA_FILE`) and names the URL's host (the HTTPS endpoint identification algorithm), with the
  host sent as SNI - and the handshake completes before `AUTH` is encoded, so the password never travels
  before the peer is verified. Under the production profile `redis://` is refused. Keys live under a
  `StoreNamespace`, one per surface, each a `RedisKeyspace` over the one client:
  `oidf:as:*` (the token endpoint's challenges and proof jtis), `oidf:cas:*` (the attester's challenges, proof
  jtis and evidence bindings), `oidf:fed:endpoint:*` (spent client assertions at the federation endpoints) and
  `oidf:admin:dpop:*` (reserved for the operator API, S-8). The layout under each: `:challenge:<value>`,
  `:jti:<client> <jti>`, `:evidence:<digest>`, the digest being the attester's SHA-256 of the evidence's
  JWS Signing Input. The keys are byte for byte the ones 0.4.0 wrote, so a rolling upgrade from 0.4.0 finds
  the challenges and spent proofs the old nodes recorded (`RedisAttestationStoreTest`). No exception message
  quotes a URL's userinfo: the client replaces it with `***`.
- **`AuthorizationDetailsGate`** (package-private) - [the token gate](#the-token-gate): the request's
  `authorization_details` against the attestation's, with the containment model.
- **`AttestationRarModels`** - the model set this classloader enforces, read once from `OIDF_RAR_MODELS_FILE` or
  `OIDF_RAR_MODELS` through `RarModels.fromEnvironment`, its fingerprint logged once; a document that cannot be
  read is refused on every call after.
- **`RarEntitlement`** - the old containment check (five array fields). Unused since 0.4.0 and deprecated for
  removal; it stays only because `plugins/rar-paz-plugin`'s `RarContainmentContractTest` reads this file until
  plan item S1c deletes that test ([F-0100](../../docs/findings/F-0100.yaml)).
- **`ClientAttestationChallengeServlet`** (`…clientattestation.servlet`) — the authorization server's challenge
  endpoint: `POST /federation/attestation-challenge` returns `{"attestation_challenge", "expires_in"}` with
  `Cache-Control: no-store` (ABCA-10 §6.1), issuing into `oidf:as:challenge:*`; advertised as `challenge_endpoint`
  in the Entity Configuration's OP metadata. It and the attester's endpoint (`GET /federation/attestation/challenge`,
  in `attestation-issuer`, issuing into `oidf:cas:challenge:*`) are both `ChallengeEndpointServlet`s: one method
  each, 405 with an `Allow` header for any other (`HEAD` included, so nothing issues a challenge its response
  cannot carry; PingFederate 13.1.3 answers every `OPTIONS` 403 itself, before any servlet sees it), and their
  own cap and settings. Neither store knows the other's challenges, so a challenge from one surface is refused at
  the other (CAS §4.1).
- **`ChallengeRateLimiter`** — per-caller fixed-window cap on the (necessarily unauthenticated) challenge
  endpoint. The endpoint itself can't be resource-exhausted (it only ever writes into a bounded cache);
  the attack this stops is a flood evicting legitimate clients' challenges before they're redeemed, which
  presents as intermittent attestation failures rather than as an outage. Default 60 requests/caller/60s;
  the limiter's own caller map is itself bounded.

## The token gate

CAS §7.1: an authorization server "MUST, when authenticating a client via an attestation containing
`authorization_details`, ensure that any authority granted in issued tokens is a subset of the attestation's
`authorization_details` (same subset semantics as Section 7 rule 1), and MUST reject requests exceeding it with
`invalid_authorization_details` [RFC9396]." `ClientAttestationVerifier.verify` asks `AuthorizationDetailsGate` once
the attestation and its proof have verified:

1. The request's text is read by the model's reader (`RarModels.parseDetails`). Nothing requested - absent, blank,
   `[]` - is not checked, whatever the attestation carries.
2. `_principal_sub` (a BFF's principal) and `_agent_id` (the filter's agent marker) are taken off each detail. The
   model refuses both as `forbidden`, so without this every BFF request would be malformed; the grant does not
   carry them.
3. The attestation's `authorization_details` are read from its verified payload by the same reader - not from
   jose4j's parse, which reads a decimal as a `double` and drops a list entry that is not an object - and held to
   the model. Absent is empty, and nothing is within an empty ceiling.
4. `RarModels.contains(attestation's, request's)`: every field of every detail compared by its type's rule, and a
   field the attestation's details constrain and the request leaves out is not contained. The grant is the
   request's own details, never filled in from the attestation: what passes here is what PingFederate issues.

| Refused because | Error | Description |
|---|---|---|
| not valid JSON, not an array of objects, a value its rule cannot compare, no `type` | `invalid_authorization_details` | `authorization_details is malformed` |
| past a size limit (16 details, depth 8, 256 members, 2048 characters, 64 digits) | `invalid_authorization_details` | `authorization_details exceeds a size limit` |
| a field the type's model does not declare | `invalid_authorization_details` | `authorization_details carries a field its type does not define` |
| a type no model names | `invalid_authorization_details` | `authorization_details names a type this server does not support` |
| not within the attestation's details | `invalid_authorization_details` | `authorization_details exceeds what the client attestation allows` |
| the attestation's own details are ones the model refuses | `invalid_client` | `the client attestation's authorization_details cannot be evaluated by this server` |

RFC 9396 §5 is the first four ("The AS MUST refuse to process any unknown authorization details type or
authorization details not conforming to the respective type definition") and §6 the fifth ("Otherwise, the AS
refuses the request with the error code invalid_authorization_details (similar to invalid_scope)"). The last is
the credential's fault, not the request's. The description is fixed; the exception's cause is the model's own
message, which names the detail and the field and never the value, for the log. The token-endpoint filter answers
`invalid_authorization_details` with 400 (RFC 6749 §5.2); 0.3.0 answered a request outside the attestation's
details 401 `access_denied`. The vector file in `libs/rar-model`'s test-jar runs through this gate as
`AsVectorRunnerTest`, with the three cases it answers differently named there.

## Configuration

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `oidf.redis.url` (system property), then `OIDF_REDIS_URL`, then `REDIS_URL` (env) | unset | Set: challenge, replay and evidence-binding state lives in Redis, cluster-wide, under the namespaces above. Unset: per-node in-memory, which a clustered deployment must not run. Read through libs/platform's `platform-redis` settings catalogue | Not a `redis://` or `rediss://` URL with a host: first request, every store accessor throws, so the token endpoint answers 500 `server_error` to attested clients and the challenge endpoint and the attester answer 500 - a configuration error, not an outage, so not a 503. `redis://` under the production profile: the same, with a message naming `OIDF_DEPLOYMENT_PROFILE` - the password would cross the network in the clear |
| `OIDF_REDIS_CA_FILE` (`oidf.redis.ca.file`) | unset (the JVM's CAs) | A PEM file of one or more CA certificates to trust for `rediss://`, the shape managed Redis providers publish | Missing, unreadable or holding no certificate: first request, as above, naming the variable |
| `OIDF_REDIS_POOL_SIZE`, `OIDF_REDIS_BORROW_TIMEOUT_MS`, `OIDF_REDIS_COMMAND_TIMEOUT_MS`, `OIDF_REDIS_SENTINEL_MASTER`, `OIDF_REDIS_SENTINELS`, `OIDF_REDIS_SENTINEL_PASSWORD` | 8 / 1000 / 3000 / unset | The client's pool, its two deadlines, and finding the master through Redis Sentinel: [libs/platform](../platform/README.md#redis) | A value its catalogue entry refuses: first request, as for the URL, the message starting `a Redis setting is refused` and naming the setting. An exhausted pool or a command past its deadline is an outage, answered as `STORE_UNAVAILABLE` is above |
| `OIDF_DEPLOYMENT_PROFILE` | unset (production) | `development` allows a plaintext `redis://` store, and lets an authorization_details type no model names fall back to the common fields; unset, `production` or anything else is production. Read through libs/platform's `DeploymentProfile` (plan item PR-1): `development` trimmed, in any case; the common-fields fallback is rar-model's and takes exactly `development` (F-0160) | Not checked beyond that: a typo is production |
| `OIDF_RAR_MODELS_FILE`, `OIDF_RAR_MODELS` (env only) | unset (the built-in models) | A models document - a file path, or the document inline; one or the other - adding types, or fields to the built-in ones ([libs/rar-model](../rar-model/README.md#a-models-document)). Read once per classloader by `AttestationRarModels`, which logs the fingerprint. From plan item S1c, the RAR plugin reads the same variables and denies when its fingerprint differs | A document the library refuses, an unreadable file, or both set: every call refuses (`MODEL_INVALID`). The token-endpoint filter doesn't start, the attester's issuance servlet fails from its first request, and the issuance criterion refuses every attested token |
| `challengeCacheMaxEntries`, `challengeTtlSeconds`, `replayCacheMaxEntries` (init-params on `ClientAttestationChallengeServlet`) | 8192 / 300 / 8192 | Sizing and TTL of the authorization server's stores. With Redis, only the TTL applies. The attester's endpoint reads the first two for its own challenges (see [attestation-issuer](../../servlets/attestation-issuer/README.md#configuration)); neither endpoint's settings reach the other's | Not an integer: at init, the value is ignored with a warning and the default used. A TTL that is not positive, or in memory a size that is neither positive nor -1: the endpoint fails to start and the store keeps what it had. With Redis only the TTL is checked; the size is not used |
| `challengeRateLimitPerWindow`, `challengeRateLimitWindowSeconds`, `challengeRateLimitMaxCallers` (init-params on either challenge endpoint) | 60 / 60 / 16384 | The endpoint's per-caller cap: requests per window, the window, and how many callers it counts at once. Each endpoint has its own | Not an integer: ignored with a warning; zero or less: the default |

Everything else is a `ClientAttestationConfig.builder()` call by the host.

**Upgrading from 0.3.0.** Keys were `oidf:challenge:*` and `oidf:jti:*`; nothing reads those prefixes from
0.4.0 on, so they are orphaned until their own TTL expires them - 300 s for a challenge, 360 s for a proof
`jti` (max-age plus skew), up to 660 s for a federation endpoint's client assertion, and as long as its own
`exp` allows, at most 86400 s, for an automatic registration's request object or client assertion. Until
then a credential spent against 0.3.0 is not known to 0.4.0 and could be presented to it once more - after
a stop-the-world upgrade as well as during a rolling one, since 0.4.0 never reads the old keys. During a
rolling upgrade the reverse holds too: a credential spent at a 0.4.0 node is unknown to the 0.3.0 nodes,
which read only the old prefixes, until the last of them stops. Proofs that
carry a required challenge cannot cross: a challenge issued by one version is unknown to the other. To close
the rest, stop every 0.3.0 node and wait out the longest window before starting 0.4.0, or accept it (a
replay needs an intercepted, spent credential). Nothing needs flushing - the old keys expire on their own -
and `FLUSHDB` would also drop 0.4.0's live challenges and spent `jti`s. A
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
instead and expects the handshake to fail before `AUTH`. `tools/ci/start-tls-redis.sh DIR PORT NAME` makes
the CA and the certificate and starts the TLS server, and prints the two TLS variables. In CI, build.yml's
java job runs both halves: a `redis` service for the plain one, and that script's server for the TLS one.
The same variables run libs/platform's own `RedisLiveTest`, which drives the client's commands and Lua
scripts against the real server. The handshake is covered without them: platform's `RedisClientTlsTest`
runs an in-JVM TLS server whose certificate `keytool` makes for the run, names `localhost` and not
`127.0.0.1`, and checks that the client verifies the name, sends it as SNI and sends nothing to an address
the certificate does not carry.

## Security posture

- `typ` is enforced: `oauth-client-attestation+jwt`, `oauth-client-attestation-pop+jwt`, `dpop+jwt`.
  Asymmetric algorithms only by default (no `none`, no MACs).
- `cnf.jwk` must be public-only; a `client_id` parameter must equal the attestation `sub`; PoP `iss`,
  when present, must equal `sub`.
- Both proof headers at once, or neither, is `invalid_client`. SD-JWT (`~`) presentations are refused —
  that encoding was retired; only plain attestation JWTs are accepted.
- Replay is keyed on `(client_id, jti)`, and the `jti` is remembered until the proof can no longer be accepted
  anywhere, not for a fixed time from first use (plan item S4c, F-0036): a PoP or DPoP proof is accepted while
  `now - iat <= max-age + skew`, so its `jti` is kept until `iat + max-age + 2 x skew` (another node's clock may be
  a skew behind), and never for less than max-age + skew from now, the retention before 0.6.0. The stores take
  that absolute time (`AttestationReplayCache.recordUntil`): memory evicts by it, expired entries first when full;
  Redis sets `PX` to the milliseconds left until the end of that second, computed once, because platform's
  `RedisClient` has no `PXAT`. A retention already past answers `STALE` without asking the store, and the proof is
  refused as stale. The relative `record(client, jti, ttlSeconds)` and `firstSeen` remain, deprecated, for the
  callers whose windows are not these proofs' (a request object, a federation endpoint's client assertion, the
  device-enrolment service). A PoP or DPoP max age of 0 or less is refused by the config builder: before 0.6.0 it
  switched the age check off, and the `jti` was then forgotten after the skew alone. A required-but-missing or
  unknown challenge is `use_attestation_challenge`; an expired attestation is `use_fresh_attestation`.
- The attestation's `authorization_details` bound what a token request may ask for, field by field, with the
  model's strict `contains`; a request is never widened by filling it in, and the model never repeats a value in
  what it reports.
- Store failures fail closed - availability is never traded for a replayable credential - and are reported
  as what they are: 503 `temporarily_unavailable` at the token endpoint, the challenge endpoint, the
  attester and the federation endpoints, never as a replay. The automatic-registration filter still takes
  the boolean view and answers 500 `server_error` for an outage, and an OGNL criterion built on
  `ClientAttestationUtils` fails.

## Build

```sh
mvn -pl libs/client-attestation -am package     # or `mvn package` at the repo root; tests run with the build
```

Versions come from `bom/pom.xml`; `rar-model` is a compile dependency, JDK only, and ships beside this jar. Consumers, by pom: `servlets/pf-integration`,
`servlets/attestation-issuer`, `services/device-enrolment` (reuses the challenge/replay stores),
`services/demo-rs` (DPoP validation), `services/harness` (attestation issuance/flow harnesses). Ships
into PingFederate via `build/pingfederate/stage-modules.sh` (pf-runtime.war merge) and inside `oidf.war`
(`servlets/oidf-war`). The client/builder side is the separate client-attestation-sdk-polyglot repo,
paired by wire protocol rather than source.
