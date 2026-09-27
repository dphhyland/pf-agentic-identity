# Separate challenges for the authorization server and the attester

## Changelog

- Plan item S4b closes F-0037: the attester gets its own challenge endpoint, `GET /federation/attestation/challenge`,
  issuing into `oidf:cas:challenge:*`; the authorization server keeps `POST /federation/attestation-challenge` in
  `oidf:as:challenge:*`; a challenge from either is refused at the other, and each surface's metadata names only
  its own endpoint. New in the register: F-0115, F-0116, F-0117, F-0118 and U-0125.

## Before you deploy

1. **An attester client fetches its challenge from the attester's own endpoint.** A client that put a challenge
   from `POST /federation/attestation-challenge` into its instance-key proof must fetch it with
   `GET /federation/attestation/challenge` instead - the URL `/.well-known/client-attestation-service` and
   `/.well-known/client-attester` now give as `challenge_endpoint`. Until it moves, `/federation/attestation`
   answers 401 `{"error":"invalid_instance_proof","error_description":"challenge is unknown, expired, or already
   used"}`. The refused challenge is not spent: it stays good at the token endpoint for its 300 s. A client that
   follows `challenge_endpoint` but still `POST`s gets 405 with `Allow: GET` and
   `{"error":"invalid_request","error_description":"this challenge endpoint takes GET, not POST"}`. Proofs without
   a challenge are unaffected while `challengeRequired` is `false`, the default. Move clients once every node runs
   this release: a 0.3.0 node has no `GET /federation/attestation/challenge` (404), and its attester reads only
   `oidf:challenge:*`. Both documents are publicly cacheable - `/.well-known/client-attestation-service` for an
   hour, `/.well-known/client-attester` for five minutes - so a client or proxy holding a copy from before the
   upgrade names the old path until the copy expires; a client that reads `challenge_endpoint` should fetch the
   documents again after the upgrade, and one that keeps its copy in memory has to be restarted. Nothing in this
   repository fetches the attester's challenge; `AttestationFlowHarness` and the idp-agentic-demo bridge fetch the
   authorization server's, for the PoP at the token endpoint, and are right as they are. The clients that fetch
   the attester's are in other repositories: see **The client SDK and domain-authority's agents lose the
   attester's challenge until they change**.
2. **The client SDK and domain-authority's agents lose the attester's challenge until they change.**
   client-attestation-sdk-polyglot's `ClientAttestation` (Python, Go, TypeScript and Java alike; read on
   2026-09-27) takes `challenge_endpoint` from `/.well-known/client-attester`, `POST`s to it, goes on without a
   challenge after any error, and keeps the document for the life of the object. pf-agentic-identity-domain-authority
   uses that SDK in its demo workloads and its agent-runtime gateway, and its hand-written agents (aws-bedrock-demo,
   cross-cloud-chain, gke-spiffe-demo) and its AKS and EKS lab capture adapters `POST` to the same member; the GKE
   adapter labels its challenge step with the old path. After the upgrade:
   - A client with the new document gets 405, and mints with no challenge. The mint succeeds while the attester's
     `challengeRequired` is `false`, the default, so the proof loses its freshness without a sign. Where it is
     `true`, every mint answers 401 `invalid_instance_proof`, "a server-issued challenge is required".
   - An SDK object made before the upgrade still `POST`s to `/federation/attestation-challenge` and puts the
     authorization server's challenge in its proof. Every mint then answers 401 `invalid_instance_proof`,
     "challenge is unknown, expired, or already used", until the object is made again: its copy of the document
     is not an HTTP cache and does not expire. The agent-runtime gateway holds one such object for the life of
     the process.
   - Once the SDK `GET`s the attester's challenge, its default of putting the same value in the token-endpoint
     PoP or DPoP `nonce` (always in Go, TypeScript and Java; in Python unless `challenge_at_token=False`) answers
     400 `use_attestation_challenge`. It did before this release as well, because the attester had spent the
     value; now the value is also from the wrong namespace.

   What to change: `GET` the attester's `challenge_endpoint` for the instance-key proof, and for the PoP either
   `POST` to `/federation/attestation-challenge` for a second challenge, which the Entity Configuration's
   `openid_provider` metadata names, or send none. Restart long-running workloads once every node runs this
   release. Leave the attester's `challengeRequired` at `false` until these clients have moved.
   `/.well-known/client-attester` does not name the authorization server's challenge endpoint (F-0118).
3. **The token endpoint refuses the attester's challenges.** A challenge from
   `GET /federation/attestation/challenge` presented in a Client Attestation PoP or a DPoP `nonce` answers 400
   `use_attestation_challenge`; fetch the token endpoint's from `POST /federation/attestation-challenge`, which the
   Entity Configuration's `openid_provider` metadata names. A client that put one challenge in both its proof and
   its PoP was refused before this release too, because the attester had spent it by the time the PoP arrived.
   The SDK does this by default: see **The client SDK and domain-authority's agents lose the attester's challenge
   until they change**.
4. **A wrong method at a challenge endpoint answers JSON with an `Allow` header.** Any method but `POST` at
   `/federation/attestation-challenge`, and any but `GET` at `/federation/attestation/challenge`, is 405 with
   `Allow` naming the one it takes, `Cache-Control: no-store` and a JSON `invalid_request` body, and issues no
   challenge - `HEAD` included. Before, a `GET`, `HEAD`, `PUT` or `DELETE` on the authorization server's endpoint
   fell to the servlet API's defaults, `sendError` with 405 (400 over HTTP/1.0) and no `Allow` (javap of
   jakarta.servlet-api 5.0.0, 2026-09-27). Over HTTP/1.1 only the body and the header change; over HTTP/1.0 the
   status changes too, from 400 to 405. PingFederate answers every `OPTIONS` 403 itself, before either servlet.
5. **Each endpoint's settings reach only its own challenges.** `challengeCacheMaxEntries`, `challengeTtlSeconds` and
   the three `challengeRateLimit*` init-params on `ClientAttestationChallengeServlet` now size only the
   authorization server's challenges and cap only its callers; the same names on
   `AttestationIssuanceChallengeServlet` do the same for the attester's. Before, the one endpoint's TTL and size
   were the attester's too. No shipped descriptor sets any of them, so the defaults (300 s, 8192 entries, 60
   requests a minute per caller) apply to both unless you override `web.xml`; if you did, set the attester's
   servlet as well.
6. **Attester challenges have a key prefix of their own in Redis.** With `OIDF_REDIS_URL` set, the attester's
   challenges are `oidf:cas:challenge:<value>` (300 s TTL), beside `oidf:as:challenge:*`. Anything that counts,
   evicts or alerts on key prefixes should know the new one. Nothing needs flushing.

## Notes

What changed. `ChallengeEndpointServlet` (client-attestation) holds what both endpoints share: the one method it
issues for, the namespace it issues into, its own per-caller cap, and its init-params, which configure only that
namespace (`AttestationSupport.configureChallengeService(StoreNamespace, ...)`; the old overload is the
authorization server's). `ClientAttestationChallengeServlet` is the authorization server's (`StoreNamespace.AS`,
`POST`, and `replayCacheMaxEntries` as before); `AttestationIssuanceChallengeServlet` (attestation-issuer) is the
attester's (`StoreNamespace.CAS`, `GET`). `AttestationIssuanceServlet` consumes from `oidf:cas:challenge:*`. The
CAS document and the attester configuration name the attester's endpoint; the Entity Configuration's
`openid_provider` block names the authorization server's, as before. A setting the store refuses (a TTL that is not
positive) now fails that endpoint's start and leaves the store it had, where before it could leave a zero TTL
behind for every store made after it. The issuance criterion (`ClientAttestationUtils`) learns the OP issuer
through a test seam now, as the token-endpoint filter already did, so a test can drive it; in PingFederate it asks
`OAuthIssuerUtils` as before.

The texts, read on 2026-09-27. ABCA-10 §6.1 (draft-ietf-oauth-attestation-based-client-auth-10 at ietf.org, and -11,
which says the same): a challenge is fetched with an HTTP POST to the `challenge_endpoint` URL, the response carries
`attestation_challenge` and is made uncacheable with `Cache-Control: no-store`, and "If the Authorization Server
offers a challenge endpoint, the Client MUST retrieve a challenge and MUST use this challenge in the Client
Attestation PoP JWT or DPoP Proof". CAS §4.1 (docs/openid-client-attestation-service-1_0.md): `GET
/attestation-challenge`, and "a challenge issued by one party MUST NOT be accepted by the other". The paths are this
deployment's; clients discover them from `challenge_endpoint` (CAS §5.1, ABCA-10 §6.1).

Replay and lifetime, unchanged. A challenge lives 300 s and is spent by its first use, on either surface; in memory
each namespace holds at most 8192. The token endpoint's proof `jti`s are held in `oidf:as:jti:*` for the proof's
maximum age plus the clock skew, 360 s by default; the attester's in `oidf:cas:jti:*` for 300 s. A store that cannot
answer is 503 `temporarily_unavailable` at both endpoints, as PR #31 made it.

Verification. Unit tests on 2026-09-27, JDK 20.0.2 and JDK 17.0.11, every coverage gate met: the refusal in both
directions through the real servlets, leaving the refused challenge unspent (`AttestationIssuanceServletTest`); the
token-endpoint direction through the real `ClientAttestationAuthFilter` and the real issuance criterion, each of
which refuses a challenge from `oidf:cas:challenge:*` with the challenge left unspent and takes one from
`oidf:as:challenge:*` once (`TokenEndpointChallengeSurfaceTest`); the same on the RESP fake
(`RedisAttestationStoreTest`); each method and response (`ChallengeEndpointMethodTest`,
`AttestationIssuanceChallengeServletTest`); each endpoint's settings (`ChallengeEndpointSettingsTest`,
`AttestationSupportTest`); each advertisement against the servlet mapping it names
(`ChallengeEndpointAdvertisementTest`). With the attester pointed back at `oidf:as:challenge:*`, three of the
issuance tests fail; with the filter or the criterion pointed at `oidf:cas:challenge:*`, two of
`TokenEndpointChallengeSurfaceTest`'s fail each. On a booted PingFederate 13.1.3 (`conformance/up.sh` as
`PF_RIG_NAME=pfai-s4b`, the deployed client-attestation and attestation-issuer jars byte-identical to the branch's
build): both endpoints answered their own method 200 and every other 405 with the right `Allow`; `OPTIONS` was 403
from PingFederate; the two attester documents named `/federation/attestation/challenge` and the Entity Configuration
named `/federation/attestation-challenge` only; with Redis, one challenge from each endpoint landed in its own
namespace with a 300 s TTL. PingFederate's own `/.well-known/openid-configuration` and
`/.well-known/oauth-authorization-server` named neither endpoint (F-0115). The client SDK and domain-authority were
read, not run: the symptoms in **The client SDK and domain-authority's agents lose the attester's challenge until
they change** follow from their code on 2026-09-27 and this release's answers.

Residual risk. The cross-surface refusal is proven by unit tests, not on a booted PingFederate: the rig runs
attestation inert (U-0125). Behind a proxy PingFederate does not see through, every caller shares one allowance per
endpoint - 61 requests with 61 `X-Forwarded-For` values were counted as one caller on the rig (F-0116). The
federation's `oauth_client_attester` block names neither of the attester's endpoints (F-0117). A client that
discovers from `/.well-known/client-attester` alone finds no challenge the token endpoint accepts (F-0118), and one
that discovers from PingFederate's own documents finds no challenge endpoint at all (F-0115). Until the SDK changes,
its challenge fetch fails quietly and the attester's proofs carry no challenge. The 0.4.0 notes' Package EVIDENCE
section says the attester consumes challenges from `oidf:as:challenge:*` until S4b; from this package it consumes
`oidf:cas:challenge:*`, and that sentence should go when the fragments are folded in.
