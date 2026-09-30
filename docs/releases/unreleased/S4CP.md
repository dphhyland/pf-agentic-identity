# Proof acceptance windows: instance-key proofs need iat and exp, spent jtis are kept until the window ends, and the issued TTL is capped

## Changelog

- The attester refuses an instance-key proof without `iat` and `exp`, with `exp` not after `iat`, or with `exp`
  more than 300 s after `iat`, and accepts one only from `iat - 60 s` to `exp + 60 s`: `invalid_instance_proof`,
  with one description that says what to send (CAS §4.3; plan item S4c, finding F-0036). The CAS discovery
  document's `proof_claims_required` lists `iat` and `exp`.
- A spent proof `jti` is remembered until its proof can no longer be accepted, not for a fixed time from first
  use: `exp + 60 s` for an instance-key proof at the attester, `iat + max age + 2 x 60 s` (and never less than
  max age + 60 s from now, the retention before 0.6.0) for a PoP or DPoP proof at the token endpoint. The stores
  take the absolute time through the new `AttestationReplayCache.recordUntil`; memory evicts by it, expired entries
  first when full, and Redis sets `PX` to what is left of it. A retention already past answers the new verdict
  `STALE` without asking the store. The relative `record(client, jti, ttlSeconds)` and `firstSeen` are deprecated.
- `OIDF_ATTESTER_MAX_ISSUED_TTL` (seconds, default 3600, 60 to 64800) caps a client's `attestation_issued_ttl`: above
  it the client is refused in production and clamped with a warning in development; above 64800 s (the AI Agent
  Profile's 18 hours) it is refused in both ([docs/configuration/attestation-issuer.md](../../configuration/attestation-issuer.md)).
- `ClientAttestationConfig.Builder` refuses a PoP or DPoP max age of 0 or less, and has a `clock(Clock)` for tests;
  a combined-mode DPoP proof's age is also held to that clock.

## Before you deploy

1. **CAS instance-key proofs must carry `iat` and `exp`.** From 0.6.0 the attester (`POST /federation/attestation`)
   refuses a proof without both, with `exp` at or before `iat`, or with `exp` more than 300 s after `iat`, and
   refuses one presented before `iat - 60 s` or after `exp + 60 s`. Why: a proof with no `iat` had no end, and once
   the replay store forgot its `jti` after 300 s the same captured proof was accepted again (F-0036); CAS §4.3 lists
   both claims as REQUIRED. What to change: every client that asks the attester for an attestation must add `exp`
   to its instance-key proof, 300 s or less after `iat` (120 s is plenty). Every language of
   client-attestation-sdk-polyglot at 1862a59 (Go `issuance.go`, Python `issuance.py` and `token_source.py`,
   TypeScript `issuance.ts`, Java `AttestationIssuanceClient` and `ClientAttestation`) sends `aud`, `jti` and `iat`
   and no `exp`, so it needs a release before this one is deployed; so do the demo agents that build the proof
   themselves (listed in the Notes). services/harness is fixed here. The iOS client under `clients/ios` signs its key
   proof for the device-enrolment service, not the attester, and already sends `exp` (`iat + 120`). How to tell:
   the attester answers 400 `invalid_instance_proof` with the description "the instance key proof is outside its
   validity window: 'iat' and 'exp' are required, with 'exp' after 'iat' by at most 300 s", and the CAS document's
   `proof_claims_required` now includes `iat` and `exp`. There is no development-profile escape: a replayable proof
   is not a development convenience.
2. **An issued attestation lives at most an hour in production.** From 0.6.0 a client's `attestation_issued_ttl` is
   held to `OIDF_ATTESTER_MAX_ISSUED_TTL`, default 3600 s. Why: the attestation carries the instance's standing
   until it expires, so its lifetime bounds how long a revoked instance keeps a usable credential (CAS §8), and the
   AI Agent Profile §5(1) says "An issued Client Attestation's `exp` SHALL NOT exceed `iat` + 18 hours". What
   to change: a client configured above 3600 s is refused (`invalid_client`, "attestation_issued_ttl is above the
   longest lifetime this attester issues (OIDF_ATTESTER_MAX_ISSUED_TTL)") and the attester skips it with a
   warning, so either lower the client's `attestation_issued_ttl` or raise `OIDF_ATTESTER_MAX_ISSUED_TTL` to a
   value you accept, at most 64800. Above 64800 s a client is refused in every profile. A value of
   `OIDF_ATTESTER_MAX_ISSUED_TTL` that is not a whole number from 60 to 64800 makes every issuance answer 500
   `server_error` naming the variable. How to tell: the attester's log carries the refusal for each client above
   the cap; `docs/configuration/attestation-issuer.md` has the setting. Development-profile escape: with
   `OIDF_DEPLOYMENT_PROFILE=development` a TTL above the cap (and at most 64800) is clamped to the cap with one
   WARN per client and TTL, instead of refusing the client.
3. **A PoP or DPoP max age of 0 or less is refused.** `ClientAttestationConfig.Builder.popMaxAgeSeconds` and
   `dpopMaxAgeSeconds` throw for 0 or less. Why: before 0.6.0 such a value switched the proof's age check off, and
   the replay store then kept the `jti` for the clock skew alone, so the same PoP authenticated again a minute later.
   What to change: a client whose `attestation_pop_max_age` or `attestation_dpop_max_age` extended property is 0 or
   less now fails the attestation check that reads those properties (`ClientAttestationUtils`, the OGNL criterion
   path); set it to a positive number of seconds or remove it (the default is 300). A host building the config
   itself must pass a positive value. How to tell: server.log carries "Attestation-based client authentication
   failed" with "popMaxAgeSeconds must be positive" (or `dpopMaxAgeSeconds`). There is no development-profile
   escape.

## Notes

**The two sections of the CAS draft (read verbatim 2026-09-30, docs/openid-client-attestation-service-1_0.md,
draft 00).** §4.3, Instance Key Proof: "Claims: `aud` (the CAS issuer identifier, REQUIRED), `iat` (REQUIRED),
`exp` (REQUIRED, SHOULD be ≤ 5 minutes after `iat`), `jti` (REQUIRED, unique), `challenge` (REQUIRED when
`challenge_required` is `true`)", and "The CAS MUST verify the signature against the presented `instance_key`,
validate `aud` against its own identifier, enforce `exp` with small clock skew, and reject replayed `jti` values
within the proof validity window." §5.3.1, The Default Claim Set: "`iat` is not listed as required but, when
present, MUST be validated for freshness (Section 4.3); `exp`, when present, MUST be honoured." The code follows
§4.3 and makes its SHOULD a limit. It still meets every MUST of §5.3.1 (`aud` and `jti` required, `iat` validated,
`exp` honoured), so the tests carry `CAS §4.3` and no divergence tag; the draft's own contradiction is left for its
next revision. CAS §4.6 gives the error: "`invalid_instance_proof` - The Instance Key Proof failed (signature,
`aud`, expiry, replay, challenge)."

**Who sends a proof without `exp` (grep, 2026-09-30).** In this repository only services/harness's
`AttestationIssuanceHarness`, now fixed. client-attestation-sdk-polyglot at 1862a59: all six builders named under
**CAS instance-key proofs must carry `iat` and `exp`**. The iOS client (`KeyProof.swift`) proves its key to device-enrolment and sends
`exp = iat + 120`. Outside the three the spec named, the same grep over ~/Source found demo agents that build the
attester's proof themselves without `exp`: pf-agentic-identity-domain-authority's cross-cloud-chain
(`azure/agent_d.py`, `agentcore/agent_b.py`, `agent/app.py`), `aws-bedrock-demo/agentcore/agent.py`,
`gke-spiffe-demo/agent-engine/agent.py` and `gke-spiffe-demo/railway-workload/app.py`, and pf-oidf-modules'
`demo/spiffe-bootstrap/workload/bootstrap.py`. Clients outside this machine are not known (U-0315).

**Retention.** `AttestationReplayCache.recordUntil(client, jti, retainUntilEpochSeconds)` is the new primitive; the
name differs from `record` because Java cannot overload two `long` parameters by meaning, and the relative form stays
(deprecated) for the three callers outside this package whose windows are not these proofs': pf-integration's
request objects and federation endpoint assertions, which already derive their windows from `exp`, and
device-enrolment, which does not (F-0305). A `jti` is remembered through the whole of its last second. Redis:
platform's `RedisClient` has no `PXAT`, so the store sends `SET NX PX` with the milliseconds left to the end of that
second, computed once from its clock; a key set late expires late, never early. The verdict `STALE` is new; every
existing caller treats a verdict other than `FIRST_USE` as a refusal, so none needed a change for it. At the token
endpoint the retention is `max(iat + maxAge + 2 x skew, now + maxAge + skew)`: the first term covers a node whose
clock is a skew behind, the second keeps the retention before 0.6.0 as a floor. The in-memory store in production is
ST5A's to refuse through ProfileRefusals (PLAN decision 9); which store is chosen is unchanged. A full in-memory store
still forgets a live entry once it has no expired one to drop (F-0306).

**Upgrading.** The Redis keys (`oidf:as:jti:*`, `oidf:cas:jti:*`) keep their names and values; only their expiry
changes, so nothing needs flushing. During a rolling upgrade a 0.5.0 attester node still accepts a proof without
`exp` and forgets its `jti` after 300 s, so F-0036 stays open on that node until the last one stops; update the
clients first (they can send `exp` to 0.5.0, which ignores it).

**Verified (2026-09-30, at 9ee418c0 on ea2dbf4a).** `mvn verify` of libs/client-attestation and
servlets/attestation-issuer on JDK 20 and JDK 17 (413 and 404 tests, the jacoco METHOD gates met with the new
methods under an S4c anchor), and the same test classes on PingFederate 13.1.3's own JDK 21.0.12 through the JUnit
console in the image (no failures). RedisLiveTest ran against a local redis:7-alpine with `OIDF_TEST_REDIS_URL`
set: the `jti` key's `PTTL` was within the retention second, it was a replay before the retention ended, and a
second after it the store answered `STALE` and Redis had dropped the key. The fake-clock tests cover: a proof
without `iat`, without `exp`, with `exp - iat` of 301, with `exp` before or equal to `iat`, each window edge with
the skew, a replay one second before and one second after the retention on the attester and on the token endpoint
(PoP and DPoP, with a second node a skew behind), the TTL cap in both profiles and the 64800 s ceiling, the cap's
catalogue range, and S3b's rule that the issued TTL never outlives the evidence under a clamped TTL.

**Owner actions (David).** PLAN decisions 1-20 and F-0108 are not yet confirmed; this package builds what the plan
recommends: `exp - iat` at most 300 s (the plan's rule, which turns CAS §4.3's SHOULD into a limit), a default cap
of 3600 s, and a development clamp rather than a refusal. Two choices were taken here: the CAS discovery document
now lists `iat` and `exp` in `proof_claims_required` (advertisement and enforcement must not drift), and a max age of
0 or less is refused by the config builder rather than left as an off switch (**A PoP or DPoP max age of 0 or less is refused**).
