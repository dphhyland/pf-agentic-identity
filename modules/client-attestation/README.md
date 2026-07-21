# client-attestation

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly the standalone repo [`dphhyland/client-attestation`](https://github.com/dphhyland/client-attestation) — still live for existing consumers, **backports only**. Absorbed with history 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).


> **📦 Canonical home: [dphhyland/pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity)** — this code now lives (with history) at `modules/client-attestation` in the pf-agentic-identity monorepo. This repo stays live for existing links and consumers but receives **backports only** — please open issues and PRs against the monorepo.


AS-side **OAuth Attestation-Based Client Authentication**
([draft-ietf-oauth-attestation-based-client-auth](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/)):
the verifier and supporting machinery an Authorization Server uses to authenticate a client presenting a
Client Attestation plus a proof of possession. Depends only on
[`oidf-jose`](https://github.com/dphhyland/oidf-jose) and the servlet API — **no PingFederate**.

The client/attester side that *builds* these artifacts is
[`client-attestation-sdk`](https://github.com/dphhyland/client-attestation-sdk), which is round-trip tested
against this verifier.

## What's here

- **`ClientAttestationVerifier`** — verifies the attestation + proof of possession end to end, for both
  `attest_jwt_client_auth` with both draft-10 PoP methods: `attestation_pop_jwt` (dedicated PoP JWT) and `dpop_combined` (DPoP combined mode).
- **`ClientAttestationConfig`** — the verification policy: accepted algorithms, clock skew / freshness
  windows, expected PoP audiences and DPoP `htm`/`htu`, and whether a challenge is required.
- **`DpopProofValidator`** — RFC 9449 proof validation for combined mode.
- **`AttesterKeyResolver`** — how the attester's signing keys are trusted:
  `FederationAttesterKeyResolver` (OpenID Federation trust-chain resolved) for production, or
  `StaticAttesterKeyResolver` (pre-registered keys) for dev/test.
- **`AttestationReplayCache` / `AttestationChallengeService`** — `jti` replay protection and one-time
  challenges.
- **`RarEntitlement`** — RFC 9396 `authorization_details` containment: authorize requested access against
  the entitlement the attestation asserts.
- **SD-JWT attestation** — accepts `oauth-client-attestation+sd-jwt` presentations (selective disclosure +
  key binding), with AS-declared required-disclosure enforcement.

## Install

```xml
<dependency>
  <groupId>com.pingidentity.ps.oidf</groupId>
  <artifactId>client-attestation</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Build

```bash
mvn -o clean install     # offline; requires oidf-jose 0.1.0 in ~/.m2
```
