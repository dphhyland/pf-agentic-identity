# device-enrolment

The **agent platform backend** — the Client Attester for agents running on a user's device.

Not a PingFederate extension. This is a standalone service that PF *trusts*: it runs the binding
ceremony, owns the instance registry, and mints the Client Attestations an on-device agent presents at
PF's token endpoint via `attest_jwt_client_auth`.

## The three primitives

None substitutes for another, and iOS forces the separation:

| Primitive | Attests | Can it sign our JWS? |
|---|---|---|
| **App Attest** | a genuine, unmodified build of our app on genuine Apple hardware | No — its key is sealed and its output is CBOR |
| **The IdP** (PingOne passkey) | which human is present | No — `AuthenticationServices` never exposes a passkey private key |
| **Secure Enclave P-256 key** | possession, device-bound | **Yes** — ES256, non-extractable |

App Attest cannot attest a key the app generated itself. The only thing tying it to the enclave key
is that the app commits `SHA-256(enclave JWK thumbprint ‖ challenge)` as the attestation's
`clientDataHash` — and the service recomputes that from the key and challenge *it* holds, so a
mismatch surfaces as a nonce failure rather than being taken on trust.

**Residual gap, stated because it belongs in the threat model.** This proves a genuine app asked us to
certify a key. It does not prove the key is in hardware. The EUDI ARF considered and rejected an
equivalent binding for exactly this reason: a compromised instance can ask for a certification naming
whatever it likes. Android Key Attestation does not have this gap; Apple provides no equivalent.

## Endpoints

```
POST /enrol/challenge        → { challenge, expires_in }        one-time, ≥16 bytes
POST /enrol                  → { instance_id, attestation, expires_in, appattest_key_id }
POST /attestation            → { attestation, expires_in }      the hot path; enforces the time-box
POST /user-verification      → refreshes the time-box from a fresh IdP authentication
POST /compliance             → applies a CAEP device-compliance signal
GET  /.well-known/jwks.json  → the attester's public keys, for PingFederate to verify us
GET  /health
```

Errors are the OAuth shape (`error`, `error_description`) with stable codes, so a client can branch on
`user_verification_required` — the one it can actually recover from — rather than parsing prose.

## The time-box, and why it lives here

The enclave key is biometry-gated, so a signature implies user verification happened *at some point*.
But the app holds a pre-authenticated `LAContext`, and **Apple documents no expiry on it** — so "at
some point" could be hours ago. The device-side window is therefore app-enforced, and a compromised
app could hold that context indefinitely.

So the control that actually bounds agent activity is server-side: `uv_last_verified_at` in the
registry, refreshed **only** by a verifiable IdP authentication, and checked on every mint. When it
ages out, `/attestation` returns `user_verification_required` and the agent stops until the human is
back in front of the phone. That is the time-box.

## Two defaults that fail closed

- **Development App Attest is refused** unless `APPLE_ALLOW_DEVELOPMENT=true`. A verifier accepting
  both by default is a hole that survives into production. When it is allowed, the environment is
  recorded on the device row so a development enrolment can never later pass as a production one.
- **A device whose compliance is UNKNOWN cannot mint.** Never assessed is not the same as assessed and
  clean.

## Configuration

All by environment variable. `DATABASE_URL` and `ENROLMENT_SIGNING_JWK` are secrets and are not in the
`vars.*.env` files.

| Variable | Notes |
|---|---|
| `ENROLMENT_ISSUER` | this service's entity id — the attestation `iss` and the key-proof `aud` |
| `DATABASE_URL` | Postgres JDBC URL |
| `ENROLMENT_SIGNING_JWK` | the attester's private JWK. Production should use the vault-backed `JwsSigner`; the seam exists |
| `APPLE_TEAM_ID` / `APPLE_BUNDLE_ID` | the App ID an attestation must be bound to |
| `APPLE_ALLOW_DEVELOPMENT` | default `false` |
| `UV_MAX_AGE_SECONDS` | the time-box, default 300 |
| `REQUIRE_COMPLIANT_DEVICE` | default `true` |
| `PINGONE_ISSUER` | the IdP. **Unset → enrolment is refused**, loudly, at startup |

## Running locally

```bash
docker compose -f deploy/device-enrolment/docker-compose.yml up --build
```

Brings up Postgres with the schema applied and the service on `:8080`. Enrolment will refuse until an
IdP verifier is configured — the service says so at startup rather than pretending — but the challenge
endpoint, the JWKS and the schema are all exercisable.

## What is not done yet

- **The PingOne verifier.** No tenant exists in this repository, so `UserAuthenticationVerifier` has no
  production implementation. `Main` refuses rather than stubbing it, and the tests supply their own.
- **The out-of-band notification** NIST SP 800-63B §6.1.2.1 requires when an authenticator is bound.
  This service has no channel to the user; the caller must send it.
- **Concurrency against real Postgres.** The registry contract is tested against H2 in PostgreSQL
  mode, which is a compatibility layer. The revocation write racing an issuance read needs a real
  Postgres integration test.
