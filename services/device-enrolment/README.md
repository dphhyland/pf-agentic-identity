# device-enrolment

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Written here, no upstream; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The **agent platform backend** — the Client Attester for agents running on a user's device.

Not a PingFederate extension. A standalone JVM service (`Main` wires it from the environment;
`EnrolmentHttpServer` is the JDK's own `HttpServer`, no framework) that PF *trusts*: it runs the binding
ceremony, owns the instance registry, and mints the Client Attestations an on-device agent presents at
PF's token endpoint via `attest_jwt_client_auth`. Package `com.pingidentity.ps.oidf.enrolment`.

Built on the libs: [`app-attest`](../../libs/app-attest) (App Attest verification; its test-jar
supplies the synthetic Apple chain the tests use), [`device-instance`](../../libs/device-instance)
(the registry + `DeviceAttestationMinter`), [`client-attestation`](../../libs/client-attestation)
(challenge issue/consume and `jti` replay — reused, not rewritten) and
[`oidf-jose`](../../libs/oidf-jose) (`JwsSigner`). The PostgreSQL driver ships here, not in the library.

## The three primitives

None substitutes for another, and iOS forces the separation:

| Primitive | Attests | Can it sign our JWS? |
|---|---|---|
| **App Attest** | a genuine, unmodified build of our app on genuine Apple hardware | No — its key is sealed and its output is CBOR |
| **The IdP** (PingOne passkey) | which human is present | No — `AuthenticationServices` never exposes a passkey private key |
| **Secure Enclave P-256 key** | possession, device-bound | **Yes** — ES256, non-extractable |

App Attest cannot attest a key the app generated itself. The only thing tying it to the enclave key is
that the app commits `SHA-256(enclave JWK thumbprint ‖ challenge)` as the attestation's
`clientDataHash` — and `EnrolmentService` recomputes that from the key and challenge *it* holds, so a
mismatch surfaces as a nonce failure rather than being taken on trust. After enrolment, possession of
that key is proved per call by an ES256 JWS with the key in its `jwk` header, thumbprint-matched to the
registry (`EnclaveKeyProofValidator`).

**Residual gap, stated because it belongs in the threat model.** This proves a genuine app asked us to
certify a key. It does not prove the key is in hardware. The EUDI ARF considered and rejected an
equivalent binding for exactly this reason. Android Key Attestation does not have this gap; Apple
provides no equivalent.

## Endpoints

```
POST /enrol/challenge        → { challenge, expires_in }        one-time, ≥16 bytes
POST /enrol                  → { instance_id, attestation, expires_in, appattest_key_id }
POST /attestation            → { attestation, expires_in }      the hot path; enforces the time-box
POST /user-verification      → refreshes the time-box from a fresh IdP authentication
POST /compliance             → { device_id, current_status }   applies a device-compliance change
GET  /.well-known/jwks.json  → the attester's public keys, for PingFederate to verify us
GET  /health
```

Errors are the OAuth shape (`error`, `error_description`) with stable codes, so a client can branch on
`user_verification_required` — the one it can actually recover from.

**CAEP.** `CaepEventHandler` decodes a verified CAEP SET, checks `jti` replay (SSF redelivers by
design), and dispatches each event to [`CaepSignalApplier`](../../libs/device-instance) — the actual
registry mutation, shared with `servlets/ssf`'s `InstanceRegistryReceiverHandler` so both transports
apply CAEP identically: `device-compliance-change` suspends every instance on the device;
`session-revoked` revokes the instances acting for that human; a revoked or deleted `fido2*`
`credential-change` revokes the bindings that passkey authorised. Signature, issuer, audience and
freshness are the caller's job. Two transports reach it: `/compliance` here takes the plain JSON above
(no verification of its own — it's the direct/demo path); PF's SSF receiver is the verified one,
gated behind `receiverInstanceRegistry=true` + `storeDialect=ldm` on the `ssf` module (see
[servlets/ssf](../../servlets/ssf)), which shares the `ldm` store's own `DataSource` rather than
opening a second connection to the IOM.

## The time-box, and why it lives here

The enclave key is biometry-gated, so a signature implies user verification happened *at some point*.
But the app holds a pre-authenticated `LAContext`, and Apple documents no expiry on it. The control that
actually bounds agent activity is therefore server-side: `uv_last_verified_at` in the registry, refreshed
**only** by a verifiable IdP authentication (`PingOneIdTokenVerifier`, offline against the environment
JWKS), and checked on every mint. When it ages out, `/attestation` returns `user_verification_required`
and the agent stops until the human is back in front of the phone.

## Defaults that fail closed

- **Development App Attest is refused** unless `APPLE_ALLOW_DEVELOPMENT=true`; when allowed, the
  environment is recorded on the device row so a development enrolment can never pass as production.
- **A device whose compliance is UNKNOWN cannot mint** (`REQUIRE_COMPLIANT_DEVICE`, default true).
- **No IdP configured → enrolment refused**, loudly, at startup.
- `OIDF_ATTESTATION_SUB=client_id` without `OIDF_AGENT_CLIENT_ID` refuses to start.

## Configuration (all environment variables, read in `Main`)

| Variable | Notes |
|---|---|
| `PORT` | default 8080 |
| `ENROLMENT_ISSUER` | this service's entity id — the attestation `iss` and the key-proof `aud` |
| `DATABASE_URL` | Postgres JDBC URL (secret; absent → refuses to start) |
| `ENROLMENT_SIGNING_JWK` | the attester's private JWK (secret). Production should use a vault-backed `JwsSigner`; the seam exists |
| `APPLE_TEAM_ID` / `APPLE_BUNDLE_ID` | the App ID an attestation must be bound to |
| `APPLE_ALLOW_DEVELOPMENT` | default `false` |
| `UV_MAX_AGE_SECONDS` | the time-box, default 300 — must match the `instance-registry-datasource` UV field |
| `REQUIRE_COMPLIANT_DEVICE` | default `true` |
| `PINGONE_ISSUER` / `PINGONE_CLIENT_ID` | the IdP; both required or user authentication is refused |
| `PINGONE_ACR_AAL2` | comma-separated sign-on policy names whose `acr` genuinely means AAL2; anything else is AAL1 and refused for binding |
| `OIDF_ATTESTATION_SUB` / `OIDF_AGENT_CLIENT_ID` | the staged Phase 2.5 `sub` flip: `client_id` mints `sub` = the registered client; `agent_id` carries the instance id either way. See [docs/claim-dictionary.md](../../docs/claim-dictionary.md) |

## Deploy

**There is no deploy definition for this service, deliberately.** One existed here until 2026-08-21 —
a two-stage `Dockerfile`, `railway.json` and per-env vars — and was deleted rather than moved with the
rest of the deploy tree, because no `device-enrolment` service has ever existed in any Railway
project: the config described a deployment that had never happened, and half of it (`Dockerfile.demo`)
had been unbuildable since the 2026-08-08 split.

This repo is the capability and deploys nothing. When the service is actually provisioned, write the
definition then, in whichever repo owns that environment, against what it actually needs — it will be
a better definition than the stale one. Git history has the old files if they are worth starting from.

The service needs `IDM_DATABASE_URL` and `ENROLMENT_SIGNING_JWK` supplied as secrets, and the schema
is owned by the model repo's migration workflow, not shipped here.

## Running locally, and the phone simulator

A `docker-compose.yml` alongside that deploy definition was the local demo stack: Postgres with the schema applied
plus `Dockerfile.demo`, whose entry point is `DemoServerMain` — `Main`'s wiring with a bundled synthetic
App Attest root, because only a physical iPhone can produce a chain to Apple's real one. **That
Dockerfile still builds `demo/phone-simulator` inside this repo, and that path moved out on 2026-08-08**
to the pf-agentic-identity-domain-authority repo (sibling checkout), so the compose stack does not build
as-is. `DemoServerMain` and `PhoneSimulatorCli` — the CLI that plays the phone's side of the ceremony —
live there now; its `phone-simulator/README.md` covers what the synthetic root does and does not prove,
and how to obtain a real PingOne ID token for the green path.

## PingOne

Wired against environment `fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d` ("P1AS", region AP); the client is
**Device Agent Enrolment** (`fad0652e`), a public native app with PKCE `S256_REQUIRED`, on the
`Bank_Signup_Passkey` sign-on policy — a single `fido2` MFA action despite its "registration" description,
so it serves both enrolment and the recurring refresh. It sets `noDevicesMode: BLOCK`: a user with no
passkey is blocked, so a first enrolment needs the passkey to already exist. Full reasoning in
`vars.staging.env`.

## Build and test

```bash
mvn -pl services/device-enrolment -am test      # 55 tests
```

`EnrolmentHttpEndToEndTest` drives the real HTTP surface — challenge, App Attest with the enclave-key
commitment, enrolment, re-mint, time-box refusal and recovery — with a software P-256 key standing in for
the enclave and the `app-attest` test-jar's synthetic Apple chain.

## Not done yet

- **A real device.** The harness cannot prove Apple's real attestation objects parse; only hardware can.
- **A wired notification channel.** `BindingNotifier` is a seam; its default logs on every binding.
- **This service deployed anywhere.** It has never been provisioned in any Railway project, so
  `/compliance` here is not reachable in any environment, even though the verified path (PF's SSF
  receiver, see above) already is. The stale config-as-code that claimed otherwise was deleted on
  2026-08-21.
- **The compose stack**, until `Dockerfile.demo` is repointed at the domain-authority checkout.
