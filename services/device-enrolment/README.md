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
GET  /.well-known/jwks.json  → the attester's public keys, for PingFederate to verify us
GET  /health
```

Errors are the OAuth shape (`error`, `error_description`) with stable codes, so a client can branch on
`user_verification_required` — the one it can actually recover from.

**There is no compliance endpoint.** Until 0.4.0 `POST /compliance` took `{device_id, current_status}`
as plain JSON from anyone who could reach the port - no SET, no signature, no caller authentication - and
suspended every `ACTIVE` instance on the device (the 2026-09-26 review's B4; removed by M-2, PR pending,
2026-09-27). The one path by which a compliance change reaches the registry is
[`CaepSignalApplier`](../../libs/device-instance), called from PingFederate's SSF receiver
(`servlets/ssf`'s `InstanceRegistryReceiverHandler`, behind `receiverInstanceRegistry=true` and
`storeDialect=ldm`, sharing the `ldm` store's `DataSource`). What that means for running this service is
the next section.

`CaepEventHandler` - which decodes a verified CAEP SET, checks `jti` replay (SSF redelivers by design),
and dispatches `device-compliance-change`, `session-revoked` and `credential-change` to
`CaepSignalApplier` - is still in this module and exercised by its own test, but **is not wired to any
route**: nothing in `Main` or `EnrolmentHttpServer` constructs it, and X-A18 retires it. Its
`session-revoked` handling resolves only a device-scoped subject (`sessionRevokedForDevice`); unlike the
SSF receiver it never falls back to `CaepSignalApplier.sessionRevokedForOwner` for a human-scoped
subject, so wiring it up as-is would silently no-op on a `session-revoked` naming the user.

## Not production-usable until Phase 6

Read this before deploying the service anywhere that matters. Three facts, each true of the code as it is
(verified 2026-09-27 on `main` at 711ff11):

1. **A device is registered `UNKNOWN`.** `EnrolmentService.enrol` writes the device with
   `ComplianceState.UNKNOWN` - never assessed is not the same as compliant - and mints the first
   attestation without a compliance check.
2. **Re-minting needs `COMPLIANT`.** `POST /attestation` refuses `device_not_compliant` unless the device
   is `COMPLIANT` (`REQUIRE_COMPLIANT_DEVICE`, default `true`). `UNKNOWN` fails closed, on purpose.
3. **Nothing in this repository can make a device `COMPLIANT`.** The only writer of the posture is
   `InstanceRegistry.updateCompliance`, reached from `CaepSignalApplier.deviceComplianceChange`, whose only
   live caller is the SSF receiver above (the unwired `CaepEventHandler` is the other). That receiver needs a
   transmitter that emits
   `device-compliance-change` with an `opaque` subject equal to this registry's device id, and no such
   transmitter exists: PingOne is no longer the assumed source (U-0008, David's decision of 2026-09-26),
   and the Intune adapter that will be the source is Phase 6 (X-A16).

So an enrolled device mints once and is then stuck: its instance is `ACTIVE`, its device `UNKNOWN`, every
re-mint refused. Until 0.4.0 the unauthenticated `/compliance` route was what broke the deadlock, for anyone
on the network. The only remaining way through is `REQUIRE_COMPLIANT_DEVICE=false`, which lets an
unassessed device mint for as long as it likes - a development setting that removes the compliance control
rather than satisfying it, and not one to run with.

What closes it, all Phase 6 (v0.9.0): X-A15 makes the SSF receiver a real compliance sink (per-transmitter
configuration, `iss_sub` device subjects resolved through MDM ids, durable processing, auto-resume of an
instance suspended for compliance); X-A16 is the Intune adapter that emits the signals; X-A17 correlates the
MDM record at enrolment and writes the device only if it is compliant, so no device is `UNKNOWN` to begin
with; X-A18 retires `CaepEventHandler`. The schema those need is proposed in
[docs/device/iom-schema-v2-proposal.md](../../docs/device/iom-schema-v2-proposal.md). The register carries
this as F-0004, mitigated by M-2 and open until X-A17.

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
- **A Mac must show its App Attest key bound to Full Security and SIP.** macOS 27 writes the
  Secure Enclave's conditions on the key into the credential certificate (`AppAttestKeyPolicy`); a
  Mac that does not show them is refused unless `APPLE_MACOS_REQUIRE_KEY_POLICY=false`. Without them
  code signing on the Mac cannot be relied on, so nothing the app says about the code around it can.
- **A connector that enrolled with App Attest renews with an assertion** from the same App Attest key,
  over its key proof, with a rising counter - the instance key alone, a file the Secure Enclave will
  use for whoever holds it, does not keep an agent alive. `APPLE_REQUIRE_RENEWAL_ASSERTION=false`
  waives it.
- **A device whose compliance is UNKNOWN cannot mint** (`REQUIRE_COMPLIANT_DEVICE`, default true).
- **No IdP configured → enrolment refused**, loudly, at startup.
- `OIDF_ATTESTATION_SUB=client_id` without `OIDF_AGENT_CLIENT_ID` refuses to start.

## Configuration (all environment variables, read in `Main`)

| Variable | Notes |
|---|---|
| `PORT` | default 8080 |
| `ENROLMENT_ISSUER` | this service's entity id — the attestation `iss` and the key-proof `aud` |
| `IDM_DATABASE_URL` | the Identity Object Model directory (Postgres) the registry lives in, the one the SCIM users live in; a JDBC URL or a `postgresql://` DSN (secret). Absent, the service refuses to start, and a `DATABASE_URL` left from before the move to the model is refused with a message naming the rename. Not read with `REGISTRY=memory` |
| `REGISTRY` | `iom` (default), or `memory` for a registry that lives in the process and is lost on restart - development only, with a warning at start |
| `ENROLMENT_SIGNING_JWK` | the attester's private JWK (secret). Production should use a vault-backed `JwsSigner`; the seam exists |
| `APPLE_TEAM_ID` / `APPLE_BUNDLE_ID` | the App ID an attestation must be bound to |
| `APPLE_ALLOW_DEVELOPMENT` | default `false` |
| `APPLE_MACOS_REQUIRE_KEY_POLICY` | default `true`: a Mac's attestation must show Full Security and SIP |
| `APPLE_REQUIRE_RENEWAL_ASSERTION` | default `true`: an App Attest enrolment renews with `app_attest_assertion` |
| `CONNECTOR_BUILDS` | comma-separated base64url SHA-256 hashes of the connector builds to accept; the helper commits its build through App Attest (`evidence.connector_build`). Empty accepts any build and records it |
| `UV_MAX_AGE_SECONDS` | the time-box, default 300 — must match the `instance-registry-datasource` UV field |
| `REQUIRE_COMPLIANT_DEVICE` | default `true` |
| `PINGONE_ISSUER` / `PINGONE_CLIENT_ID` | the IdP; both required or user authentication is refused |
| `PINGONE_ACR_AAL2` | comma-separated sign-on policy names whose `acr` genuinely means AAL2; anything else is AAL1 and refused for binding |
| `OIDF_ATTESTATION_SUB` / `OIDF_AGENT_CLIENT_ID` | the staged Phase 2.5 `sub` flip: `client_id` mints `sub` = the registered client; `agent_id` carries the instance id either way. See [docs/claim-dictionary.md](../../docs/claim-dictionary.md) |

The connector-agent path (the Mac connector) reads the rest, and each is off until set:

| Variable | Notes |
|---|---|
| `YUBICO_PIV_ROOTS` | path to a PEM bundle of pinned Yubico PIV roots; set, `yubikey-piv` evidence is accepted |
| `ALLOW_SELF_ASSERTED_KEYS` | default `false`; `true` accepts `secure-enclave-self-asserted` evidence, a key whose storage nobody can verify, and attests it without a `key_storage` claim (with a warning at start) |
| `AGENT_AUTHORIZATION_DETAILS` | a JSON array: the RFC 9396 ceiling every connector attestation carries |
| `PF_AUTHORITY_ENTITY_ID` / `PF_AUTHORITY_URL` / `PF_AUTHORITY_ADMIN_TOKEN` / `PF_AUTHORITY_INSECURE_TLS` | the federation authority (PingFederate's issuer) that hosts agent entities. Unset, no agent entity is registered. The URL defaults to the entity id; the admin token (`OIDF_AUTHORITY_ADMIN_TOKEN` over there) is then required; `PF_AUTHORITY_INSECURE_TLS=true` trusts a self-signed listener, for development |
| `AGENT_DISPLAY_NAME` / `AGENT_DESCRIPTION` / `AGENT_KEYWORDS` | what the authority vouches for about every agent, in its own words; the keywords as a JSON array |
| `AGENT_MISSION_TYPES` / `AGENT_MISSION_PURPOSES` | JSON arrays: the RAR types and the DPV purposes an agent may claim. Each one set becomes an essential `subset_of` policy in the authority's statement, so an agent that declares none does not resolve |

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
mvn -pl services/device-enrolment -am test      # 82 tests
```

`EnrolmentHttpEndToEndTest` drives the real HTTP surface — challenge, App Attest with the enclave-key
commitment, enrolment, re-mint, time-box refusal and recovery — with a software P-256 key standing in for
the enclave and the `app-attest` test-jar's synthetic Apple chain.

## Not done yet

- **A real device.** The harness cannot prove Apple's real attestation objects parse; only hardware can.
- **A wired notification channel.** `BindingNotifier` is a seam; its default logs on every binding.
- **This service deployed anywhere.** It has never been provisioned in any Railway project. The stale
  config-as-code that claimed otherwise was deleted on 2026-08-21.
- **A compliance source.** See [Not production-usable until Phase 6](#not-production-usable-until-phase-6):
  the receiver path exists, nothing feeds it.
- **The compose stack**, until `Dockerfile.demo` is repointed at the domain-authority checkout.
