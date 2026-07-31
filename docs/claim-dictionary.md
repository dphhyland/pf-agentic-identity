# Claim dictionary

Every claim this platform mints or verifies, the spec it comes from, and — where we depart from that
spec — the reason. Fetched from the source documents on 2026-07-31, not recalled.

The point of this file is that a reviewer can tell, for any claim, whether it is standard, an
extension, or a deliberate divergence, without reading the code.

---

## Client Attestation JWT

`draft-ietf-oauth-attestation-based-client-auth-10` (6 July 2026). Issued by the platform backend
acting as Client Attester; verified by PingFederate.

| Claim | Spec status | Value here |
|---|---|---|
| `typ` (header) | REQUIRED | `oauth-client-attestation+jwt` |
| `sub` | REQUIRED | The **opaque agent instance identifier**. Never the user, never the device. |
| `exp` | REQUIRED | `iat + 15 min` — see *Attestation lifetime* below |
| `cnf.jwk` | REQUIRED (MUST use `jwk`) | The Secure Enclave P-256 public key |
| `iat` | OPTIONAL | Always set |
| `iss` | **Removed from the spec in -08** | **Retained** — see divergence 1 |
| `key_storage` | OpenID4VCI 1.0 Appendix D | `iso_18045_moderate` — see divergence 3 |
| `user_authentication` | OpenID4VCI 1.0 Appendix D | `iso_18045_moderate` — see divergence 3 |
| `authenticator_ref` | extension | Reference to the bound passkey credential (not the credential itself) |
| `agent_build` | extension | Agent platform build/version |
| `uv_policy` | extension | The user-verification reuse window in force, seconds |

Permitted `key_storage` / `user_authentication` values, verbatim from Appendix D:
`iso_18045_high` (VAN.5), `iso_18045_moderate` (VAN.4), `iso_18045_enhanced-basic` (VAN.3),
`iso_18045_basic` (VAN.2).

## Client Attestation PoP JWT

Same draft. Minted per request by the iOS agent, signed by the Secure Enclave key.

| Claim | Spec status | Value here |
|---|---|---|
| `typ` (header) | REQUIRED | `oauth-client-attestation-pop+jwt` |
| `aud` | REQUIRED | PF's **configured** base URL — not the URL the request arrived on. The documented `aud` trap. |
| `jti` | REQUIRED | Fresh UUID; replay-cached per client |
| `iat` | REQUIRED | Max age 300 s, skew 60 s |
| `challenge` | OPTIONAL | Present when the attester requires it |
| `iss` | **Removed in -08** | Set to the attestation's `sub`, for symmetry with divergence 1 |

Transport headers: `OAuth-Client-Attestation`, `OAuth-Client-Attestation-PoP`. A third,
`OAuth-Client-Attestation-Challenge`, exists in the draft. Registered token endpoint auth methods:
`attest_jwt_client_auth` and `attest_jwt_client_auth_dpop`.

## Instance-key proof JWT — repo extension, no spec equivalent

Used by the *workload* attester (`POST /federation/attestation`), not on the iOS path.

`typ` = `oauth-attestation-instance-proof+jwt`. **This value is not registered in any draft, and that
is correct**: the OAuth attestation draft has no issuance-side proof concept at all — it starts once
the client already holds an attestation. This is a local extension covering how a caller proves
possession of the key it is asking to have attested.

Claims: `aud` (required, the attester issuer), `jti` (required), `iat` (optional, max age 300 s,
skew 60 s), `challenge` (optional — note the claim name is `challenge`, not `nonce`).

## DPoP proof

RFC 9449.

| Claim | Value |
|---|---|
| `typ` (header) | `dpop+jwt` |
| `jwk` (header) | The Secure Enclave public key |
| `htm` / `htu` / `iat` / `jti` | Per RFC |
| `cnf.jkt` (on the access token) | base64url SHA-256 JWK thumbprint (RFC 7638) of the same enclave key |

Every agent-path access token is sender-constrained. No bare bearer tokens.

## Delegation — `act`

RFC 8693.

| Claim | Value |
|---|---|
| `sub` | **The human** on whose behalf the agent acts |
| `act` | A **JSON object** |
| `act.sub` | The **agent instance identifier** |

Two rules that are easy to get wrong and are both enforced here:

- **`act` is a JSON object, not a string.** `deploy/gke-spiffe-demo/pf/terraform/token-exchange.tf`
  currently emits it as a JSON *string* for consumers to decode. That is a deviation from RFC 8693 and
  is being corrected, not carried forward.
- **Nested prior actors are informational only** and MUST NOT feed access-control decisions. Only the
  outermost `act` — the current actor — may be authorised on.

## CAEP events

SSF 1.0 and CAEP 1.0, both Final (2 September 2025). URIs under
`https://schemas.openid.net/secevent/caep/event-type/`.

| Event | Required event-specific claims |
|---|---|
| `device-compliance-change` | `previous_status`, `current_status` — each `compliant` or `not-compliant` |
| `session-revoked` | none |
| `credential-change` | `credential_type` (`fido2-platform` for a passkey), `change_type` ∈ create/revoke/update/delete |
| `assurance-level-change` | `namespace`, `current_level`; optional `previous_level`, `change_direction` |

`namespace` is MAY, not MUST, so a custom assurance namespace is first-class. The four other CAEP
types (`token-claims-change`, `session-established`, `session-presented`, `risk-level-change`) are not
used here. Eight total, no more.

## OpenID Federation

OpenID Federation 1.0 Final (17 February 2026); a Final 1.1 (5 May 2026) also exists.

| Item | Value |
|---|---|
| Entity statement `typ` | `entity-statement+jwt` |
| `authority_hints` | REQUIRED for any entity with ≥1 superior; MUST NOT appear for trust anchors **with no superiors**. PingFederate is an intermediate here, so it carries them, pointing at `deploy/lighthouse`. |
| `metadata_policy` | Narrow-only. §6.1.1: a policy "cannot be repealed or made more permissive by Intermediate Entities that are subordinate in the Trust Chain." Composition fails closed. |

Note an anchor acting as an intermediate in a nested federation *does* carry `authority_hints` — the
rule is about having superiors, not about being an anchor.

---

## Deliberate divergences

### 1. `iss` retained on the attestation and PoP

Draft -08 removed `iss` from both JWTs; -10 does not define it. We keep it.

**Why:** this repo's `ClientAttestationVerifier` resolves the attester's signing keys *by* `iss` —
through `FederationAttesterKeyResolver`, which walks an OpenID Federation trust chain from the attester
up to the anchor. Removing `iss` would mean falling back to the draft's suggested `x5c` / `kid`+`jku`
resolution and discarding the federation-based trust path, which is the whole point of the
architecture. The draft explicitly puts attester trust establishment **out of scope** (§9.8), so this
is filling a gap the spec declines to fill rather than contradicting it.

**Revisit if:** the draft later defines a federation-based resolution mechanism of its own.

### 2. Reuse within the 15-minute window, where EUDI mandates single-use

The EUDI ARF requires a Wallet Instance Attestation to be sent to **at most one** verifier
(TS3 §2.2.1.1), explicitly to prevent issuer linkability, with once-only attestation mandatory.
draft-10 permits reuse. We reuse.

**Why:** the linkability argument does not apply. An ARF wallet presents its WIA to many independent
PID and attestation providers, so a reused artefact becomes a cross-provider correlation handle. Our
attestation is presented to exactly one verifier — our own PingFederate — so there is no second party
to correlate with. The `sub` is pseudonymous regardless (invariant 2), so even that single verifier
learns no user identity from the attestation.

**Revisit if:** the attestation is ever presented to a second relying party. At that moment this
divergence becomes a real privacy defect, not a justified simplification.

### 3. `iso_18045_moderate`, not `iso_18045_high`

**Why:** the EUDI ARF distinguishes a **WSCD** — a tamper-resistant device meeting LoA High — from a
**keystore**, defined as "a hardware-backed repository and service that generates, stores, and uses
non-critical cryptographic assets", and it lists secure enclaves explicitly in that second category.
TS3 §2.3.2 requires `iso_18045_high` only "for a KA about a WSCD".

The Apple Secure Enclave is a keystore by that taxonomy. Asserting `iso_18045_high` would be a false
security claim, and a downstream policy that trusts it would be relying on an assurance we cannot
demonstrate. The value is pinned in code and asserted in a test so it cannot drift upward by accident.

**Revisit if:** a certification is obtained that actually supports a higher claim.

### 4. Attestation lifetime: 15 minutes

Not a divergence so much as a number the specs leave open, recorded here because the brief asked for
it to be defended.

The attestation asserts device posture and the user-verification policy in force. Both go stale, and a
long-lived attestation asserting current posture is fiction. The EUDI ARF caps the analogous WIA below
24 hours (`WUA_33`) and requires the provider to verify instance integrity immediately before signing.

Fifteen minutes because re-minting is cheap: it costs one round trip and — while the `LAContext` is
still live — **no user prompt**. So the usual argument for long lifetimes (user friction) does not
apply. CAEP covers the residual window between mints, and server-side UV recency (5 minutes) is
checked independently at every issuance.
