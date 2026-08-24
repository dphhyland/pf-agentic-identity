# AI Agent Profile of OAuth 2.0 Attestation-Based Client Authentication 1.0 — draft 00

## Abstract

[ABCA] — OAuth 2.0 Attestation-Based Client Authentication — defines how a client authenticates at a
token endpoint with a Client Attestation and a proof of possession, and deliberately leaves open which
algorithms are used, what `sub` means for a fleet of running instances, how long an attestation lives,
whether it may be reused, and whether the client authenticating is one instance or a whole fleet sharing
a credential. Two conformant [ABCA] deployments can therefore differ in every property that determines
their security strength.

This specification profiles [ABCA] for **AI agent fleets** — numerous, ephemeral, dynamically scheduled
instances of one registered client. It does not define new protocol mechanism; it removes variance from
an existing one by fixing what [ABCA] left open, for one specific high-stakes deployment shape.

## Status

Individual draft. Companion to [CAS] (the AI Agent Client Attestation Service — how an attestation
conformant with this profile is *issued*) and to [ABCA] (which this profile constrains but does not
redefine). This document is not an OpenID Foundation standard and has no official standing.

---

## 1. Introduction

[ABCA] answers "how does a client prove it holds the key an attestation names" and stops there by
design. For a single long-lived service with one operator that is a reasonable stopping point — the
remaining choices are obvious from context. For a fleet of AI agent instances, scheduled across
heterogeneous infrastructure, the same choices are not obvious, and getting them wrong is not cosmetic:

- The **wrong algorithm allowlist** admits `alg` confusion or a weak signature scheme into an
  authentication credential.
- The **wrong `sub` semantics** — an opaque per-instance identifier, unregistered — forces one PF/OAuth
  client per running pod, which is an inventory problem wearing an identity costume, not identity.
- **No lifetime ceiling** turns a "short-lived credential" claim into marketing.
- **No stance on shared credentials** re-opens the exact problem [ABCA] exists to close: a `client_secret`
  or a long-lived key shared across a fleet destroys per-instance accountability the moment it's copied
  once.

This profile closes each of these for the AI-agent case specifically. It is scoped narrowly and
deliberately: it constrains the **attestation and proof-of-possession artifacts and their use at the
authorization server**. It does not define an issuance API (see [CAS]), how the authorization server
establishes trust in the attester that signed a given attestation (see Section 1.1), a
revocation-propagation mechanism (SSF/CAEP or equivalent — a recommended complement, but a
separate specification), or an authorization-decision mechanism (RAR containment enforcement, PDP
policy). Bundling those in would leave one conformance claim covering too much surface to mean anything
precise.

### 1.1 Relationship to Other Specifications

**[ABCA] is authoritative for the attestation artifacts themselves** — their base claim set, `typ`
values (`oauth-client-attestation+jwt`, `oauth-client-attestation-pop+jwt`), the `attest_jwt_client_auth`
and `attest_jwt_client_auth_dpop` token endpoint authentication methods, and the challenge mechanism.
This profile does not respecify any of it; it selects among options [ABCA] leaves to the deployment and
defines the extension claim needed for a fleet (Section 6).

**[CAS] defines issuance**: the API an agent instance calls to obtain an attestation that conforms to
this profile. A CAS need not be used — an attester issuing directly via some other mechanism can still
produce a conformant attestation — but every normative requirement in this profile is written to be
satisfiable by [CAS] without modification.

**Explicitly out of scope**, named here so conformance to this profile is never mistaken for a claim
about them:

- **Attester trust establishment.** How an authorization server decides it trusts the signing key behind
  a given `iss` — OpenID Federation trust chains, a pinned `x5c`/`kid`+`jku`, or something else — is not
  addressed by this profile. [ABCA] itself puts this out of scope (§9.8); this profile does not re-scope
  it in. [CAS] §6.2 discusses trust models for client metadata sources, which is an adjacent but distinct
  question (trusting *who a client is bound to*, not trusting *who signed the attestation*).
- **Revocation propagation.** This profile does not require SSF/CAEP or any other real-time revocation
  channel — see Section 9 for what that omission costs a deployment.
- **Fine-grained authorization enforcement.** Section 7 profiles the optional `authorization_details`
  extension claim itself; it does not mandate where or how `requested ⊆ attested` containment is
  enforced downstream (issuer-side, PDP-side, or both is implementation policy, not this profile's
  concern).
- **Instance authentication** (how the instance proves *what it is* to the attester) — [CAS] §3 already
  covers this; it is not repeated or altered here.

**SPIFFE-native client authentication: considered, not adopted.** [SPIFFE-CLIENT-AUTH] defines an
alternative in which an SVID authenticates directly at the token endpoint with no attester — including
§3.3, which carries a WIMSE Workload Identity Token (`typ` `wit+jwt`) in the same
`OAuth-Client-Attestation` header this profile uses, paired with the same PoP JWT. It would therefore
be natural to expect this profile to cover that binding as well. It deliberately does not, for two
reasons.

First, §3.3 requires a real SPIFFE trust domain whose signing keys are published at a bundle endpoint,
so it can serve only SPIFFE-attested instances. Wallet, device-platform and cloud workload-identity
evidence have no such trust domain, and an agent fleet spanning runtimes cannot use one binding for all
of its instances.

Second, and decisive for this profile specifically: a WIT defines only `sub`, `exp`, `cnf`, `iss` and
`jti`. It has no equivalent of `agent_id` (Section 6) or of the attester-asserted entitlement of
Section 7. A verifier implementing [SPIFFE-CLIENT-AUTH] alone would authenticate such an instance
correctly and then ignore precisely the claims this profile exists to carry — leaving the acting
instance unidentifiable and the entitlement ceiling unenforced. Extension claims could be added to a
WIT, but a verifier outside this profile would disregard them, so the interoperability gained is
authentication only, not authorization.

A deployment that is wholly SPIFFE-native and whose authorization needs nothing beyond the SVID's own
claims should prefer [SPIFFE-CLIENT-AUTH] directly, and this profile does not apply to it.

### 1.2 Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown here.

### 1.3 Terminology

This specification uses the terms defined in [ABCA], OAuth 2.0 [RFC6749], JSON Web Token [RFC7519], and
Proof-of-Possession Key Semantics for JWTs [RFC7800]. In addition, adopted from [CAS]:

**Agent Instance (Instance)**
: A single running embodiment of an OAuth client — a process, container, or device-resident agent. One
  client typically has many instances.

**Agent Type**
: The registered OAuth client the fleet of instances authenticates as. What [ABCA] means by `sub`
  under this profile (Section 6).

**Instance Key**
: An asymmetric key pair generated by, and confined to, an Agent Instance for its lifetime. Its public
  half is the `cnf` key of an issued Client Attestation.

---

## 2. Roles

| Role | Answers | Constrained by this profile |
|---|---|---|
| **Attester** | Who vouches that this Instance Key belongs to this Agent Type? | Sections 3–7 (what it may issue) |
| **Authorization Server** | Does this attestation authenticate the client, and how much? | Sections 3–8 (what it must verify) |
| **Agent Instance** | The thing presenting the attestation and its own PoP. | Sections 4, 8 (what credential shape it holds) |

*Who the Attester itself trusts before it signs — instance authentication — and how the Authorization
Server trusts the Attester's key are both out of scope here (Section 1.1).*

A **Resource Server** consuming a downstream access token is out of scope of this profile. This
repository's own `services/demo-rs` implements the analogous resource-server-side checks (AS signature,
DPoP binding, delegation-chain validation) but is not itself a written profile — an RS-side companion to
this document, covering that role the way Section 3–8 cover the attester/AS side, does not yet exist.

---

## 3. Algorithms

The Client Attestation JWT and its accompanying PoP or DPoP proof:

1. Signatures under this profile **SHALL** use `PS256` or `ES256`.
2. Signatures **SHALL NOT** use `RS256`, any `HS*` (HMAC) algorithm, or `none`.
3. An authorization server verifying an attestation or proof **SHALL** apply an explicit algorithm
   allowlist restricted to `{PS256, ES256}` — not merely rely on a JWT library's default rejection of
   `none`, which is necessary but not sufficient (a library default does not exclude `RS256` or `HS*`).

**Rationale.** This narrows [ABCA]'s open algorithm choice to two algorithms: `PS256`'s RSASSA-PSS
padding avoids the legacy PKCS#1 v1.5 surface `RS256` carries,
and `ES256` covers constrained signers (a device Secure Enclave, an HSM-backed workload identity) that
cannot economically do RSA. Restricting to two algorithms, both asymmetric, both without known
malleability concerns, removes an entire class of implementation-specific downgrade risk rather than
requiring every deployment to reason about it independently.

This section governs the attestation and proof-of-possession artifacts only. If trust in the attester
happens to be established via OpenID Federation — a deployment choice this profile neither mandates nor
precludes (Section 1.1) — the entity statement signatures on that separate trust chain are governed by
[OIDFED]'s own algorithm requirements (which mandate `RS256` support for interoperability) and are
unaffected by this section; they are a different JWT with a different job.

---

## 4. Sender-Constraining Proof

An Agent Instance **SHALL** authenticate using either:

- `attest_jwt_client_auth` — [ABCA]'s bare proof-of-possession mode, or
- `attest_jwt_client_auth_dpop` — [ABCA]'s combined mode using an [RFC9449] DPoP proof.

This profile does not mandate a single sender-constraining mechanism for every agent. Agent runtimes
vary too widely — some can bind a proof to an individual HTTP request's method and URI (DPoP), others
operate through infrastructure that makes that binding impractical (a bare PoP suffices there) — for a
single mandate to be both correct and adoptable. An authorization server **SHALL** support both; a
deployment **MAY** require one or the other per client.

Whichever mode is used:

1. `cnf.jwk` in the Client Attestation **SHALL** be a public key only. An authorization server **SHALL**
   reject an attestation whose `cnf.jwk` is a private key.
2. The algorithm constraints of Section 3 apply identically to the PoP/DPoP proof signature.
3. A DPoP proof, when used, **SHALL** be validated per [RFC9449] in full — `htm`, `htu`, freshness,
   single-use `jti` — not merely checked for the presence of a `jwk` header matching `cnf`.

---

## 5. Attestation Lifetime and Reuse

1. An issued Client Attestation's `exp` **SHALL NOT** exceed `iat` + 18 hours. This is a ceiling, not a
   target — see the note below.
2. Within its validity window, an attestation **MAY** be presented to the authorization server more than
   once (this profile does not require single-use, unlike wallet-attestation models such as the EUDI
   ARF's WIA).
3. An attestation conformant with this profile **SHALL** be accepted by at most one authorization
   server. A deployment where the same attestation would otherwise validate at more than one AS
   **SHALL** either mint a distinct attestation per AS or fall back to single-use — reuse across
   multiple verifiers turns a pseudonymous instance identifier into a cross-service correlation handle,
   which the single-verifier assumption in point 2 exists specifically to avoid.

**On the 18-hour ceiling.** [CAS] §8 RECOMMENDS a much shorter default (300 seconds) and ties it
explicitly to revocation latency: with a short TTL, a deauthorized instance holds a usable credential
for at most one TTL window, because refresh re-checks the instance's standing, the client's standing,
and policy every time. Nothing about that trade-off changes here — a shorter lifetime is still the
stronger default for any agent whose posture (compliance state, binding, entitlement) can change during
its own runtime, and deployments **SHOULD** choose the shortest lifetime consistent with their
re-minting cost. This profile sets its ceiling well above that recommendation to admit the other end of
the spectrum: long-running, infrastructure-hosted agents where posture is comparatively stable and
re-minting cost (an extra round trip, a fresh runtime-attestation fetch) matters more than a tight
window. A deployment choosing a lifetime near this ceiling accepts a correspondingly wide window in
which stale posture is presented before it is next re-validated, and **SHOULD** compensate with an
out-of-band revocation channel (Section 9) — this profile does not require one, but does not absorb the
risk of omitting one either.

---

## 6. Identity Claims: `sub` and `agent_id`

1. `sub` **SHALL** identify the Agent Type — the registered OAuth client. It **SHALL NOT** be a
   per-instance identifier. This is the ABCA-conformant reading of `sub` and resolves the fleet problem
   directly: one `sub`, many instances, rather than one registered client per running instance.
2. `agent_id` (extension claim, not defined by [ABCA]) **SHALL** always be present. It **SHALL** be a
   per-instance identifier: randomly generated, never derived from the user or the device, and unique
   only within the issuing authority. The acting party's full identity under this profile is the pair
   (`iss`, `agent_id`), not `sub` alone.
3. `agent_id` **SHALL NOT** be treated as, or substituted for, a Resource Owner's subject identifier at
   any point downstream. It names the instance; it never names a human.

**Rationale.** [ABCA] draft -08 removed a per-instance concept from scope entirely, leaving deployments
to either misuse `sub` for it (the client-per-instance anti-pattern this document opened with) or invent
their own extension. `agent_id` is this profile's standard answer, chosen so that `sub` keeps its
ordinary OAuth meaning and every fleet-aware consumer (delegation chains, audit, revocation) has one
stable name to key off regardless of how many instances the client has ever had.

---

## 7. Entitlement Extension: `authorization_details`

An attestation conformant with this profile **MAY** carry an `authorization_details` claim
[RFC9396] expressing the entitlement ceiling the attester is willing to vouch for. This extension is
**OPTIONAL** — not every AI-agent deployment needs fine-grained, attester-asserted entitlement, and this
profile does not require it for conformance.

A deployment that **does** adopt it:

1. **SHALL** treat the claim as attester-asserted authority, not caller-supplied — an authorization
   server **MUST NOT** accept a value for this claim from anywhere other than the verified attestation
   itself.
2. **SHOULD** enforce that any `authorization_details` granted downstream is a subset of the attested
   entitlement ("containment": `requested ⊆ attested`).

This profile deliberately does not say *where* containment is enforced — at the token endpoint directly,
by a downstream policy engine, or both as defense-in-depth are all conformant, and the right answer
depends on the deployment's architecture. A deployment adopting this extension without enforcing
containment anywhere has adopted a claim that constrains nothing; that is a deployment defect, not a
profile ambiguity.

---

## 8. Client Type: Exclusion of Shared Credentials

An Agent Instance authenticating under this profile **SHALL** hold its own Instance Key, generated by
and confined to that instance for its lifetime. The private half **SHALL NOT** leave the instance and
**SHALL NOT** be shared across instances.

This profile **SHALL NOT** be used with a client authenticated by a shared secret
(`client_secret_basic`/`client_secret_post`) or by any credential not cryptographically bound to a
single running instance.

This is [ABCA]'s own model, stated here explicitly so that "every instance holds its own key" is a
testable conformance point rather than an assumption a deployment could violate without anyone noticing
(for example, by provisioning one shared Instance Key across a pool of instances to save enrolment cost)
while still nominally using [ABCA].

---

## 9. Security Considerations

- **No revocation-propagation channel is required, and that has a cost.** This profile does not mandate
  SSF/CAEP or any other real-time signal from the attester's authority to the authorization server
  (Section 1.1). Without one, a revoked or deauthorized instance stops authenticating only the next time
  its attestation is checked against current state — at next re-mint, not the moment it is revoked. A
  deployment that skips a revocation channel is accepting that gap, not overlooking it; one that adopts
  SSF/CAEP or an equivalent closes it independently of Section 5's lifetime choice.
- **The 18-hour ceiling widens that gap unless a revocation channel closes it.** A deployment using a
  lifetime near the ceiling accepts that a deauthorized-but-not-yet-expired instance can continue
  authenticating for up to that long on posture that may no longer be true, unless the revocation channel
  above closes it sooner. Choosing this ceiling without one is a deliberate trade — shorter re-minting
  overhead for a wider window — not an oversight this profile makes invisible.
- **Proof-of-possession, not the attestation, protects against theft of the credential.** A captured
  attestation is useless without the Instance Key — every use requires a fresh PoP or DPoP proof over
  that key. Attestation lifetime (Section 5) does not primarily defend against a stolen attestation; it
  bounds how long *stale posture* can be presented as current.
- **Attester key compromise is a fleet-wide event.** One attester signs for every instance of every
  client bound to it (unlike, e.g., a per-client bridge-signing key). This is the same trust model as a
  CA signing certificates and carries the same mitigation: the attester's signing key SHOULD be held in
  an HSM/KMS/transit signer such that the private key never enters the issuing process, and its
  compromise SHOULD be treated as equivalent to compromising every attestation it has ever issued or
  will issue until rotated. How an authorization server would *detect* such a compromise is a trust-
  establishment question this profile does not address (Section 1.1).
- **Cross-verifier reuse turns pseudonymity into correlation.** Section 5's single-verifier constraint
  is essential, not incidental — `agent_id` is a stable pseudonym precisely because this profile
  assumes it is seen by one relying party. A deployment that violates the single-verifier assumption
  without moving to single-use has silently created a correlation handle across services.

## 10. Privacy Considerations

`agent_id` is a per-instance pseudonym by design, never a human identifier and never derived from one.
Whether a human is accountable for a given instance — which principal deployed it, who to contact on
compromise — is out of scope for this profile; deployments needing that binding maintain it out-of-band
(e.g. an instance registry, as in [CAS]'s own reference model) rather than in the attestation itself. An
`operator` or similar accountable-party claim is a plausible future extension to this profile but is not
adopted in this draft.

---

## 11. Conformance

This table allocates each requirement to the roles that bear it. It states what conformance
**requires**; it is not a report of what any particular implementation currently does. For that, see
Section 11.1.

| Requirement | Attester | Authorization Server | Agent Instance |
|---|---|---|---|
| Signs/verifies only `PS256`/`ES256` (§3) | MUST | MUST | MUST |
| Explicit algorithm allowlist, not library default (§3) | — | MUST | — |
| Accepts both PoP and DPoP modes (§4) | — | MUST accept both | MUST use one |
| `cnf.jwk` is public-key-only (§4) | MUST | MUST reject a private key | — |
| `exp` ≤ `iat` + 18h (§5) | MUST | MUST reject excess | — |
| Attestation accepted by ≤ 1 AS (§5) | — | — | MUST |
| `sub` = Agent Type, never per-instance (§6) | MUST | MUST reject a violation | — |
| `agent_id` always present, random, per-instance (§6) | MUST | — | — |
| `authorization_details`, if present, is attester-asserted only (§7) | MUST | MUST NOT caller-source | — |
| Own, unshared Instance Key (§8) | — | MUST reject shared credentials | MUST |

### 11.1 Conformance status of the reference implementation

A profile may specify ahead of the code, and this one does. The implementation in this repository
**does not conform under its shipped defaults**, and stating so here is the point of this subsection —
a conformance table that a reader mistakes for a status report is worse than none.

Three requirements need explicit configuration. All three are reachable through existing configuration
seams; none holds by default:

| Requirement | Shipped default | Gap |
|---|---|---|
| §3 algorithms | `ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS` is ten wide — `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA` — and is applied to the attestation, PoP and DPoP algorithm sets alike | The `none` and MAC half of §3.2 holds (neither is in the set), but `RS*` is admitted. Conformance requires narrowing the set explicitly through the config builder |
| §5 18-hour ceiling | off. `JwtCodec.verifyAgainstKeys` requires `exp` and allows 60s clock skew, but nothing bounds `exp - iat` unless the deployment sets a ceiling | Enforcement exists and is tested, but is disabled by default: `ClientAttestationConfig.maxAttestationLifetimeSeconds(long)` defaults to the `NO_MAX_ATTESTATION_LIFETIME` sentinel. Conformance requires setting it to `64800` |
| §6 `sub` semantics | conformant on the workload path, which mints `sub` = client id. On the device path `OIDF_ATTESTATION_SUB=client_id` is default-off, so `sub` still carries the instance identifier | See [claim-dictionary.md](claim-dictionary.md) divergence 5: this is a staged migration, not an oversight. §6.1 is met on one path and is a migration target on the other |

The remaining rows were not audited for this note and carry no claim either way here.

**The executable form of this table** is `ProfileConformanceTest` in `libs/client-attestation`. It
builds an explicitly profile-conformant configuration and asserts §3, §5 and §6 against it, so the
requirements above are checked by the build rather than only asserted in prose. Two of its cases —
`theShippedDefaultsAreBroaderThanTheProfile` and `theCeilingIsOffUnlessTheDeploymentSetsIt` — pin the
gap deliberately: narrowing a shipped default will fail them loudly rather than letting this section go
quietly stale. [claim-dictionary.md](claim-dictionary.md) carries the same requirements as a
conformance-status table, plus a fourth row for `agent_id` — omitted here because §6 places that duty on
the attester, so an authorization server enforcing it as well is defence in depth rather than a
conformance obligation. That table is kept separate from the numbered divergences because those record
departures from [ABCA] whereas these record departures from this profile.

Deployments **MUST NOT** describe themselves as conformant to this profile on the strength of running
this implementation. Conformance is a property of a configured deployment, and requires opting in to
each of the above.

---

## 12. References

### 12.1 Normative

- **[RFC2119] / [RFC8174]** — Key words for use in RFCs.
- **[RFC6749]** — The OAuth 2.0 Authorization Framework.
- **[RFC7519] / [RFC7800]** — JWT, Proof-of-Possession Key Semantics for JWTs (`cnf`).
- **[RFC9449]** — OAuth 2.0 Demonstrating Proof of Possession (DPoP).
- **[ABCA]** — OAuth 2.0 Attestation-Based Client Authentication,
  draft-ietf-oauth-attestation-based-client-auth-10.

### 12.2 Informative

- **[CAS]** — OpenID Client Attestation Service for AI Agents 1.0 (this repository,
  [docs/openid-client-attestation-service-1_0.md](openid-client-attestation-service-1_0.md)).
- **[OIDFED]** — OpenID Federation 1.0 (referenced only as one possible, non-mandated attester trust
  mechanism — see Section 1.1).
- **[RFC9396]** — OAuth 2.0 Rich Authorization Requests.
- **[SPIFFE-CLIENT-AUTH]** — SPIFFE Client Authentication for OAuth 2.0,
  draft-ietf-oauth-spiffe-client-auth. The alternative binding considered and not adopted in
  Section 1.1.

---

## Appendix A. Decision Log (Informative)

The choices this profile makes where [ABCA] leaves options open, and why — in the spirit of
[claim-dictionary.md](claim-dictionary.md)'s divergence log for the underlying implementation.

| # | Decision | Chosen here | Why not the alternative |
|---|---|---|---|
| 1 | Algorithms | `PS256`/`ES256` only | `RS256` carries legacy PKCS#1 v1.5 padding risk `PS256` avoids; excluding it removes a downgrade path rather than requiring every verifier to reason about it |
| 2 | Sender-constraining | Both PoP and DPoP valid | Agent runtimes vary too widely in whether request-level binding is practical for one mandate to fit all |
| 3 | Lifetime ceiling | 18 hours (ceiling, not target) | Admits infrastructure-hosted agents with stable posture, where re-minting is expensive, without removing [CAS]'s own shorter (300s) recommendation for the common, revocation-sensitive case |
| 4 | Reuse | Permitted within the window, single-verifier only | Single-use adds no protection PoP doesn't already provide; the single-verifier constraint is what actually preserves `agent_id`'s pseudonymity |
| 5 | `sub` semantics | Agent Type (ABCA-conformant); `agent_id` carries the instance | Keeps `sub` meaning what OAuth already expects it to mean, avoids one-client-per-instance |
| 6 | Attester trust establishment | Left entirely out of scope | [ABCA] itself already excludes it (§9.8); folding it into this profile would conflate two separable questions (what the attestation *asserts* vs. how the AS decides to *trust the signer*) that different deployments answer differently |
| 7 | Entitlement claim | Optional extension, enforcement point unspecified | Not every deployment needs attester-asserted RAR ceilings; where it's used, *where* containment is enforced is an architecture choice this profile shouldn't foreclose |
| 8 | Shared credentials | Excluded explicitly | Makes the fleet-scale premise of the whole document a testable conformance point, not an assumption |

## Appendix B. Document History

- **draft 00** — initial profile, derived from a running implementation and its own documented
  divergences ([claim-dictionary.md](claim-dictionary.md)). Scoped deliberately narrow: attestation
  artifact and AS-side use only, with issuance ([CAS]), attester trust establishment, revocation
  propagation, and authorization enforcement all named as explicit non-goals rather than left ambiguous.
