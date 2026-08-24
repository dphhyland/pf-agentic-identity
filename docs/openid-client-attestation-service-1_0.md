# OpenID Client Attestation Service for AI Agents 1.0 — draft 00

## Abstract

This specification defines a **Client Attestation Service** (CAS): an HTTP API from which a running
AI agent instance obtains a **Client Attestation** — a signed JSON Web Token, as defined by OAuth 2.0
Attestation-Based Client Authentication [ABCA] — by proving its runtime identity with a verifiable
**Instance Attestation** rather than by holding a pre-shared secret.

The specification defines:

- the **issuance API** (endpoints, request parameters, processing rules, response, and errors);
- how the issued attestation **binds the requesting instance's identity to an OAuth 2.0 Client
  Identifier** [RFC6749];
- **discovery metadata** for the service, published either as a well-known document or as OpenID
  Federation 1.0 [OIDFED] entity metadata;
- how **policy is applied at issuance** to down-scope the client's authority, expressed as OAuth 2.0
  Rich Authorization Requests `authorization_details` [RFC9396].

The mechanism by which an instance authenticates to the Client Attestation Service is **out of scope**;
this specification defines the properties such a mechanism must have and references candidate
mechanisms (SPIFFE JWT-SVIDs, Wallet Instance Attestations, platform key attestation, WebAuthn) without
mandating any.

## Status

Individual draft for contribution to the OpenID Foundation (proposed home: the Artificial Intelligence
Identity Management Community Group). This document is not an OpenID Foundation standard and has no
official standing.

---

## 1. Introduction

OAuth 2.0 deployments increasingly serve **AI agents**: autonomous or semi-autonomous workloads that
are numerous, short-lived, and dynamically scheduled across heterogeneous runtimes. The traditional
model — a `client_secret` or a long-lived private key provisioned to "the client" — fails for such
fleets in three ways:

1. **Scale** — one registered client may be embodied by hundreds of ephemeral instances; sharing one
   secret across them destroys per-instance accountability.
2. **Provenance** — a secret says nothing about *what* is presenting it: which build, which runtime,
   which platform, operated by whom.
3. **Revocation** — revoking a shared secret revokes the whole fleet; not revoking it leaves
   compromised instances trusted indefinitely.

[ABCA] addresses the *use* of client attestations at the authorization server: a client authenticates
with an attestation JWT signed by an **attester**, plus a proof-of-possession of the attested key.
[ABCA] deliberately does not define **how the attestation is issued**. This specification fills that
gap for agentic workloads: it defines the service an agent instance calls, at runtime, to *earn* its
Client Attestation by presenting a verifiable proof of what it is.

The resulting model has three trust layers, each with its own key and its own authority:

| Layer | Question answered | Key | Authority |
|---|---|---|---|
| **Instance** | *Which running instance is this?* | the platform / provider attestation key | the instance's trust root (e.g. a SPIFFE trust domain, a wallet provider, a device platform) |
| **Client** | *Which OAuth client is this instance part of, and what may it be granted?* | — (metadata, not a key) | the client metadata source (registration authority, federation trust anchor) |
| **Attestation** | *Who vouches that this instance key belongs to this client?* | the attester's signing key | the Client Attestation Service |

The instance's own **Instance Key** is generated and held by the instance for its whole lifetime and
never leaves it; only the short-lived attestation vouching for that key is refreshed.

### 1.1 Relationship to Other Specifications

**[ABCA] is authoritative for the attestation artifacts themselves.** The Client Attestation JWT and
the Client Attestation PoP JWT — their structure, required claims, `typ` values
(`oauth-client-attestation+jwt`, `oauth-client-attestation-pop+jwt`), validation rules, HTTP headers,
the `attest_jwt_client_auth` method, and the authorization-server challenge mechanism — are defined by
[ABCA] and are **not respecified here**. This specification defines only what [ABCA] declares out of
scope: the protocol by which a client instance authenticates to the attester and obtains its
attestation. A CAS issues [ABCA]-conformant Client Attestation JWTs; where this document mentions
their claims it does so descriptively, and [ABCA] controls in any conflict. This document additionally
defines two extension claims carried in issued attestations (Section 4.5), relying on [ABCA]'s rule
that unrecognised claims are ignored — with the enforcement consequence addressed in Section 7.

**Adjacent work.** Wallet ecosystems ([HAIP], EUDI wallet architectures) define issuance of Wallet
Instance Attestations for wallets specifically; the IETF WIMSE working group [WIMSE] addresses
workload identity in service environments. This specification sits above both: it *consumes* their
artifacts (a WIA, a SPIFFE SVID) as Instance Attestations and is agnostic to which is used. It
standardizes the layer neither addresses — exchanging a runtime-scoped instance identity for an
ecosystem-scoped OAuth client credential, under registered bindings and policy.

**Contrast with [SPIFFE-CLIENT-AUTH].** That specification takes the opposite approach for SPIFFE
deployments: an SVID is presented **directly** at the token endpoint as the client credential — a
JWT-SVID as a `client_assertion` (§3.1), an X.509-SVID over mutual TLS (§3.2), or a WIMSE Workload
Identity Token in [ABCA]'s attestation header (§3.3, `typ` `wit+jwt`) — with the authorization server
verifying it against the trust domain's own signing keys, and no attester in between. Both are
legitimate bindings of the same idea, and the difference is where platform-specific credential handling
lives. Under [SPIFFE-CLIENT-AUTH] the authorization server learns each platform's credential format,
trust model and key distribution; under this specification the CAS absorbs that variance and the
authorization server sees one uniform credential.

The trade is generality against directness. A CAS accepts evidence formats that have no SPIFFE trust
domain to verify against and therefore cannot use [SPIFFE-CLIENT-AUTH] at all — wallet WIAs, device
platform attestation, and cloud workload-identity tokens (GKE, EKS, AKS, AWS STS, Azure managed
identity) whose SPIFFE IDs, where an implementation synthesizes them for uniform internal handling, are
not backed by a bundle endpoint. A deployment that is wholly SPIFFE-native, and whose authorization
decisions rely only on claims the SVID itself carries, gains little from the indirection and may prefer
the direct binding. One that spans runtimes, or that relies on attester-asserted claims such as an
entitlement ceiling (Section 7), needs the exchange this specification defines: those claims are added
by the attester under policy and have no equivalent in an SVID.

### 1.2 Requirements Notation and Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT",
"RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all capitals, as shown
here.

### 1.3 Terminology

This specification uses the terms defined in OAuth 2.0 [RFC6749], JSON Web Token [RFC7519],
Proof-of-Possession Key Semantics for JWTs [RFC7800], Rich Authorization Requests [RFC9396], and
[ABCA]. In addition:

**Agent Instance (Instance)**
: A single running embodiment of an OAuth client — a process, container, wallet installation, or
  device-resident agent. One client typically has many instances.

**Instance Key**
: An asymmetric key pair generated by and confined to an Agent Instance for its lifetime. Its public
  half becomes the `cnf` key of issued Client Attestations; its private half signs Instance Key
  Proofs at issuance and Client Attestation PoPs [ABCA] at the authorization server.

**Instance Attestation**
: A verifiable statement, issued by an authority in the instance's runtime environment, that
  identifies the instance (and possibly binds a key). Examples: a SPIFFE JWT-SVID [SPIFFE], a Wallet
  Instance Attestation [HAIP], a platform key-attestation statement.

**Instance Attestation Format**
: A named scheme (e.g. `spiffe`, `wallet`) identifying how an Instance Attestation is encoded,
  validated, and what trust root vouches for it.

**Client Attestation Service (CAS, "Attester")**
: The service defined by this specification. It validates an Instance Attestation and an Instance Key
  Proof, applies policy, and issues a Client Attestation naming the client and binding the Instance
  Key. Its identifier (`iss` of issued attestations) is an HTTPS URL.

**Client Binding**
: A registered association between an OAuth Client Identifier and one or more instance subjects
  (e.g. SPIFFE IDs, wallet instance identifiers), optionally carrying per-instance entitlements and
  attributes.

**Entitlement / Entitlement Ceiling**
: A set of `authorization_details` objects [RFC9396] expressing the maximum authority that may be
  attested for a client or for one of its instances. Issued attestations MUST NOT exceed the ceiling.

**Client Metadata Source**
: The mechanism by which the CAS obtains a client's attestation configuration (bindings, entitlements,
  instance trust roots): local registration, OpenID Federation [OIDFED], or a Client ID Metadata
  Document [CIMD].

---

## 2. Architecture Overview

```
                         ┌──────────────────────────────┐
                         │   Client Metadata Source      │
                         │  (registration / federation / │
                         │   CIMD)                       │
                         └──────────────┬───────────────┘
                                        │  bindings, ceilings,
                                        │  instance trust roots
   ┌───────────────┐   ①attest    ┌─────▼─────────────┐
   │ Agent Instance │────────────►│ Client Attestation │
   │  (instance key,│◄────────────│ Service (CAS)      │
   │   instance     │  Client     └─────┬─────────────┘
   │   attestation) │  Attestation      │ publishes signing keys
   └───────┬───────┘                    │ (metadata / federation)
           │ ②client auth               ▼
           │  [ABCA]            ┌───────────────────┐
           └───────────────────►│ Authorization      │──► access token
                                │ Server             │
                                └───────────────────┘
```

1. The instance obtains an Instance Attestation from its runtime (out of scope), generates or holds
   its Instance Key, and calls the CAS issuance endpoint (Section 4).
2. The CAS resolves the client's metadata (Section 6), validates the Instance Attestation against the
   client's registered instance trust roots, verifies the Instance Key Proof, matches the proven
   instance subject against the Client Bindings, applies policy (Section 7), and issues a Client
   Attestation.
3. The instance authenticates at the authorization server per [ABCA], presenting the attestation plus
   a PoP signed by its Instance Key. The AS validates the attestation against the CAS's published
   signing keys (Section 5).

The attestation is short-lived (Section 8); the instance re-attests with a fresh Instance Attestation
as needed. Deauthorizing an instance therefore takes effect within one attestation lifetime with no
per-request revocation infrastructure at the AS.

---

## 3. Instance Authentication (Out of Scope, With Requirements)

How the calling instance proves its identity to the CAS is deliberately **not standardized** here:
runtimes differ too widely, and the mechanisms evolve independently. Instead, this section states the
properties any Instance Attestation mechanism MUST provide, and lists candidate mechanisms
(non-normatively).

An Instance Attestation mechanism, as consumed by this specification, MUST provide:

1. **Verifiability** — the CAS can cryptographically verify the attestation against a trust root it
   accepts for the client (Section 6.2), which is never supplied by the instance itself.
2. **A stable instance subject** — a string identifier for the instance (or its class) that Client
   Bindings can reference (e.g. a SPIFFE ID, a wallet instance `sub`).
3. **Freshness** — an expiry, and issuance recent enough that possession implies the instance is
   currently authorized by its runtime authority.
4. **Audience restriction** (RECOMMENDED) — the attestation is addressed to the CAS, preventing
   replay of attestations obtained for other purposes.
5. **Key binding** (OPTIONAL) — the attestation may itself bind a public key; if it does, Section 4.4
   requires it to match the presented Instance Key.

Candidate mechanisms (informative):

| Mechanism | Subject | Trust root | Binds a key |
|---|---|---|---|
| SPIFFE JWT-SVID [SPIFFE] | SPIFFE ID | trust-domain bundle (e.g. SPIRE) | no |
| Wallet Instance Attestation [HAIP] | wallet instance id | wallet provider | yes (`cnf`) |
| Android Key Attestation / Apple App Attest | app/device identity | platform vendor | yes |
| WebAuthn attestation [WebAuthn] | credential id | authenticator vendor / MDS | yes |
| X.509-SVID over mutual TLS [RFC8705][SPIFFE] | SPIFFE ID (SAN) | trust-domain bundle | channel-bound |

Transport-level authentication of the HTTP request itself (e.g. mTLS) MAY be used in addition and is
likewise out of scope.

---

## 4. The Attestation Issuance API

The CAS exposes two endpoints. All requests and responses use `application/json`. Responses containing
attestations or challenges MUST include `Cache-Control: no-store`. The endpoints MUST be served over
TLS.

### 4.1 Challenge Endpoint (OPTIONAL)

When the CAS requires request freshness beyond what the Instance Attestation provides, it advertises a
challenge endpoint (`challenge_endpoint`, Section 5.1) and sets `challenge_required` to `true`.

```
GET /attestation-challenge
```

Response:

```json
{ "attestation_challenge": "q83vEhKcy...", "expires_in": 120 }
```

The response parameter name `attestation_challenge` is used deliberately: it is the same vocabulary
[ABCA] defines for its authorization-server challenge mechanism, so implementations reuse one
challenge-handling code path for both legs. The two mechanisms remain distinct — [ABCA]'s challenge
freshens the PoP presented *to the AS*; this one freshens the Instance Key Proof presented *to the
CAS* — and a challenge issued by one party MUST NOT be accepted by the other.

A challenge is single-use: the CAS MUST reject an Instance Key Proof presenting a challenge it did not
issue, has already consumed, or that has expired. A CAS MAY also deliver a fresh challenge on any
response using the `OAuth-Client-Attestation-Challenge` HTTP header pattern defined in [ABCA].

### 4.2 Attestation Endpoint

```
POST /attestation
Content-Type: application/json
```

| Parameter | Required | Description |
|---|---|---|
| `client_id` | see below | The OAuth Client Identifier the instance claims to belong to. When the Client Metadata Source is OpenID Federation, this is the client's Entity Identifier; when CIMD, its metadata URL. |
| `instance_key` | REQUIRED | The instance's public key as a JWK [RFC7517]. |
| `instance_attestation` | REQUIRED | The Instance Attestation, in the encoding of its format. |
| `instance_attestation_format` | OPTIONAL | The format identifier (Section 10), e.g. `"spiffe"`, `"wallet"`. If absent the CAS MAY infer the format; inference only routes — full validation still applies. |
| `proof` | REQUIRED | The Instance Key Proof (Section 4.3). |
| `authorization_details` | OPTIONAL | The subset of authority the instance requests, per [RFC9396]. Absent means "the maximum my binding permits" (Section 7). |

`client_id` is REQUIRED unless the CAS supports **reverse resolution** — locating the client whose
published bindings contain the proven instance subject. Reverse resolution semantics are deployment
specific; a CAS that does not support it MUST reject requests without `client_id` with
`invalid_request`.

### 4.3 Instance Key Proof

A JWT demonstrating live possession of the Instance Key, signed with the private half of
`instance_key`:

- Header: `alg` (an asymmetric algorithm; `none` MUST be rejected), `typ`:
  `oauth-attestation-instance-proof+jwt`.
- Claims: `aud` (the CAS issuer identifier, REQUIRED), `iat` (REQUIRED), `exp` (REQUIRED, SHOULD be
  ≤ 5 minutes after `iat`), `jti` (REQUIRED, unique), `challenge` (REQUIRED when
  `challenge_required` is `true`). A deployment MAY require additional **custom claims** in the proof;
  these are advertised in the CAS metadata and governed by Section 5.3.2.

The CAS MUST verify the signature against the presented `instance_key`, validate `aud` against its own
identifier, enforce `exp` with small clock skew, and reject replayed `jti` values within the proof
validity window.

**Why this is not the [ABCA] PoP JWT.** The Instance Key Proof is structurally close to the Client
Attestation PoP JWT, and deliberately mirrors its claim vocabulary (`aud`, `jti`, `challenge`) — but
it carries a distinct `typ`. Reusing `oauth-client-attestation-pop+jwt` here would allow
cross-protocol replay (a captured issuance proof presented at a token endpoint, or vice versa), and
the PoP's `iss` = client identifier presumes an already-attested client, which at issuance time is
exactly what has not yet been established. The distinct `typ` makes the two artifacts mutually
unacceptable by construction.

### 4.4 Processing Rules

Upon receiving an issuance request the CAS MUST:

1. **Resolve the client** via a supported Client Metadata Source (Section 6). Resolution failure, an
   inactive/revoked client, or absence of attestation configuration → `invalid_client`.
2. **Validate the Instance Attestation** with the validator for its format, against the instance
   trust roots established for this client (Section 6.2) — including signature, expiry, and (where the
   format defines one) audience = the CAS. Failure → `invalid_instance_attestation`.
3. **Key-binding cross-check** — if the Instance Attestation itself binds a public key, that key MUST
   equal the presented `instance_key` (compare by JWK thumbprint [RFC7638]). Mismatch →
   `invalid_instance_attestation`.
4. **Match the binding** — the attested instance subject MUST match one of the client's Client
   Bindings. No match → `instance_not_authorized`.
5. **Verify the Instance Key Proof** per Section 4.3. Failure → `invalid_instance_proof`.
6. **Apply policy** (Section 7) to compute the effective `authorization_details`. If the request asks
   for authority exceeding the ceiling → `access_denied` (or, at the CAS's discretion, issuance of the
   narrowed intersection — the choice MUST be consistent and documented in its metadata via
   `narrowing_behavior`: `"reject"` or `"narrow"`).
7. **Mint and sign** the Client Attestation (Section 4.5) with the CAS signing key, and return it.

### 4.5 The Issued Client Attestation

The response:

```json
{ "attestation": "eyJ0eXAiOiJvYXV0aC1jbGllbnQtYXR0ZXN0YXRpb24rand0...", "expires_in": 300 }
```

The `attestation` value MUST be a **Client Attestation JWT as defined by [ABCA]**, which is
authoritative for its structure, required claims, `typ`, and validation; this document does not
respecify them. The CAS populates the [ABCA] claims as follows (a profile, not a redefinition): `iss`
is the CAS identifier, `sub` is the OAuth Client Identifier of the resolved client, `cnf` carries the
attested Instance Key as an RFC 7800 `jwk`, and `exp − iat` SHOULD be short (default 300 s;
Section 8).

This specification defines two **extension claims** carried in issued attestations:

| Claim | Description |
|---|---|
| `workload` | Instance provenance (below). |
| `authorization_details` | The effective (policy-applied) entitlement [RFC9396]. OPTIONAL; absent when the deployment does not use entitlements. |

Per [ABCA], recipients ignore claims they do not understand — so these extensions never break an
[ABCA]-conformant verifier, but they are also not enforced by one. Section 7 states the profile
requirement on authorization servers that makes `authorization_details` binding.

The `workload` claim is a JSON object:

| Member | Description |
|---|---|
| `attested_by` | The Instance Attestation Format that was validated (e.g. `"spiffe"`, `"wallet"`). |
| `subject` | The proven instance subject. Formats MAY additionally emit their native member (e.g. `spiffe_id`, `wallet_instance`). |
| `attributes` | OPTIONAL. Attributes drawn from the matched Client Binding's registered metadata — e.g. `region`, `environment`, `tier`. These are **enrichment**: asserted by the metadata source, never by the requester. |
| `instance_attestation` | OPTIONAL. The validated Instance Attestation, embedded for audit. Deployments SHOULD weigh the privacy cost (Section 9.2). |

A downstream authorization server or resource server can therefore make decisions on *who vouched*
(`iss`), *which client* (`sub`), *which instance and platform* (`workload`), and *what authority was
granted* (`authorization_details`) — with the key binding (`cnf`) preventing use by any other party.

### 4.6 Errors

Errors use HTTP 400 (or 401/403 where noted) with:

```json
{ "error": "instance_not_authorized", "error_description": "spiffe://prod.example/agent-x is not bound to client https://client.example" }
```

| Code | Meaning |
|---|---|
| `invalid_request` | Malformed or missing parameters. |
| `invalid_client` | Unknown, unresolvable, revoked, or unconfigured client. (401) |
| `invalid_instance_attestation` | The Instance Attestation failed validation, or its bound key mismatches `instance_key`. |
| `instance_not_authorized` | Valid attestation, but the subject is not bound to the client. (403) |
| `invalid_instance_proof` | The Instance Key Proof failed (signature, `aud`, expiry, replay, challenge). |
| `access_denied` | The requested `authorization_details` exceed the permitted ceiling. (403) |
| `server_error` | Internal failure. (500) |

---

## 5. Discovery

### 5.1 Client Attestation Service Metadata

A CAS publishes a metadata document at:

```
GET {issuer}/.well-known/client-attestation-service
```

| Field | Required | Description |
|---|---|---|
| `issuer` | REQUIRED | The CAS identifier; MUST equal the `iss` of issued attestations and the URL prefix under which the document was retrieved. |
| `attestation_endpoint` | REQUIRED | URL of the issuance endpoint (Section 4.2). |
| `challenge_endpoint` | OPTIONAL | URL of the challenge endpoint (Section 4.1). |
| `challenge_required` | OPTIONAL | Boolean, default `false`. |
| `jwks_uri` / `jwks` | REQUIRED (one) unless the CAS publishes its keys via OpenID Federation (Section 5.2) | The CAS attestation-signing keys, for validation by authorization servers. |
| `instance_attestation_formats_supported` | REQUIRED | Array of format identifiers, e.g. `["spiffe","wallet"]`. |
| `client_metadata_sources_supported` | OPTIONAL | Array from `["registration","openid_federation","cimd"]`, in the CAS's assurance order. |
| `authorization_details_types_supported` | OPTIONAL | The [RFC9396] `type` values this CAS can evaluate. |
| `narrowing_behavior` | OPTIONAL | `"reject"` (default) or `"narrow"` (Section 4.4 step 6). |
| `attestation_signing_alg_values_supported` | OPTIONAL | JWS algorithms used for issued attestations. |
| `proof_signing_alg_values_supported` | OPTIONAL | JWS algorithms accepted for the Instance Key Proof. |
| `request_parameters_required` | OPTIONAL | The request members the CAS requires (Section 5.3.1); default `["client_id","instance_key","instance_attestation","proof"]`. |
| `proof_claims_required` | OPTIONAL | Claims the Instance Key Proof must carry (Section 5.3.1); default `["aud","jti"]`. MUST include `"challenge"` when `challenge_required` is `true`. |
| `attestation_claims_issued` | OPTIONAL | Claims present in every issued attestation (Section 5.3.1); default `["iss","sub","iat","exp","cnf","workload"]`. |
| `attestation_claims_optional` | OPTIONAL | Claims issued only when applicable; default `["authorization_details"]`. |
| `custom_claims_required` | OPTIONAL | Additional deployment-defined claims the CAS requires in the Instance Key Proof before it will mint (Section 5.3.2). |
| `custom_claims_supported` | OPTIONAL | Deployment-defined claims the CAS understands as policy evidence but does not require (Section 5.3.2). |

### 5.2 Discovery via OpenID Federation

In an OpenID Federation [OIDFED] ecosystem, the CAS is a federation entity. It publishes an Entity
Configuration containing the metadata of Section 5.1 under the entity type identifier
**`oauth_client_attester`**:

```jsonc
"metadata": {
  "oauth_client_attester": {
    "issuer": "https://attester.example.com",
    "attestation_endpoint": "https://attester.example.com/attestation",
    "instance_attestation_formats_supported": ["spiffe", "wallet"],
    "jwks": { "keys": [ /* attestation-signing keys */ ] }
  }
}
```

This yields three properties a bare well-known document cannot:

1. **Verified keys** — an authorization server resolves the CAS's signing keys through a validated
   trust chain to a common trust anchor, instead of trusting TLS alone.
2. **Membership and revocation** — an attester that leaves the federation stops resolving; its
   attestations stop being accepted at chain-validating verifiers.
3. **Cross-domain reach** — one client, with instances in several runtime domains, can be attested by
   any federation-member CAS, and the resulting attestations verify anywhere in the federation.

An instance discovers *which* CAS to call from its client's own metadata: the client's attestation
configuration (Section 6.1) names its `attester`.

### 5.3 Issuance Claims: the Default Set and Custom Claims

Issuance is a claims exchange: the caller supplies claims proving *who is asking*, and the CAS mints
claims stating *what was attested*. This section pins the **default set** every conformant CAS
requires and issues, then defines how a deployment extends it with **custom claims** — without either
side guessing, because both sets are advertised in the metadata document (Section 5.1).

#### 5.3.1 The Default Claim Set

**Request members** (advertised as `request_parameters_required`). A CAS MUST require:

| Member | Purpose |
|---|---|
| `client_id` | Names the client whose binding is claimed (unless the CAS supports reverse resolution, Section 4.2). |
| `instance_key` | The public key to be attested (`cnf`). |
| `instance_attestation` | The proof of instance identity, in a supported format. |
| `proof` | The Instance Key Proof. |

**Instance Key Proof claims** (advertised as `proof_claims_required`). A CAS MUST require:

| Claim | Purpose |
|---|---|
| `aud` | The CAS identifier — prevents cross-service replay. |
| `jti` | Unique id — replay detection within the proof validity window. |
| `challenge` | REQUIRED only when `challenge_required` is `true`; the server-issued single-use challenge. |

`iat` is not listed as required but, when present, MUST be validated for freshness (Section 4.3);
`exp`, when present, MUST be honoured.

**Issued attestation claims** (advertised as `attestation_claims_issued` / `attestation_claims_optional`).
Every attestation contains the [ABCA] base claims `iss`, `sub`, `iat`, `exp`, `cnf`, plus this
specification's `workload` claim; `authorization_details` is added when an entitlement is granted
(Section 4.5). A consumer can therefore rely on the default set without reading the metadata document
— the advertisement exists so tooling can verify, and so extensions (below) are discoverable.

#### 5.3.2 Custom Claims

A deployment frequently needs more than the default set — a build digest before attesting a
production workload, a deployment or tenant identifier for policy routing, a regional marker for data
residency. This specification supports such claims without changing the wire protocol:

1. **Carriage.** Custom claims are carried as **additional claims of the Instance Key Proof**. The
   proof is already signed by the Instance Key, so custom claims arrive integrity-protected and bound
   to the very key being attested — no new parameter, envelope, or signature is introduced.
2. **Advertisement.** The CAS advertises deployment-required claims in `custom_claims_required` and
   understood-but-optional claims in `custom_claims_supported`. Names SHOULD follow JWT claim-naming
   practice ([RFC7519] Section 4.2/4.3: collision-resistant, or established public names).
3. **Enforcement.** A CAS MUST reject a request whose proof lacks a claim listed in
   `custom_claims_required` (or carries it empty) with `invalid_instance_proof`. The effective
   required proof-claim set is `proof_claims_required` ∪ `custom_claims_required`.
4. **Custom claims are evidence, not assertions.** A caller-supplied custom claim is input to the
   issuance decision (Section 7 — including any external PDP consultation), and nothing more. The CAS
   MUST NOT copy caller-supplied custom-claim values into `workload.attributes` or any other issued
   claim unless it has verified them against an authoritative source. This preserves the invariant of
   Section 7 rule 5: the request says *who*; the metadata source and policy decide *what*.

More broadly, the claims consumed at issuance come from three sources with three distinct authorities,
and a deployment's additional requirements may attach to any of them:

| Source | Asserted by | Examples | May the CAS require more of it? |
|---|---|---|---|
| Instance Key Proof | the caller (signed by the Instance Key) | `challenge`, custom evidence (`deployment_id`, `build_digest`) | Yes — via `custom_claims_required`. |
| Instance Attestation | the instance's runtime authority | SPIFFE ID and audience; a WIA's `cnf` | Yes — but such requirements are format-specific and belong to the format's validation profile (Section 10), not to `custom_claims_required`. |
| Client Binding metadata | the client metadata source | `region`, `environment`, entitlements | Yes — as registration-time policy (Section 6); never supplied by the caller. |

Only the third source may populate `workload.attributes`. The first two prove; the third describes.

---

## 6. Associating Instance Identity with an OAuth Client ID

The heart of this specification is the registered, verifiable association:

> *instance subject* ⟷ *OAuth Client Identifier*

It is established in the client's **attestation configuration** and consumed by the CAS at step 4 of
Section 4.4. The requester can never assert it; it can only *prove* an instance subject that the
configuration already binds.

### 6.1 The Client Attestation Configuration

A JSON object, uniform across all metadata sources, registered under the name
**`oauth_client_attestation`**:

```jsonc
"oauth_client_attestation": {
  "attester": "https://attester.example.com",   // the CAS this client uses (minted iss;
                                                //  also the required audience of instance
                                                //  attestations where the format has one)
  "issued_ttl": 300,                            // requested attestation lifetime (s)
  "instance_trust": {                           // trust roots for instance attestations
    "spiffe_trust_bundle": { "keys": [ /* trust-domain JWT authorities */ ] },
    "wallet_providers": [ "https://wallet-provider.example" ]
  },
  "entitlement": [                              // OPTIONAL client-level ceiling (RFC 9396)
    { "type": "sales_agent", "sales_regions": ["EMEA", "APAC"] }
  ],
  "instances": [                                // the Client Bindings
    {
      "subject": "spiffe://prod.example/payments-agent",
      "entitlement": [ { "type": "sales_agent", "sales_regions": ["EMEA"] } ],
      "metadata": { "region": "EMEA", "environment": "prod", "tier": "gold" }
    },
    { "subject": "urn:wallet:instance:abc123" }
  ]
}
```

- `instances[].subject` — the instance subject in the syntax of its format. Format-specific aliases
  (`spiffe_id`, `wallet_instance`) MAY be used and are equivalent.
- `instances[].entitlement` — a per-instance ceiling; MUST be a subset of the client-level
  `entitlement` when both are present (Section 7).
- `instances[].metadata` — attributes copied into the issued `workload.attributes` (enrichment).

### 6.2 Client Metadata Sources and Their Trust

The configuration is identical across sources; **what differs is how it is acquired and what vouches
for it** — and that difference drives what the CAS may believe from it.

| Source | Acquisition | Vouched by | Assurance |
|---|---|---|---|
| **Registration** | provisioned at the CAS / AS (registration API, admin, IaC) | the operator | operator-controlled |
| **OpenID Federation** | the client is an entity; its Entity Configuration carries `oauth_client_attestation`; resolved and chain-validated to the trust anchor | the trust anchor (live membership + revocation) | high |
| **CIMD** [CIMD] | `client_id` is an HTTPS URL; the CAS fetches the Client ID Metadata Document and reads `oauth_client_attestation` | TLS + control of the URL (unsigned) | low — self-asserted |

Rules:

1. A CAS supporting multiple sources SHOULD try them in descending assurance order (federation, then
   CIMD, then local registration for non-URL client identifiers), taking the first that yields a
   configuration.
2. **Federation:** the CAS MUST validate the trust chain from the client entity to a configured trust
   anchor and SHOULD perform a live resolution per issuance (or with a short cache) so that revoking
   the entity's membership revokes issuance within one cache lifetime. The instance trust roots in
   chain-validated metadata MAY be trusted as published, because the anchor vouches for the entity.
3. **CIMD:** the document is unsigned; the CAS MUST NOT accept **instance trust roots** from it —
   otherwise anyone controlling a URL could publish a trust bundle they also control and mint valid
   instance attestations for arbitrary subjects. Under CIMD the trust roots MUST come from the CAS's
   own configured allowlist (e.g. a trust-domain → bundle map), and the document may assert only its
   `instances` and entitlements within them. Fetches MUST enforce the [CIMD] URL validation rules,
   SHOULD apply an SSRF guard (HTTPS only; refuse private/loopback resolution) and a response size cap,
   and MUST confirm the document's `client_id` equals the URL fetched.
4. In all cases the two proofs compose: the *instance's trust root* proves the subject is genuine; the
   *client's metadata source* proves the subject is bound to the client. Neither alone suffices.

---

## 7. Policy: Down-Scoping at Issuance

The CAS is a policy enforcement point. The authority carried in an issued attestation is computed as:

```
effective = requested ∩ ceiling(instance)          where
ceiling(instance) = instances[i].entitlement       if present
                  = entitlement (client-level)      otherwise
and instances[i].entitlement ⊆ entitlement MUST hold at registration time.
```

Normative rules:

1. The issued `authorization_details` MUST be a subset of the applicable ceiling. Subset semantics are
   defined per `authorization_details` `type`, following [RFC9396]: for a candidate to be within the
   ceiling there must be a ceiling object of the same `type` whose constraints it does not exceed
   (arrays: subset; numeric limits: ≤; absent ceiling field: unconstrained).
2. An empty or absent `authorization_details` request means the instance asks for its **full ceiling**;
   the CAS issues the ceiling of the matched binding. (This makes the common case one round trip while
   keeping least-privilege available to instances that want it.)
3. A request exceeding the ceiling is handled per the advertised `narrowing_behavior`: `"reject"` →
   `access_denied`; `"narrow"` → issue the intersection.
4. The CAS MAY consult an **external Policy Decision Point** — for example an OpenID AuthZEN [AUTHZEN]
   PDP — to further constrain (never widen) the result, using the proven instance subject,
   `workload.attributes`, client identifier, and requested details as decision inputs. This admits
   context-dependent down-scoping (time of day, risk signals, environment) without changing the wire
   contract.
5. Attributes in `workload.attributes` are drawn exclusively from the matched binding's registered
   `metadata` (and CAS-side policy). The CAS MUST NOT copy caller-supplied values into them. An
   instance can prove *who* it is; only the metadata source and policy decide *what it is like* and
   *what it may do*.

### 7.1 Authorization Server Profile Requirement

The `authorization_details` attestation claim is an extension (Section 4.5); an [ABCA]-conformant
authorization server that does not implement this specification will ignore it, and the ceiling would
then constrain nothing beyond issuance. Therefore: an authorization server participating in a
deployment of this specification **MUST**, when authenticating a client via an attestation containing
`authorization_details`, ensure that any authority granted in issued tokens is a subset of the
attestation's `authorization_details` (same subset semantics as Section 7 rule 1), and MUST reject
requests exceeding it with `invalid_authorization_details` [RFC9396].

This completes the down-scoping chain — **registration ceiling → attested authority → token
authority**, monotonically non-increasing — with each hop enforced by a different party (the metadata
source, the CAS, the AS).

---

## 8. Lifetime, Rotation and Revocation

- **Two lifetimes, one key.** The Instance Key lives as long as the instance and is never re-issued;
  the Client Attestation over it is short-lived (RECOMMENDED default 300 seconds, configurable per
  client via `issued_ttl`, capped by CAS policy).
- **Refresh = re-attest.** The instance refreshes by re-calling the issuance endpoint with a *fresh*
  Instance Attestation. Refresh therefore re-checks, every time: the instance's standing with its
  runtime authority, the client's standing with its metadata source, the binding, and policy.
- **Revocation levers**, in increasing blast radius: remove one binding (that instance stops
  re-attesting); revoke the client at its metadata source (all instances stop); rotate the instance
  trust root (the runtime domain stops); remove the CAS's federation membership (everything it signed
  stops verifying at chain-validating parties).
- Deployments SHOULD choose `issued_ttl` as their revocation-latency bound: with a 300-second TTL, a
  deauthorized instance holds usable credentials for at most five minutes, with no per-request
  revocation traffic at the AS.

---

## 9. Security Considerations

### 9.1

- **Attestation ≠ bearer credential.** An issued attestation is useless without the Instance Key: the
  AS requires the [ABCA] PoP. Interception of the issuance response alone grants nothing.
- **Key substitution.** Step 3 of Section 4.4 (bound key = presented key) prevents presenting a valid
  Instance Attestation for one key while enrolling a different key it does not attest.
- **Replay.** The Instance Key Proof's `jti` MUST be tracked for one-time use within its validity
  window; the challenge (when required) MUST be single-use. Instance Attestation formats with audience
  restriction MUST be validated with the CAS as audience.
- **Self-asserted metadata.** The CIMD constraints of Section 6.2 rule 3 are load-bearing: an unsigned
  document must never be able to introduce a trust root.
- **Signing-key protection.** The CAS signing key SHOULD be held in an HSM/KMS/transit signer such
  that the private key never enters the CAS application process. Per-client signing keys limit the
  blast radius of a key compromise to one client's attestations.
- **Confused deputy.** `aud` on the Instance Key Proof (and on audience-bearing Instance Attestations)
  MUST be the CAS itself, so material presented here cannot be relayed from or to another service.
- **Requested-scope injection.** The `authorization_details` request parameter is an untrusted input;
  it can only shrink the result (Section 7). Implementations MUST NOT treat any caller-supplied field
  as an attribute assertion.

### 9.2 Privacy Considerations

`workload.attributes` and an embedded `instance_attestation` can expose infrastructure topology
(cluster names, regions, provider identifiers) to every party that reads the attestation. Deployments
SHOULD register only attributes that downstream authorization actually uses, and SHOULD omit the raw
Instance Attestation from issued tokens unless audit requirements demand it.

---

## 10. Registries (IANA / OIDF Considerations)

This specification would register:

1. **`typ` value:** `oauth-attestation-instance-proof+jwt` (the Instance Key Proof, Section 4.3).
2. **JWT claim:** `workload` (Section 4.5).
3. **OAuth client metadata / OpenID Federation metadata:** the `oauth_client_attestation` client
   configuration object (Section 6.1) and the `oauth_client_attester` federation entity type
   (Section 5.2).
4. **Well-known URI:** `client-attestation-service` (Section 5.1).
5. **An Instance Attestation Format registry**, seeded with `spiffe` and `wallet`, with a defined
   template: format identifier, encoding, validation procedure, subject syntax, whether a key is
   bound, trust-root model. New formats (e.g. platform key attestation, WebAuthn) are added without
   changes to this API.

Nothing owned by [ABCA] is re-registered: `oauth-client-attestation+jwt`, the PoP `typ`, the
`attestation_challenge` parameter, the `OAuth-Client-Attestation-Challenge` header, and
`attest_jwt_client_auth` are [ABCA] registrations that this specification reuses by reference. The
`authorization_details` JWT claim is registered by [RFC9396].

---

## 11. References

### 11.1 Normative

- **[RFC2119] / [RFC8174]** — Key words for use in RFCs.
- **[RFC6749]** — The OAuth 2.0 Authorization Framework.
- **[RFC7515] / [RFC7517] / [RFC7519] / [RFC7638]** — JWS, JWK, JWT, JWK Thumbprint.
- **[RFC7800]** — Proof-of-Possession Key Semantics for JWTs (`cnf`).
- **[RFC9396]** — OAuth 2.0 Rich Authorization Requests.
- **[ABCA]** — OAuth 2.0 Attestation-Based Client Authentication,
  draft-ietf-oauth-attestation-based-client-auth.
- **[OIDFED]** — OpenID Federation 1.0.

### 11.2 Informative

- **[CIMD]** — OAuth Client ID Metadata Document, draft-ietf-oauth-client-id-metadata-document.
- **[SPIFFE]** — SPIFFE / SPIRE: Secure Production Identity Framework, JWT-SVID and Trust Domain &
  Bundle specifications.
- **[HAIP]** — OpenID4VC High Assurance Interoperability Profile (Wallet Instance Attestation).
- **[AUTHZEN]** — OpenID AuthZEN Authorization API.
- **[WebAuthn]** — W3C Web Authentication.
- **[WIMSE]** — IETF Workload Identity in Multi System Environments (WG documents), including
  draft-ietf-wimse-workload-creds (the Workload Identity Token, `typ` `wit+jwt`).
- **[SPIFFE-CLIENT-AUTH]** — SPIFFE Client Authentication for OAuth 2.0,
  draft-ietf-oauth-spiffe-client-auth. Presents an SVID directly at the token endpoint; see Section 1.1
  for how that differs from the exchange this document defines.
- **[RFC8705]** — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.
- **[RFC9449]** — OAuth 2.0 Demonstrating Proof of Possession (DPoP).

---

## Appendix A. Example: SPIFFE-Attested Agent (Informative)

Request:

```http
POST /attestation HTTP/1.1
Host: attester.example.com
Content-Type: application/json

{
  "client_id": "https://client.example/payments",
  "instance_key": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" },
  "instance_attestation_format": "spiffe",
  "instance_attestation": "eyJhbGciOiJFUzI1NiIsImtpZCI6InNwaXJlLTEifQ…",
  "proof": "eyJ0eXAiOiJvYXV0aC1hdHRlc3RhdGlvbi1pbnN0YW5jZS1wcm9vZitqd3QiLCJhbGciOiJFUzI1NiJ9…"
}
```

Issued attestation (decoded payload):

```jsonc
{
  "iss": "https://attester.example.com",
  "sub": "https://client.example/payments",
  "iat": 1783200000,
  "exp": 1783200300,
  "cnf": { "jwk": { "kty": "EC", "crv": "P-256", "x": "…", "y": "…" } },
  "workload": {
    "attested_by": "spiffe",
    "subject": "spiffe://prod.example/payments-agent",
    "spiffe_id": "spiffe://prod.example/payments-agent",
    "attributes": { "region": "EMEA", "environment": "prod", "tier": "gold" }
  },
  "authorization_details": [
    { "type": "sales_agent", "sales_regions": ["EMEA"], "max_txn_eur": 5000 }
  ]
}
```

Everything under `workload.attributes` and `authorization_details` was **added by the CAS** from the
client's registered binding and policy — the request could not assert any of it.

## Appendix B. Document History

- **draft 00** — initial individual draft, generalised from a running implementation (SPIFFE and
  wallet instance formats; registration, OpenID Federation, and CIMD metadata sources; OpenBao-transit
  signing; entitlement-ceiling policy). Revised to make [ABCA] fully authoritative for the attestation
  artifacts: base claims deferred rather than respecified, challenge vocabulary aligned
  (`attestation_challenge`), distinct instance-proof `typ` rationale added, and an AS profile
  requirement added for `authorization_details` enforcement.
