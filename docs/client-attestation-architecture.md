# Client Attestation — architecture, state, and gaps

What the client attestation pipeline is, what it does today, which standards it meets, what proves
that, and what is still missing. Written from the source on 2026-08-17, not recalled: every claim
below was read at the file it describes, and every test count came from a surefire run, not a grep.

This is the map. It does not restate the specs (see
[openid-client-attestation-service-1_0.md](openid-client-attestation-service-1_0.md)), the claim
layouts ([claim-dictionary.md](claim-dictionary.md)), or the per-module detail (the module READMEs) —
it says how they fit together and where the edges are.

---

## 1. What this is

An agent instance is ephemeral. It gets scheduled, runs, and dies; there is no sensible way to hand it
a client secret, and one registered OAuth client per running pod is not identity, it is an inventory
problem. So the pipeline splits the job in two.

**Issuance.** The instance proves *what it is* — a SPIFFE JWT-SVID, a GKE/EKS/AKS/Azure/GCP workload
token, or a Wallet Instance Attestation — to a **Client Attester**, and proves possession of a key it
just generated. The attester reverse-maps that evidence onto a registered OAuth client and mints a
short-lived **Client Attestation** JWT: `sub` = the client id, `cnf.jwk` = the instance's own key,
plus the workload facts and an RFC 9396 entitlement ceiling.

**Verification.** The instance then authenticates at PingFederate's token endpoint with that
attestation plus a fresh proof of possession — `attest_jwt_client_auth`. The attestation is the only
credential. No secret ever reaches the instance, the credential expires in minutes, and the authority
it can ask for is bounded at mint time rather than argued about at the token endpoint.

Both halves implement `draft-ietf-oauth-attestation-based-client-auth-10`. The issuance half has no
equivalent in that draft — the draft starts once the client already holds an attestation — so this
repo wrote the missing half up as its own spec draft, published in
[openid-client-attestation-service-1_0.md](openid-client-attestation-service-1_0.md).

---

## 2. Architecture

### 2.1 Components, by pipeline position

| Position | Module | Role | Artifact |
|---|---|---|---|
| Issue | `servlets/attestation-issuer` | The Client Attester: issuance endpoint, evidence validators, discovery, minting, per-client signing keys | `attestation-issuer-0.1.0.jar` |
| Issue (device) | `libs/device-instance`, `libs/app-attest`, `services/device-enrolment` | The device-resident path: App Attest → enrolment → instance registry → device attestation minter | `device-instance-0.1.0.jar`, `app-attest-0.1.0.jar`, `device-enrolment-0.1.0.jar` |
| Identity | `libs/agent-registry` | Mints/resolves `agent_id`, the per-running-instance pseudonym | `agent-registry-0.1.0.jar` |
| Verify | `libs/client-attestation` | The AS-side verifier, DPoP validation, challenge + replay stores, RAR containment | `client-attestation-0.1.0.jar` |
| Verify (trust) | `libs/openid-federation` | Attester trust via OpenID Federation trust chains; AS capability advertisement | `openid-federation-0.1.0.jar` |
| Enforce | `servlets/pf-integration` | The `/as/token.oauth2` filter, the OGNL issuance criterion and claim hooks, PF client store | `oidf.jar` |
| Consume | `plugins/rar-paz-plugin` | Bounds the PingAuthorize RAR decision by the attested ceiling | `pf.plugins.pf-rar-paz-plugin.jar` |
| Consume (RS) | `services/demo-rs` | Resource-server side: AS signature, DPoP proof, `cnf.jkt` equality, RFC 8693 `act` chain | `demo-rs-0.1.0.jar` |

Three of these load into PingFederate and the classloader they land on matters. `oidf.jar`,
`attestation-issuer` and their libraries are merged into `pf-runtime.war` at root context by
[`assemble-pf-runtime-war.sh`](../build/pingfederate/assemble-pf-runtime-war.sh) — that is why
`/federation/attestation` serves with no `/oidf` prefix. The same jars are *also* copied into
`server/default/deploy/` by the [Dockerfile](../build/pingfederate/Dockerfile), because the OGNL
hooks run on PF's engine classloader, which cannot see `pf-runtime.war/WEB-INF/lib`.

### 2.2 Issuance flow

```mermaid
sequenceDiagram
    participant W as Workload / instance
    participant A as Attester (attestation-issuer)
    participant R as AgentRegistry
    participant V as OpenBao transit

    W->>A: POST /federation/attestation-challenge (optional)
    A-->>W: {attestation_challenge, expires_in}
    W->>W: generate instance key; sign instance-key proof
    W->>A: POST /federation/attestation<br/>{instance_key, instance_attestation, proof, [authorization_details], [asserted_context]}
    A->>A: resolve client FROM EVIDENCE (try each client's trust config)
    A->>A: validate instance-key proof: sig under presented JWK, typ, aud,<br/>challenge consume, jti replay
    A->>A: custom proof claims; WIA cnf must equal instance_key
    A->>A: workload introspection; asserted-context narrowing (intersect only)
    A->>A: RAR ceiling — RarEntitlement.authorize(requested, ceiling)
    A->>R: resolveOrMint(iss, client_id, format, subject)
    R-->>A: agent_id
    A->>V: sign (or inline JWK, dev)
    V-->>A: signature
    A-->>W: 200 {attestation, expires_in}  Cache-Control: no-store
```

The step worth pausing on is the first one inside the attester. **The workload never names a client.**
It presents only its evidence; the attester tries every attestation client's trust config, and the
client whose bundle cryptographically verifies the evidence *and* whose bindings contain the resulting
identity is the match. A `client_id` in the body is accepted and ignored. Two clients matching the same
identity is a configuration fault and is rejected rather than resolved arbitrarily
([`AttestationIssuanceServlet:569-641`](../servlets/attestation-issuer/src/main/java/com/pingidentity/ps/oidf/servlet/attestation/AttestationIssuanceServlet.java#L569)).

An `agent_id` anywhere in the request — top level or smuggled inside an `authorization_details` entry —
is rejected outright, not ignored (`:699`, `:756`). It is the attester's to mint.

### 2.3 Token-endpoint flow

```mermaid
sequenceDiagram
    participant W as Workload / instance
    participant F as ClientAttestationAuthFilter<br/>(webapp classloader)
    participant PF as PingFederate token endpoint
    participant O as OGNL issuance criterion<br/>(engine classloader)
    participant P as PingAuthorize (via RAR plugin)

    W->>F: POST /as/token.oauth2<br/>OAuth-Client-Attestation + (PoP | DPoP)
    alt no attestation header
        F->>PF: pass through untouched
    else attestation present
        F->>F: ClientAttestationVerifier.verify(...)
        F->>F: mint bridge client_assertion (ES256, iss=sub=client_id)
        F->>PF: forward with client_id + client_assertion,<br/>client_secret dropped, Authorization suppressed
    end
    PF->>PF: native private_key_jwt authentication
    PF->>O: access-token mapping issuance criterion
    O->>O: verify the SAME attestation again (own replay cache)
    O->>P: publish attestation context (request attribute)
    P-->>PF: bounded authorization_details
    PF-->>W: access token (cnf.jkt bound; act chain)
```

**Why a servlet Filter and not an SDK plugin.** PingFederate has no native support for
`attest_jwt_client_auth` and no SDK extension point for client authentication. The filter is
registered by web.xml surgery in the deploy image, and the assemble script asserts the mapping is
present or fails the build
([`assemble-pf-runtime-war.sh:136-140`](../build/pingfederate/assemble-pf-runtime-war.sh#L136)).

**Why it is verified twice.** The filter runs on the webapp classloader; the OGNL criterion runs on
the engine classloader. They cannot share a replay cache unless Redis is configured, so each sees a
given PoP `jti` exactly once per request and a genuine replay fails in both. This is deliberate, and
documented at
[`ClientAttestationAuthFilter:50-55`](../servlets/pf-integration/src/main/java/com/pingidentity/ps/oidf/servlet/clientregistration/ClientAttestationAuthFilter.java#L50).

**Fail-closed, and the one way it is not.** An invalid attestation is rejected at the filter with the
draft's error codes and never reaches PF; an internal error returns 500 rather than falling through
credential-less. A request with *no* attestation header passes through untouched, so the filter can
never widen access — PF still enforces whatever that client is configured for. The exception is the
bridge key: if `OIDF_BRIDGE_PRIVATE_JWK` is unset, an attestation-bearing request also passes through
unbridged, with a warning. That is not a security hole (PF then rejects it for want of a credential),
but it does mean the whole method is silently inert on a deployment that forgot the variable. See §6.

### 2.4 The three key hierarchies

Easy to conflate, so stated separately.

| Hierarchy | Who holds the private key | Configured by | Code |
|---|---|---|---|
| **Attester signing** — signs the minted attestation | The attester, per client | `attestation_signing_key_ref` (OpenBao transit, key never leaves the vault) **or** `attestation_signing_jwk` (inline, dev). Exactly one | `AttesterSigningKey` |
| **Instance key** — signs the PoP/DPoP, and the issuance-time proof | The instance itself; generated locally, public half carried as `cnf.jwk` | nothing — presented per request | `InstanceKeyProofValidator`, `DpopProofValidator` |
| **Bridge key** — signs the `client_assertion` the filter hands PF | The PF deployment, one key | `OIDF_BRIDGE_PRIVATE_JWK` / `oidf.bridge.private.jwk` (EC private JWK), public half registered in **every** attestation client's JWKS | `ClientAttestationAuthFilter:164-188` |

Attester *trust* on the AS side is a fourth, separate thing: `FederationAttesterKeyResolver` walks an
OpenID Federation trust chain from the attester to the anchor; `StaticAttesterKeyResolver` is a
pre-registered map marked dev/demo only; `FallbackAttesterKeyResolver` tries the static list first and
federation for everything else.

The bridge key deserves its own note because it is the least documented and the most load-bearing. It
is a **single deployment-held key that can mint a `private_key_jwt` for any attestation client** — it
is registered in all of their JWKS. Compromise it and you can authenticate as any of them without any
attestation at all. The filter also suppresses the `Authorization` header on the bridged request
(`BridgeAuthRequest:262-271`) so PF cannot read stale Basic credentials that no longer match the
injected parameters, and drops `client_secret` for the same reason.

### 2.5 Client metadata resolution

Before the attester can reverse-map evidence onto a client, it needs the set of attestation clients and
each one's issuance config — evidence type, trust bundle, bindings, ceiling, signing key. The CAS spec
draft (§6.2) names three sources and ranks them by who vouches for the metadata: **OpenID Federation**
(the trust anchor vouches — high), **CIMD** (an unsigned document at an HTTPS URL — low, self-asserted),
and **local registration** (the operator vouches). The spec says try them in that order, first hit wins.

What the code does
([`AttesterResolvers:40-58`](../servlets/attestation-issuer/src/main/java/com/pingidentity/ps/oidf/servlet/attestation/AttesterResolvers.java#L40)):

| Order | Source | Enabled by | Produces config via | Vouched by, in practice |
|---|---|---|---|---|
| 1 | CIMD | `OIDF_ATTESTER_CIMD_URL` | `CimdClientResolver` → `CimdMapping.toConfig` | TLS + control of the URL. **Nothing else** — see §6 |
| 2 | OpenID Federation entity | `OIDF_ATTESTER_FEDERATION_ENTITY` | `OpenIdFederationClientResolver` → `CimdMapping.toConfig` | The entity's **own self-signature**. Not the anchor — no trust chain is walked |
| 3 | PF client store | always | `PfIssuanceClientResolver` → `AttestationIssuanceConfig.fromProperties` | The operator, via `attestation_*` extended properties; `isEnabled()` filtered |

Three things to know about the chain, all of which shape §6:

- **The order is inverted against the spec.** CIMD — the lowest-assurance source — is tried first.
  Resolution is first-match per client id with no field-level merge (`ChainClientResolver:48-67`), so
  a client id present in both CIMD and the PF store yields the CIMD copy, whole.
- **Both external sources funnel through `CimdMapping.toConfig`**, which builds a config with exactly
  one binding and **never sets a client-level ceiling** — so the instance-⊆-client containment rule
  in `AttestationIssuanceConfig:292-300`, which is guarded on a non-empty client ceiling, is a no-op
  for them.
- **Registration status is a PF-store concept only.** `PfIssuanceClientResolver:77` drops disabled
  clients before they can match. CIMD and federation have no status: presence in the document is the
  whole gate, and the 300 s cache serves stale indefinitely on fetch failure. There is no check on any
  path that the client is registered for `attest_jwt_client_auth` — on PF the bridge means every
  working client is registered as `private_key_jwt`, so a naive check would reject all of them; the
  signal `PfIssuanceClientResolver:82` actually uses is the presence of `attestation_issuer`.

---

## 3. What is implemented

### 3.1 Surfaces

| Method + path | Class | Notes |
|---|---|---|
| `POST /federation/attestation` | `AttestationIssuanceServlet` | Issuance. `200 {"attestation","expires_in"}`, `Cache-Control: no-store` |
| `POST /federation/attestation-challenge` | `ClientAttestationChallengeServlet` | Ships in the `client-attestation` jar, not the issuer. `{"attestation_challenge","expires_in"}` |
| `GET /.well-known/client-attester`, `/federation/.well-known/client-attester` | `AttesterConfigurationServlet` | Deployment discovery: endpoints, evidence types read off the validator registry, `evidence_audience`, `pop_audience`, active resolver plugins |
| `GET /federation/attester-configuration?client_id=` | same | Per-client view: issuer, evidence audience, trust domain, RAR type names. Ceiling, bindings and signing config deliberately withheld |
| `GET /.well-known/client-attestation-service` | `ClientAttestationServiceMetadataServlet` | The CAS 1.0 §5 document. Reads the same config the issuance servlet enforces, so advertisement cannot drift from enforcement |
| Filter over `/as/token.oauth2` | `ClientAttestationAuthFilter` | Registered as `ClientAttestationAuth` by the deploy image |

### 3.2 Verification pipeline

In order, from `ClientAttestationVerifier.verify` — the ordering is the point, authentication
completes before any authorisation happens:

1. `OAuth-Client-Attestation` required. Exactly one of `OAuth-Client-Attestation-PoP` or `DPoP`; both
   or neither is `invalid_client`.
2. A `~` anywhere in the attestation is refused — that is the retired SD-JWT presentation encoding.
3. Attestation: `typ` must be `oauth-client-attestation+jwt`; `iss` resolves the attester's keys
   through `AttesterKeyResolver` (using a `trust_chain` JWS header if present); expiry maps to
   `use_fresh_attestation`, not a generic failure.
4. `cnf.jwk` asserted public-only. A `client_id` request parameter, if present, must equal `sub`.
5. Required-disclosure policy: any claim in `requiredDisclosedClaims` (`workload`,
   `authorization_details`) must be present and non-empty, else `insufficient_disclosure`.
6. Proof of possession:
   - **PoP mode** — `typ=oauth-client-attestation-pop+jwt`, verified under the `cnf` key; `aud` must be
     in the accepted set (an *empty* accepted set is `invalid_client` "Server misconfigured", not a
     pass); PoP `iss`, when present, must equal `sub`; `iat` freshness with skew; challenge consumed;
     `jti` replay-checked.
   - **DPoP combined mode** — full RFC 9449 validation, then `Jwks.assertSameKey(cnf, proof.jwk)`;
     the challenge comes from `nonce`; `jti` replay-checked.
7. *Then* authorisation: `RarEntitlement.authorize(requested, entitled)`.

`DpopProofValidator` explicitly does not do replay or challenge binding — those are the caller's, and
the verifier supplies them.

### 3.3 Issuance pipeline

From `AttestationIssuanceServlet.issue`: require `instance_key` / `svid` (alias
`instance_attestation`) / `proof` → resolve the client from evidence → validate the instance-key proof
(signature under the *presented* JWK, `typ`, `aud` = attester issuer, challenge consume, `jti` replay
at 300s) → deployment-required custom proof claims (evidence for policy only, never copied into the
minted JWT) → if the evidence binds a key (a WIA `cnf`) it must equal `instance_key` → workload
introspection merged over binding metadata → optional asserted-context resolution, **intersected**
into the ceiling and never unioned → RAR ceiling (`authorize`, or the full ceiling when nothing was
requested) → `agent_id` → mint and sign.

One thing the code comments promise and the code does not deliver: step 6 reads "resolve the granted
entitlement against the effective ceiling, then apply any selector-conditioned downscoping the policy
requires" (`AttestationIssuanceServlet:217-218`). Only the first clause exists. The introspected
selectors and the binding's metadata (`version`, region, whatever the operator declared) are merged
into `workloadAttributes` and passed to the minter as `workload.attributes` — they are **never read by
any ceiling computation**. The only narrowing that happens is the asserted-context intersection, and
that is keyed on a caller-supplied discriminator, not on evidenced attributes. See §6 and §8.

The `agent_id` policy is three-valued on purpose: no registry configured at all means no claim and
issuance proceeds (back-compatible); a registry that is configured but fails is `server_error`. It
never silently issues an attestation without an agent identity once you have opted in.

### 3.4 Evidence catalogue

`InstanceAttestationValidators.defaults()` — the id is the client's `attestation_evidence`:

| Id | Validator | Format family |
|---|---|---|
| `spiffe-jwt` | `SpiffeInstanceAttestationValidator` | `spiffe` |
| `gke-sa-token` | `GkeTokenValidator` | `spiffe` |
| `gcp-id-token` | `GcpSaTokenValidator` | `spiffe` |
| `eks-sa-token` | `EksTokenValidator` | `spiffe` |
| `aws-sts-web-identity` | `AwsStsWebIdentityValidator` | `spiffe` |
| `aks-sa-token` | `AksWorkloadIdentityValidator` | `spiffe` |
| `azure-mi-token` | `AzureManagedIdentityValidator` | `spiffe` |
| `wallet-instance-attestation` | `WalletInstanceAttestationValidator` | `wallet` |

The wallet entry is registered with an **unconfigured key resolver** so the id is always discoverable
and config-validatable, and any actual WIA fails loudly until wallet-provider trust is configured.
Adding an evidence type means registering one plugin — supported-types, trust-domain requirements and
the discovery document are all derived from this registry.

### 3.5 Error codes

Issuance (`IssuanceException`) and verification (`ClientAttestationException`):

| Issuance code | HTTP | | Verification code |
|---|---|---|---|
| `invalid_request` | 400 | | `invalid_client` |
| `invalid_client` | 400 | | `use_attestation_challenge` |
| `invalid_svid` | 401 | | `use_fresh_attestation` |
| `invalid_instance_attestation` | 401 | | `invalid_authorization_details` |
| `invalid_instance_proof` | 401 | | `access_denied` |
| `spiffe_id_not_authorized` | 403 | | `insufficient_disclosure` |
| `instance_not_authorized` | 403 | | |
| `access_denied` | 403 | | |
| `server_error` | 500 | | |

At the filter, `use_attestation_challenge` returns 400 and everything else 401; an internal error is
500 `server_error`.

### 3.6 Configuration

**Per-client PF extended properties — verification** (read by `ClientAttestationUtils` as
`extproperties.*`): `attestation_pop_max_age`, `attestation_dpop_max_age`, `attestation_clock_skew`,
`attestation_challenge_required`, `attestation_expected_htu`, `attestation_accepted_algs`,
`attestation_pop_algs`, `attestation_dpop_algs`, `attestation_required_claims`. Defaults come from
`ClientAttestationConfig`: skew 60 s, PoP and DPoP max age 300 s, asymmetric algorithms only
(`RS*`/`PS*`/`ES*`/`EdDSA` — no `none`, no MACs), challenge not required, no required disclosures.

`attestation_required` is written onto a client by `RegistrationService` and declared in terraform, but
**nothing reads it** — verification is driven by the presence of the headers, not by a flag.

**Per-client PF extended properties — issuance** (`AttestationIssuanceConfig`): `attestation_issuer`,
`attestation_issued_ttl`, `attestation_spiffe_bundle`, `attestation_bundle_url`,
`attestation_entitlement`, `attestation_signing_key_ref`, `attestation_signing_jwk`,
`attestation_instances`, `attestation_trust_domain`, `attestation_evidence`,
`attestation_evidence_issuer`, `attestation_asserted_context_resolver`.

**Environment / system properties** (sysprop first, then env):

| Setting | Effect | Set in the checked-in deploy config? |
|---|---|---|
| `oidf.redis.url` → `OIDF_REDIS_URL` → `REDIS_URL` | Cluster-wide challenge + replay store. Unset = per-node in-memory | No — a resource of whichever environment deploys this, so set outside this repo |
| `OIDF_BRIDGE_PRIVATE_JWK` / `oidf.bridge.private.jwk` | The filter's bridge signing key. Unset = every attestation request passes through unbridged | **No** — named only in a comment in the assemble script |
| `oidf.mock.attesters` | Static attester trust, bypassing federation trust chains | **Yes** — written into `run.properties.subst.default` by the Dockerfile |
| `oidf.attestation.required.claims` | Global required-disclosure default | Yes — `workload`, via the Dockerfile |
| `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` | Attester trust chain resolution (AS side). Required even in mock mode, or token-endpoint attestation auth NPEs | Yes — staging and production |
| `OIDF_TRUST_CONTROLLER_HOST` + `OIDF_ATTESTER_OP_ISSUER` | Federation-backed **wallet-provider** trust (note: a different variable from the line above) | No |
| `OIDF_WALLET_PROVIDER_JWKS` | Static wallet-provider trust map | No |
| `OIDF_ATTESTER_CIMD_URL`, `OIDF_ATTESTER_FEDERATION_ENTITY`, `OIDF_ATTESTER_SIGNING_JWK` | Extra client-metadata sources | No |
| `OIDF_ATTESTER_SPIRE_ENTRIES_URL` | SPIRE selector introspection; unset = no-op introspector | No |
| `OIDF_ENTRA_AGENT_DIRECTORY` | Registers the Entra asserted-context resolver | No |
| `OIDF_ATTESTATION_SUB=client_id` + `OIDF_AGENT_CLIENT_ID` | Device path: flips `sub` to the registered client id (divergence 5). Flag without the client id refuses to start | No |

**Servlet init-params**: `challengeRequired`, `customClaimsRequired` / `customClaimsSupported`,
`challengeEndpointEnabled`, `attestationSigningAlgValuesSupported`, `openBaoUrl` / `openBaoToken`,
`challengeCacheMaxEntries`, `challengeTtlSeconds`, `replayCacheMaxEntries`.

### 3.7 Storage

`AttestationSupport` holds process-wide singletons so the challenge endpoint and the token-endpoint
hook share state across classloaders. With no Redis URL it is per-node LRU+TTL
(`InMemoryAttestationChallengeService` / `InMemoryAttestationReplayCache`, defaults 8192 entries /
300 s). With one, `RedisAttestationStore` implements both interfaces over `MiniRedisClient`, a
dependency-free RESP client: issue is `SET … EX`, consume is `DEL`, first-seen is `SET … NX EX`.
**Unreachable Redis fails closed** — availability is never traded for a replayable credential.

---

## 4. Standards alignment

Status vocabulary: **Implemented** — the clause is met; **Partial** — met on one path or under
configuration that is not the default; **Divergence** — deliberate, defended in
[claim-dictionary.md](claim-dictionary.md); **Extension** — no spec equivalent exists; **Not
implemented** — stated so it is not mistaken for coverage.

### 4.1 `draft-ietf-oauth-attestation-based-client-auth-10`

| Requirement | Where | Status |
|---|---|---|
| Attestation JWT `typ=oauth-client-attestation+jwt` | `ClientAttestationVerifier:38`, `AttestationMinter:31` | Implemented |
| `sub` names the OAuth client | `AttestationMinter` (workload path, always); `DeviceAttestationMinter` (device path, behind a flag) | Partial — divergence 5 |
| `cnf.jwk`, public-only, REQUIRED | `Jwks.assertPublicOnly`, `AttestationMinter` | Implemented |
| `exp` REQUIRED; expiry ⇒ `use_fresh_attestation` | `verifyAttestation` | Implemented |
| `iss` removed in -08 | Retained | Divergence 1 |
| PoP JWT `typ=oauth-client-attestation-pop+jwt`, `aud`, `jti`, `iat` | `verifyPopMode` | Implemented |
| `attest_jwt_client_auth` at the token endpoint | `ClientAttestationAuthFilter` | Implemented |
| `attest_jwt_client_auth_dpop` / `dpop_combined`, DPoP key = `cnf` key | `verifyDpopMode`, `Jwks.assertSameKey` | Implemented |
| Both proof headers, or neither, is an error | `verify:91-98` | Implemented |
| Challenge endpoint (§6.1) and `use_attestation_challenge` | `ClientAttestationChallengeServlet`, `enforceChallenge` | Implemented, off by default |
| Error codes `invalid_client` / `use_attestation_challenge` / `use_fresh_attestation` | `ClientAttestationException` | Implemented |
| SD-JWT presentation encoding (retired) | Actively refused | Implemented |
| Attester trust establishment (§9.8, out of scope in the draft) | `FederationAttesterKeyResolver` | Extension |
| Single-use attestation | Reused within the 15-minute window | Divergence 2 |
| Per-instance identity claim | `agent_id` | Extension — divergence 5 |
| Instance-key proof at issuance (`oauth-attestation-instance-proof+jwt`) | `InstanceKeyProofValidator` | Extension — the draft has no issuance side |

### 4.2 The OAuth RFCs

| Requirement | Where | Status |
|---|---|---|
| RFC 9449 DPoP: `typ=dpop+jwt`, self-signature under the `jwk` header, alg allowlist, `htm`/`htu`, `iat`, `jti` | `DpopProofValidator` | Implemented |
| RFC 9449 replay of the DPoP proof | Caller's job; supplied by the verifier, **not** by `services/demo-rs` | Partial |
| RFC 9396 `authorization_details` containment (`type` match, subset on `actions`/`locations`/`datatypes`/`privileges`/`sales_regions`) | `RarEntitlement`, `RarContainment` | Implemented |
| RFC 9396 processing at issuance (`AuthorizationDetailProcessor`) | `plugins/rar-paz-plugin` | Implemented |
| RFC 8693 `act` as a JSON object; outermost actor only is authorisable | `delegationActChain`, `services/demo-rs` `ActChain` | Partial — PF's ability to emit a nested object is unresolved, see `unverified.md` item 8 |
| RFC 7800 `cnf` | Attestation `cnf.jwk`; access token `cnf.jkt` | Implemented |
| RFC 7515 / 7517 / 7519 / 7638 | `libs/oidf-jose` throughout | Implemented |
| RFC 8705 mTLS client authentication | — | Not implemented |
| RFC 9126 PAR | — | Not implemented |
| FAPI 2.0 Security Profile | — | **Not assessed.** No FAPI reference exists anywhere in the repo |

### 4.3 OpenID Federation 1.0 (Final, 17 Feb 2026)

| Requirement | Where | Status |
|---|---|---|
| Attester keys resolved through a trust chain to the anchor | `FederationAttesterKeyResolver` | Implemented |
| Wallet-provider keys likewise | `FederationWalletProviderKeyResolver` | Implemented, unconfigured by default |
| AS advertises `attest_jwt_client_auth` / `attest_jwt_client_auth_dpop`, PoP methods `attestation_pop_jwt` / `dpop_combined`, alg lists, `challenge_endpoint` | `AttestationMetadataConfig` | Implemented |
| `metadata_policy` narrow-only, fails closed | `MetadataPolicy.composeWith` | Partial — the §6.1.4 merge table could not be read; see `unverified.md` item 11 |

### 4.4 CAS 1.0 draft-00 — this repo's own spec

Does the implementation match the text it published?

| Section | Status |
|---|---|
| §3 instance authentication requirements | Implemented |
| §4 issuance API — challenge endpoint, attestation endpoint, instance-key proof, processing rules, errors | Implemented |
| §5 discovery metadata | Implemented — and `ClientAttestationServiceMetadataServlet` reads the same config the issuance servlet enforces, so the document cannot drift from behaviour |
| §6 associating instance identity with a client id | **Partial** — resolution is by evidence rather than by a supplied `client_id` (good), and all three metadata sources exist. But §6.2 rule 1 (federation → CIMD → registration order) is inverted; rule 2 (federation MUST chain-validate to the anchor) is **not met** — self-signature only; rule 3 (CIMD MUST NOT supply instance trust roots) is **violated** — see the next row |
| §6.2 rule 3 — CIMD trust roots | **Not implemented.** `CimdMapping.toConfig:29-30` copies `bundle` and `bundle_url` straight out of the unsigned document. `OIDF_CIMD_TRUST_BUNDLES` exists but is read only to *advertise* `cimd` in the CAS metadata; nothing enforces it. Whoever controls the CIMD URL can publish a bundle they hold the keys to and mint attestations for arbitrary subjects |
| §7 down-scoping at issuance | **Partial** — rules 1–3 (subset semantics, empty request = full ceiling, `narrowing_behavior: reject`) are met. Rule 4 (a PDP or context-dependent narrowing) is not; the selector-conditioned downscoping the code comments describe is comment-only (§3.3); and the registration-time `instances[i].entitlement ⊆ entitlement` check is inert for CIMD/federation-sourced clients because they never carry a client ceiling |
| §8 lifetime / rotation / revocation | Partial — lifetime and rotation yes; revocation depends on the CAEP loop, which is not closed (`unverified.md` items 7 and 12); and a federation client's revocation at the anchor does not revoke issuance because no chain is walked |

### 4.5 Everything else

| Standard | Where | Status |
|---|---|---|
| SPIFFE / SPIRE — JWT-SVID validation, trust domains, selector introspection | `SpiffeSvidValidator`, `SpireSelectorIntrospector` | Implemented |
| Cloud workload OIDC tokens (GKE, GCP SA, EKS, AWS STS web identity, AKS, Azure MI) | Six validators, each mapping onto a SPIFFE identity | Implemented |
| HAIP 1.0 / EUDI ARF Wallet Instance Attestation | `WalletInstanceAttestationValidator` | Implemented, but refuses until wallet trust is configured |
| OpenID4VCI 1.0 Appendix D `key_storage` / `user_authentication` | Device path, `iso_18045_moderate` | Divergence 3 |
| `draft-ietf-oauth-client-id-metadata-document` (CIMD) | `CimdClientResolver` | Partial — resolution and caching yes; the CAS-spec constraint that trust roots must not come from the document is not enforced (§4.4) |
| Apple App Attest | `libs/app-attest`, verified to Apple's root CA | Implemented |
| SSF 1.0 / CAEP 1.0 (revocation signals) | `servlets/ssf` | Implemented as a transmitter/receiver; the signal source is unresolved |

---

## 5. Test coverage

All figures below are from a surefire run on 2026-08-17 (`mvn test` over the six modules), not from
counting annotations. Everything green: 57 / 179 / 20 / 42 / 104 / 49 tests across
`client-attestation`, `attestation-issuer`, `pf-integration`, `rar-paz-plugin`, `openid-federation`
and `device-instance`.

### 5.1 Keyed to §4

| §4 row | Tests | What they actually assert |
|---|---|---|
| ABCA attestation + PoP verification | `ClientAttestationVerifierTest` (18) | PoP and DPoP happy paths; DPoP key must equal `cnf`; expired ⇒ `use_fresh`; both proof headers rejected; missing proof rejected; wrong PoP `aud` rejected; `client_id` mismatch rejected; a **private** key in `cnf` rejected; replay rejected; challenge required-but-missing ⇒ `use_challenge`; valid challenge accepted, stale/unknown rejected; `agent_id` carried through in both modes; a PoP whose `iss` is the `agent_id` rather than the client id still rejected |
| ABCA challenge endpoint | `AttestationChallengeServiceTest` (4) | Consumable once; unknown rejected; unique; expired rejected |
| ABCA replay | `AttestationReplayCacheTest` (4), `RedisAttestationStoreTest` (11) | First-use/replay; `(jti, client)` pairs independent; blank `jti` rejected; bounded cache evicts but stays usable. Redis: same contract cross-instance, **wrong password fails closed**, **Redis down fails closed**, survives stale connections |
| ABCA `agent_id` extension | `ClientAttestationTest` (3), `AttestationMinterTest` (5) | Null when absent, parsed when present, doesn't perturb other fields; omitted rather than emitted blank |
| RFC 9449 DPoP | `DpopProofValidatorTest` (9) | Valid accepted; `htu` ignores query/fragment; wrong method/URI/`typ` rejected; missing `jti` rejected; stale rejected; tampered signature rejected; disallowed alg rejected |
| RFC 9396 containment | `RarEntitlementTest` (8) | Grants within entitlement; denies region/action outside; denies when nothing attested but something requested; grants nothing when nothing requested; missing `type` invalid; array parsing |
| RFC 9396 at issuance | `AttestationAwareRarProcessorTest` (4), `AttestationSubjectTest` (5) | Fail-open strips the internal `_principal_sub` marker; PERMIT merges and strips; DENY throws when configured; engine error throws with cause. Subject parses the PF hook attribute shape, `agent_id` when published |
| RFC 8693 `act` | `ClientAttestationUtilsTest` (3) | Prefers `agent_id` as the acting party; falls back to `client_id` when null or blank |
| OIDF attester trust | `FederationAttesterKeyResolverTest` (3) | Resolves chain-validated keys; prefers dedicated attester metadata keys; rejects an unreachable attester |
| OIDF AS advertisement | `AttestationMetadataConfigTest` (2), `MetadataPolicyTest` | Defaults advertise the plain JWT format and both PoP methods; `one_of`/`value` exercised over `attest_jwt_client_auth` |
| CAS §4 issuance | `AttestationIssuanceServletTest` (52) | Happy path issues an attestation that verifies; unknown SPIFFE id, wrong SVID audience, proof signed by the wrong key, replayed proof all rejected; request exceeding entitlement denied; no clients configured rejected; missing fields rejected; `agent_id` absent with no registry, emitted when configured, registry receives the **resolved** instance subject not the raw SVID, and a **failing registry fails the request**; GKE evidence with fetched bundle; WIA binding a different key rejected; refusal when no wallet trust; declared format narrows the search; bundle-fetch failure with no cache is a server error; SPIRE selectors introspected; malformed `authorization_details` ⇒ `invalid_request`; challenge consumed once then refused; required custom claim missing/blank rejected |
| CAS §5 discovery | `AttesterConfigurationServletTest` (7), `ClientAttestationServiceMetadataServletTest` (8) | Global document advertises endpoints and proof requirements; `agent_id_supported` reflects the flag both ways; per-client view withholds ceiling/bindings/signing; unknown client ⇒ 404; base URL prefers forwarded headers and omits default ports. CAS doc: challenge-required adds `challenge` to proof claims; endpoint can be disabled; custom claims from init-params and environment; formats follow the registered validators |
| CAS §6/§7 client resolution and down-scoping | `AttestationIssuanceConfigTest` (10), `SpiffeBindingTest` (5), `ChainClientResolverTest` (5), `CimdClientResolverTest` (5), `EntraDirectoryAssertedContextResolverTest` (6) | Bindings/metadata/entitlement parsing; wildcard archetype covers its prefix; exact entry beats an overlapping wildcard; **instance entitlement exceeding the client ceiling is rejected**; CIMD TTL caching, stale-copy-on-refetch-failure, server error with no cache |
| SPIFFE | `SpiffeSvidValidatorTest` (7), `SpireSelectorIntrospectorTest` (3) | Wrong audience / expired / wrong trust domain / unknown kid / bad signature / malformed SPIFFE id all rejected |
| Cloud evidence | `GkeTokenValidatorTest` (6), `GcpSaTokenValidatorTest` (6), `EksTokenValidatorTest` (5), `AwsStsWebIdentityValidatorTest` (6), `AksWorkloadIdentityValidatorTest` (5), `AzureManagedIdentityValidatorTest` (6) | Correct mapping onto a SPIFFE id, then wrong-issuer / wrong-audience / expired / bad-subject rejections; AWS also covers an assumed-role ARN with the session dropped |
| HAIP / WIA | `WalletInstanceAttestationValidatorTest` (15) | Untrusted provider, wrong signing key, kid not in the bundle, wrong audience, expired, missing `cnf`, unexpected `typ`, pinned-provider mismatch, private `cnf` key, malformed token all rejected; **unconfigured wallet trust refuses rather than accepts** |
| Attester signing keys | `AttesterSigningKeyTest` (4), `RemoteJwksCacheTest` (4) | Picks transit by key-ref vs local by inline JWK; rejects neither-or-both; rejects transit without a vault configured |
| Evidence registry | `InstanceAttestationValidatorsTest` (9) | Defaults carry every built-in type; cloud types share the SPIFFE family; each declares its trust-domain/bundle needs; unknown type is a client fault; duplicate ids are a config error; `with()` replaces rather than duplicates; format sniffed with SPIFFE fallback |

### 5.2 Where coverage is absent

Stated plainly, because the shape of the gaps is not random — the enforcement points on the PF side
are the thin part.

| Not covered | Why it matters |
|---|---|
| **`ClientAttestationAuthFilter` — no tests at all** | This is the class that implements `attest_jwt_client_auth`. Untested: the bridge assertion (claims, TTL, alg), `Authorization` suppression, the `client_secret` drop, pass-through when no attestation header, the multi-header 400, the fail-closed 500, and the unbridged pass-through when the key is missing |
| `TokenEndpointAutoRegistrationFilter` — no tests | The other `/as/token.oauth2` filter, same deal |
| `ClientAttestationUtils` — 3 tests, all on actor preference | `validateClientAttestation` (the OGNL issuance criterion), `attestationClaim` and `delegationActChain` are otherwise unexercised. These are what actually gate token issuance |
| No end-to-end test spanning issuance → token endpoint | Every test is unit-level. `AttestationMinterTest` does verify a minted attestation through `ClientAttestationVerifier`, which is the closest thing to a seam test, but nothing exercises the HTTP path |
| `MiniRedisClient` `rediss://` (TLS) | The plain path is well covered by `FakeRedisServer`; the TLS path is not |
| Signature verification in the OGNL claim hooks | By design they base64-decode without verifying — safe only because `validateClientAttestation` gates the same mapping. Nothing tests that coupling |
| **`OpenIdFederationClientResolver` — no tests at all** | The federation metadata source. Entity-statement fetch, self-signature verification and `spiffe_client_bindings` parsing are all unexercised. `ChainClientResolverTest` uses fake plugins, not this class |
| `PfIssuanceClientResolver` — no test class | The default, always-on metadata source. No test asserts a disabled client is excluded, or that a client without `attestation_issuer` is skipped |
| Selector-conditioned downscoping | `spireSelectorsAreIntrospectedIntoWorkloadAttributes` asserts the selectors appear in the payload; nothing asserts the granted ceiling changes — because it does not (§3.3) |
| Issuance driven through CIMD or federation | `AttestationIssuanceServletTest` injects prebuilt configs via `setClientResolver`; no test runs `issue()` behind a real external resolver |

### 5.3 How they run

`mvn package` at the repo root, tests on. Two `provided` PF jars (`pf-protocolengine`,
`pingfederate-sdk` 13.0.0.3) must be `install:install-file`d first — see
[`.github/workflows/build.yml`](../.github/workflows/build.yml) for the exact steps. CI runs the full
reactor with tests on every push to `main` and every pull request. The three deploy workflows do
**not** run tests (`deploy-pingfederate.yml` builds with `-DskipTests`).

---

## 6. What still needs to be done

Each item: what is missing, why it matters, what closes it.

### Blocking for production

**CIMD hands the attester its own trust roots.** `CimdMapping.toConfig:29-30` accepts `bundle` and
`bundle_url` from the Client ID Metadata Document — an unsigned JSON file at an HTTPS URL. The CAS spec
this repo published says (§6.2 rule 3) a CAS MUST NOT do this, and explains why: whoever controls the
URL can publish a trust bundle they hold the keys to and mint valid instance attestations for arbitrary
subjects. `OIDF_CIMD_TRUST_BUNDLES` — the trust-domain → JWKS allowlist the spec calls for — exists in
name, but is read only by the metadata servlet to advertise `cimd` as a source; the resolver chain
never sees it. Not live in any checked-in deploy config (`OIDF_ATTESTER_CIMD_URL` is unset), which is
the only reason this is not an incident. *Closes when:* trust roots under CIMD come solely from the
allowlist keyed by `trust_domain`, a document that carries `bundle`/`bundle_url` is refused at parse,
and the fetch enforces HTTPS-only, no private/loopback resolution, a size cap, and `client_id` equal to
the fetched URL. Slice 0 in §8.

**Federation-resolved clients are not chain-validated.** `OpenIdFederationClientResolver:96-103`
verifies the entity configuration against its **own inline `jwks`** — tamper-evidence, not trust. No
`TrustChainValidator` runs on this path (the only one in the issuer is for wallet-provider keys). Spec
§6.2 rule 2 says the CAS MUST validate the chain to a configured anchor and SHOULD resolve live so that
revoking the entity's membership revokes issuance within one cache lifetime. Today revocation at the
anchor changes nothing at the attester. `FederationAttesterKeyResolver:43-46` on the AS side already
does the right thing and is the pattern to copy. *Closes when:* the chain is validated to
`OIDF_FEDERATION_TRUST_ANCHORS`, bindings are read from the validated leaf, and stale-on-error is
limited to transport failures — never a failed chain. Slice 1 in §8.

**The shipped image trusts static attester keys.** `build/pingfederate/Dockerfile:78-79` writes
`oidf.mock.attesters` into `run.properties.subst.default`, pointing at
`build/pingfederate/ (supplied per deployment)` — hardcoded EC public keys for `urn:agent:northwind-*`.
`ClientAttestationUtils` logs "DEV MODE … OpenID Federation trust-chain validation is DISABLED" when it
uses them. Anyone holding the matching private key can mint an attestation those issuers will accept,
with no federation chain. *Closes when:* the property is moved out of the base Dockerfile into a
dev-only overlay, and staging/production run federation-only.

**A private attester key is committed.** The deploying repo's [`attestation-demo-clients.tf`](https://github.com/dphhyland/pf-oidf-modules/blob/main/deploy/pingfederate/terraform/attestation-demo-clients.tf)
carries an inline EC **private** JWK (`kid = "mock-attester-1"`), a hardcoded issuer
`https://attester.example.com`, and a "throwaway" client secret. *Closes when:* the demo clients move
to transit-backed signing, or the file moves to a demo-only tree that is never applied to a real
environment.

**The bridge key is a single key that authenticates as any attestation client.**
`OIDF_BRIDGE_PRIVATE_JWK` signs a `private_key_jwt` whose `iss`/`sub` is whichever client the filter
just verified, and its public half sits in every attestation client's JWKS. There is no rotation
story, no per-client separation, and no threat-model note anywhere in the repo. *Closes when:* the
threat model is written down and either the key is scoped per client or the risk is explicitly
accepted in writing.

**The token-endpoint method is inert in the checked-in deploy config.** No `vars.*.env` sets
`OIDF_BRIDGE_PRIVATE_JWK`, so on those settings alone the filter passes every attestation-bearing
request straight through with a warning. Only the OGNL criterion path is live. *Closes when:* the
variable is set as a deploy secret and the deploy docs say so — or, better, when the filter refuses to
start rather than degrading silently.

**`ClientAttestationAuthFilter` is untested.** See §5.2. The fail-closed behaviour is asserted in a
javadoc comment and nowhere else.

**The issuance criterion is bound to an unverified ATM id.**
The deploying repo's [`access-token-mappings.tf`](https://github.com/dphhyland/pf-oidf-modules/blob/main/deploy/pingfederate/terraform/access-token-mappings.tf) says `attestATM` is "almost certainly
the mapping — CONFIRM via GET /oauth/accessTokenMappings". If it is wrong, the gate silently applies to
nothing. *Closes when:* the id is confirmed against a live server and the comment is deleted.

**Four extended properties the issuer reads are not declared in terraform.**
`extended-properties.tf` declares `attestation_required` (which nothing reads) but omits
`attestation_evidence`, `attestation_bundle_url`, `attestation_evidence_issuer` and
`attestation_asserted_context_resolver`. PF rejects an `extended_parameters` entry whose name is not
declared, so as it stands that terraform cannot create a client using cloud evidence, a remote trust
bundle, or asserted context — the whole non-SPIFFE catalogue. The file's own header warns it "MAY be
missing" names; it is. *Closes when:* the four names are added and the singleton is reconciled against
the live list as the header instructs.

### Production hardening

**Selector-conditioned downscoping does not exist.** The code comment at
`AttestationIssuanceServlet:217-218` describes it, the `SpireSelectorIntrospector` javadoc gives an
example of it ("only grant EMEA when `k8s:ns:demo` is among the selectors"), and the CAS spec §7 rule 4
allows for it — but nothing implements it. Introspected selectors and binding metadata such as
`version` are carried into `workload.attributes` and never touch the ceiling. This is the stage that
turns "the instance proved what it is" into "so it may do this much *given* what it is". The narrowing
primitive that would carry it, `intersectCeilings`, already exists and is proven by the
asserted-context path. *Closes when:* per-binding conditional ceilings in registration metadata are
evaluated after introspection and intersected in. Slice 3 in §8.

**The instance-⊆-client containment check is inert for external sources.**
`AttestationIssuanceConfig:292-300` refuses a binding whose entitlement exceeds the client ceiling —
but only when a client ceiling is present, and `CimdMapping.toConfig` never sets one. A CIMD or
federation binding's entitlement is therefore bounded by nothing but itself. *Closes when:* the external
mapping schema carries a client-level ceiling and the check refuses a binding entitlement with no
ceiling to sit under. Slice 2 in §8.

**Wallet trust is unconfigured everywhere.** Neither `OIDF_TRUST_CONTROLLER_HOST` +
`OIDF_ATTESTER_OP_ISSUER` nor `OIDF_WALLET_PROVIDER_JWKS` is set in any deploy config, so the WIA path
is discoverable and always fails. Note also that the wallet path reads
`OIDF_TRUST_CONTROLLER_HOST` while the AS-side attester trust reads
`OIDF_FEDERATION_TRUST_CONTROLLER_HOST` — two variables, one concept, easy to set the wrong one.
*Closes when:* the names are unified and the value is set.

**No Redis in the checked-in config means per-node replay state.** With two verification points on two
classloaders and a clustered PF, in-memory caches mean a PoP `jti` can be spent once per node.
`DEMO-MINT-DEPLOY.md` says staging has `OIDF_REDIS_URL` set outside the repo; production is unstated.
*Closes when:* Redis is a documented requirement for any clustered deployment rather than an optional
upgrade.

**The divergence-5 `sub` flip is unfinished.** `OIDF_ATTESTATION_SUB=client_id` is default-off, so on
the device path `sub` still carries the instance identity — the thing the draft says is the client id.
The migration order is written down in `claim-dictionary.md`; steps 3 and 4 (flip, delete the flag)
have not happened. *Closes when:* consumers are confirmed to read `agent_id`, the flag is flipped, and
it is removed.

**`services/demo-rs` has no replay cache wired.** `DelegatedTokenValidator` reports the DPoP proof's
`jti` precisely so a caller can cache it; no caller exists. A resource server that skips it accepts a
captured proof for as long as it stays fresh. `AttestationReplayCache` already exists and is the thing
to wire. (`unverified.md` item 10.)

**No FAPI 2.0 assessment.** This deployment is exactly the shape FAPI 2.0 targets — sender-constrained
tokens, high-assurance clients, fine-grained authorisation — and FAPI is not referenced anywhere in the
repo. That is a gap in the *claim*, not necessarily in the behaviour. *Closes when:* someone reads FAPI
2.0 Security Profile against §4 above and records which clauses hold. It will surface PAR and mTLS as
real absences.

**Whether PF can emit `act` as a JSON object is unresolved.** RFC 8693 defines `act` as an object; the
existing mapping emits a JSON *string* for consumers to decode. `ActChain` parses both and reports the
legacy form so the deviation stays visible. This directly affects the delegation claim the pipeline
produces. (`unverified.md` item 8.)

**The OGNL claim hooks trust an unverified decode.** `attestationClaim` and `delegationActChain`
base64-decode the attestation without checking the signature, arguing that
`validateClientAttestation` gates issuance on the same mapping. That is true today and invisible
tomorrow — remove the criterion from a mapping and the claim hooks become unauthenticated. *Closes
when:* the coupling is either enforced in code or documented at both call sites.

**`RarContainment` duplicates `RarEntitlement`.** The PAZ plugin shades its own copy; the file carries
the repo's one literal `TODO: consolidate the two into a shared library`. Two implementations of a
containment rule will drift, and the drift is a privilege-escalation shape.

### Nice to have

- The metadata resolution chain runs CIMD → federation → PF store; the spec says federation → CIMD →
  registration, descending assurance. First-match-per-client-id means the lowest-assurance source
  currently wins a collision. Reordering is a one-line change once slice 0 and 1 make both external
  sources safe.
- `ClientAttestationServiceMetadataServlet:138` advertises `cimd` as an active metadata source off
  `OIDF_CIMD_TRUST_BUNDLES`; the resolver chain is enabled by `OIDF_ATTESTER_CIMD_URL`. Two variables,
  and the discovery document can claim a source that is not wired, or omit one that is.
- Challenges are off by default on both the issuance and verification sides. Nothing is wrong with
  that, but it means the anti-replay story rests entirely on `jti` caching.
- SPIRE selector introspection is a no-op unless `OIDF_ATTESTER_SPIRE_ENTRIES_URL` is set, so
  `workload.attributes` carries only the binding's declared metadata by default.
- `EntraDirectoryAssertedContextResolver` is an MVP: a static JSON directory in an environment
  variable.
- Attester key resolution depends on retaining `iss` (divergence 1). Worth revisiting if the draft ever
  defines a federation-based resolution mechanism of its own.

---

## 7. Related documents

| Document | What it is for |
|---|---|
| [openid-client-attestation-service-1_0.md](openid-client-attestation-service-1_0.md) | The CAS 1.0 draft-00 spec — normative text for the issuance side |
| [claim-dictionary.md](claim-dictionary.md) | Every claim, its spec status, and the five numbered deliberate divergences |
| [unverified.md](unverified.md) | The twelve assumptions that could not be confirmed against an authoritative source |
| [libs/client-attestation/README.md](../libs/client-attestation/README.md) | The verifier module in detail |
| [servlets/attestation-issuer/README.md](../servlets/attestation-issuer/README.md) | The issuer module in detail |
| [servlets/pf-integration/README.md](../servlets/pf-integration/README.md) | The PF glue: filters, OGNL hooks, key resolvers |
| [services/device-enrolment/README.md](../services/device-enrolment/README.md) | The device path and its enrolment ceremony |
| [build/pingfederate/README.md](../build/pingfederate/README.md) | How the AS image is built, and what each consumer supplies |
| [DEMOS.md](DEMOS.md) | Which demos exercise this pipeline and how to bring them up |

---

## 8. Next work

The gaps in §6, cut into slices that are each independently shippable and tested, ordered by
dependency and blast radius. Suggested order: **0 → 5 → 1 → 2 → 4 → 3**. Slices 0 and 5 are small and
unblock a real staging cut; 3 is the biggest and, from a security stance, the least urgent (the spec's
rule 4 is a MAY) — but it is the one that delivers the stage the design always intended.

### Slice 0 — CIMD trust-root allowlist

*Blocking. Small.*

- `CimdMapping.toConfig`: refuse `bundle` and `bundle_url` from the document — `invalid_client` at
  config parse, with a log line naming the rule. Resolve trust roots from `OIDF_CIMD_TRUST_BUNDLES`
  (trust-domain → JWKS map) keyed by the entry's `trust_domain`; **fail closed** when the domain is not
  in the map.
- `CimdClientResolver`: enforce the spec's fetch rules — HTTPS only; refuse private/loopback
  resolution; response size cap; the document's `client_id` must equal the fetched URL.
- Move `OIDF_CIMD_TRUST_BUNDLES` reading into a shared helper so the metadata servlet advertises `cimd`
  off the same setting that makes it safe.
- Tests, `CimdClientResolverTest`: bundle in document refused; unknown trust domain refused;
  allowlisted domain resolves; `client_id` mismatch refused; `http://` refused.

### Slice 1 — Federation trust-chain validation for federation-resolved clients

*Blocking.*

- `OpenIdFederationClientResolver`: after the entity-configuration fetch, validate the chain to the
  anchor via `TrustChainValidator` — the pattern is `FederationAttesterKeyResolver:43-46`; anchor from
  `OIDF_FEDERATION_TRUST_ANCHORS`, gateway from `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`. Read
  `spiffe_client_bindings` from the **chain-validated leaf**, not the raw fetch. Keep the 300 s cache so
  revoking membership revokes issuance within one lifetime; serve stale on *transport* failure only —
  never on a failed chain, or revocation is defeated.
- `AttesterResolvers`: reorder to federation → CIMD → PF store. Note in this doc that
  first-match-per-client-id now means the higher-assurance source wins a collision.
- Tests, new `OpenIdFederationClientResolverTest`: chain-valid entity resolves; chain-invalid or revoked
  entity refused; transport failure serves stale; chain failure does not; bindings come from the
  validated leaf.

### Slice 2 — Ceiling containment for external sources

*Hardening. Small.*

- `CimdMapping.toConfig`: map a document-level `entitlement` (client ceiling) to `P_ENTITLEMENT` so
  the instance-⊆-client rule fires; and change the rule to refuse an external-source binding
  entitlement that has **no** client ceiling to sit under, rather than silently accepting it.
- Tests, `AttestationIssuanceConfigTest` / `CimdClientResolverTest`: external binding exceeding the
  document ceiling rejected; binding entitlement with no document ceiling rejected.

### Slice 3 — Selector-conditioned downscoping

*Hardening. The stage the design describes and the code comments promise.*

- A `CeilingPolicy` SPI evaluated at step 6, **after** introspection, returning a ceiling that is folded
  in via the existing `intersectCeilings` — narrow only, never widen.
- First implementation, declarative, in registration metadata: per-binding `conditional_ceilings`,
  each `{ "when": { attribute → value | prefix | range }, "ceiling": [RAR] }`. `when` matches against
  the merged `workloadAttributes` (SPIRE selectors, binding metadata such as `version`). Every matching
  rule's ceiling is intersected; no match leaves the ceiling unchanged.
- Second implementation, later: an AuthZEN PDP call (spec §7 rule 4). The repo already has PingAuthorize
  and gm-api AuthZEN work to reuse. Out of scope for this slice; the SPI is the seam.
- Wire through `AttestationIssuanceConfig` (parse; validate each rule's ceiling ⊆ the binding
  entitlement at config time, same discipline as instance-⊆-client) and `CimdMapping.toConfig`.
- Advertise `conditional_ceilings_supported` in `/.well-known/client-attestation-service`, from the
  same config the issuance servlet enforces.
- Tests, `AttestationIssuanceServletTest`: selector hit narrows the granted ceiling; no hit leaves it;
  a rule exceeding the binding entitlement rejected at parse; version-range match; multiple rules
  intersect.

### Slice 4 — Test the enforcement points

*Hardening. Parallelisable with 1–3.*

- `ClientAttestationAuthFilterTest` (none today): bridge assertion claims, TTL, alg; `Authorization`
  suppressed; `client_secret` dropped; pass-through with no header; multi-header 400; fail-closed 500;
  unbridged pass-through when the key is missing.
- `PfIssuanceClientResolverTest` (none today): disabled client excluded from `attestationClients()`;
  client without `attestation_issuer` excluded.
- `ClientAttestationUtils`: `validateClientAttestation` happy and deny paths via a stubbed request.

### Slice 5 — Deploy hygiene

*Blocking items from §6 that are configuration, not code.*

- `oidf.mock.attesters` out of the base Dockerfile into a dev-only overlay.
- `extended-properties.tf`: add `attestation_evidence`, `attestation_bundle_url`,
  `attestation_evidence_issuer`, `attestation_asserted_context_resolver`; drop the unread
  `attestation_required` or wire it.
- `OIDF_BRIDGE_PRIVATE_JWK` as a documented deploy secret; consider making the filter refuse to start
  without it rather than degrading silently.
- Confirm the `attestATM` mapping id against a live server and delete the "CONFIRM" comment.
- The demo private attester JWK out of `attestation-demo-clients.tf`.

### Open question, recorded rather than answered

Should issuance check that the client is registered for `attest_jwt_client_auth`? On PingFederate the
bridge means every working client is registered as `private_key_jwt`, so a naive check would reject all
of them. The signal `PfIssuanceClientResolver:82` already uses — presence of `attestation_issuer` — is
the honest one for the PF store; federation and CIMD would need their own. Not in any slice above.
