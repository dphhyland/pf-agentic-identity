# attestation-issuer

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Extracted with history from `pf-oidf-modules` 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The **Client Attestation issuer** - the issuing side of OAuth Attestation-Based Client Authentication.
A workload proves what it is (a SPIFFE SVID, a cloud identity token, a Wallet Instance Attestation) and
walks away with a short-lived Client Attestation bound to its own instance key, which it then presents
at the AS token endpoint. Verification lives in [`client-attestation`](../../libs/client-attestation);
the AS-side wiring in [`pf-integration`](../pf-integration), on which this module depends (client store,
wallet-provider trust, PF signing key). Written up as a spec draft in
[docs/openid-client-attestation-service-1_0.md](../../docs/openid-client-attestation-service-1_0.md);
the pipeline end to end, with standards alignment, test coverage and the open gaps, is
[docs/client-attestation-architecture.md](../../docs/client-attestation-architecture.md).

Plain `@WebServlet` classes on the webapp classloader (not a PF-INF plugin): the jar goes into a war's
`WEB-INF/lib` and PF's Jetty scans it. Package `com.pingidentity.ps.oidf.issuer` holds the logic
(renamed from `.common` on 2026-08-15); `com.pingidentity.ps.oidf.servlet.attestation` keeps its FQCNs.

## Endpoints

| Path | Class | What |
|---|---|---|
| `POST /federation/attestation` | `AttestationIssuanceServlet` | Issuance. JSON body: `instance_key` (JWK), `instance_attestation` (alias `svid`), `proof`, optional `authorization_details` / `asserted_context`; a `client_id` is accepted but ignored and an `agent_id` is rejected. The client is resolved **from the evidence**: it is validated against every attestation client's config and the one whose trust bundle verifies it *and* whose bindings contain the resulting identity is the match. Then: instance-key proof (its window, challenge + `jti` replay - [below](#the-instance-key-proof)), deployment-required custom proof claims, the binding's ceiling narrowed by the asserted context's when there is one (the containment model's meet), the grant (`authorize(requested, ceiling, INHERIT)`, or the full ceiling for an empty request - [below](#the-ceiling-and-the-grant)), `agent_id`, mint. `200 {"attestation","expires_in"}`, `Cache-Control: no-store`. |
| `GET /.well-known/client-attester`, `/federation/.well-known/client-attester` | `AttesterConfigurationServlet` | This deployment's discovery document: endpoints, evidence types (read off the validator registry), `evidence_audience`, `pop_audience` (PF's OP issuer - the "aud trap"), active resolver plugins. Cacheable, parameterless. |
| `GET /federation/attester-configuration?client_id=` | same | Per-client view: issuer, evidence audience, trust domain, RAR type names. Ceiling, bindings and signing config are deliberately not exposed. |
| `GET /.well-known/client-attestation-service` | `ClientAttestationServiceMetadataServlet` | The fixed CAS 1.0 §5 document: required request members, required proof claims (`aud`, `jti`, `iat`, `exp`, `challenge` when required, plus custom), claims minted. Reads the same config the issuance servlet enforces, so advertisement and enforcement cannot drift. |
| `GET /federation/attestation/challenge` | `AttestationIssuanceChallengeServlet` | The attester's challenge endpoint (CAS §4.1), for the instance-key proof: `200 {"attestation_challenge","expires_in"}`, `Cache-Control: no-store`; 429 `slow_down` over its per-caller cap (60 a minute by default); 503 `temporarily_unavailable` when the store cannot record the challenge. Issues into `oidf:cas:challenge:*`, which `/federation/attestation` consumes, once. Any other method, `POST` and `HEAD` included, is 405 with `Allow: GET`. Advertised as `challenge_endpoint` by both discovery documents above. |
| `POST /federation/attestation-challenge` | `ClientAttestationChallengeServlet` (in `client-attestation`) | The **authorization server's** challenge endpoint (ABCA-10 §6.1), for the PoP at the token endpoint - not this module's. Its challenges live in `oidf:as:challenge:*`, and the attester refuses them (`invalid_instance_proof`); the token endpoint likewise refuses the attester's (`use_attestation_challenge`). |

## Evidence validators

`InstanceAttestationValidators.defaults()` is the catalogue; adding a type is registering one plugin.
Ids (the client's `attestation_evidence`): `spiffe-jwt` (`SpiffeInstanceAttestationValidator`),
`gke-sa-token`, `gcp-id-token`, `eks-sa-token`, `aws-sts-web-identity`, `aks-sa-token`,
`azure-mi-token` (each resolves to a SPIFFE identity, `format() == "spiffe"`), and
`wallet-instance-attestation` (`WalletInstanceAttestationValidator`, format `wallet`). The wallet entry
is registered with an *unconfigured* key resolver so the id is always discoverable and a WIA fails
loudly until wallet-provider trust is configured. `SpireSelectorIntrospector` (optional) merges SPIRE
registration selectors into `workload.attributes`; they are not evidence selectors ([below](#evidence-selectors)).

What each validator checks, and what it copies into the identity, as the code does it on 2026-09-28. The key
source for every type but the wallet's is the client's trust bundle: `attestation_spiffe_bundle` inline, or
`attestation_bundle_url` fetched and cached (`RemoteJwksCache`). The key is the one the header's `kid` names, or
the bundle's only key when there is no `kid`. The algorithm must be RS, PS or ES 256/384/512 or EdDSA, so `none`
and HMAC are refused. `aud` must contain the client's `attestation_issuer`. `exp` is required and refused once more
than 60 s past; `iat` is read when present. A failure of the evidence is `invalid_svid`, or
`invalid_instance_attestation` for the wallet; a cloud type's client with no `attestation_trust_domain` is a
configuration error, `invalid_client`.

| Evidence type (validator) | Key | `iss` | Other claims required | `subject` | `trustDomain` | `workloadClaims` |
|---|---|---|---|---|---|---|
| `spiffe-jwt` (`SpiffeInstanceAttestationValidator`, via `SpiffeSvidValidator`) | trust bundle | not read | `sub` a `spiffe://` ID with a trust domain, equal to `attestation_trust_domain` when set | `sub` | the authority of `sub` | `spiffe_id` = `sub` |
| `gke-sa-token` (`GkeTokenValidator`), `eks-sa-token` (`EksTokenValidator`), `aks-sa-token` (`AksWorkloadIdentityValidator`) | trust bundle (the cluster's JWKS) | equal to `attestation_evidence_issuer` when set | `sub` = `system:serviceaccount:<ns>:<sa>` | `spiffe://<attestation_trust_domain>/ns/<ns>/sa/<sa>` | `attestation_trust_domain` (required) | `spiffe_id` = subject |
| `gcp-id-token` (`GcpSaTokenValidator`) | trust bundle (Google's JWKS) | equal to `attestation_evidence_issuer` when set | `email` | `spiffe://<attestation_trust_domain>/sa/<email>` | `attestation_trust_domain` (required) | `spiffe_id` = subject |
| `aws-sts-web-identity` (`AwsStsWebIdentityValidator`) | trust bundle (the account issuer's JWKS) | equal to `attestation_evidence_issuer` when set | `sub` = `arn:aws...:iam::<account>:role/<role>` or `arn:aws...:sts::<account>:assumed-role/<role>/<session>` | `spiffe://<attestation_trust_domain>/aws/<account>/role/<role>` | `attestation_trust_domain` (required) | `spiffe_id` = subject |
| `azure-mi-token` (`AzureManagedIdentityValidator`) | trust bundle (the tenant's JWKS) | equal to `attestation_evidence_issuer` when set | `oid` | `spiffe://<attestation_trust_domain>/azure/mi/<oid>` | `attestation_trust_domain` (required) | `spiffe_id` = subject |
| `wallet-instance-attestation` (`WalletInstanceAttestationValidator`) | the keys the wallet-provider resolver returns for `iss` (a federation trust chain, or the static `OIDF_WALLET_PROVIDER_JWKS` map); header `typ` one of the four WIA types or absent | required; equal to `attestation_trust_domain` when set | `sub`; `cnf.jwk`, a public key, returned as `boundKey` | `sub` | `iss` | `wallet_provider` = `iss`, `wallet_instance` = `sub` |

## Evidence selectors

`InstanceIdentity.selectors()` (plan item X-B01) is what the validator proved about the instance, in one
namespace: an immutable, sorted multimap from `<source>:<name>` to a sorted set of values. `source` is the evidence
type id; `name` comes from the validator's fixed list (`selectorNames()`). Nothing reads the selectors yet. Plan
item X-B09 (Phase 5) is to condition ceilings on them (`conditional_ceilings`, a `CeilingPolicy` SPI) and decide
what, if anything, an attestation discloses.

| Evidence type | Selector | From | Compared with the client's configuration |
|---|---|---|---|
| `spiffe-jwt` | `spiffe-jwt:spiffe_id` | `sub` | no |
| | `spiffe-jwt:trust_domain` | the authority of `sub` | `attestation_trust_domain`, when set |
| `gke-sa-token`, `eks-sa-token`, `aks-sa-token` | `<type>:issuer` | `iss` | `attestation_evidence_issuer`, when set |
| | `<type>:namespace`, `<type>:service_account` | `sub`, `system:serviceaccount:<namespace>:<service_account>` | no |
| `gcp-id-token` | `gcp-id-token:issuer` | `iss` | `attestation_evidence_issuer`, when set |
| | `gcp-id-token:email` | `email` | no |
| `aws-sts-web-identity` | `aws-sts-web-identity:issuer` | `iss` | `attestation_evidence_issuer`, when set |
| | `aws-sts-web-identity:account`, `aws-sts-web-identity:role` | `sub`, the IAM principal ARN; the role is the one the SPIFFE path carries, the session name dropped | no |
| `azure-mi-token` | `azure-mi-token:issuer` | `iss` | `attestation_evidence_issuer`, when set |
| | `azure-mi-token:tenant_id` | `tid` | no: pin `attestation_evidence_issuer` to the tenant's issuer to tie it to one tenant |
| | `azure-mi-token:object_id` | `oid` | no |
| `wallet-instance-attestation` | `wallet-instance-attestation:provider` | `iss`, whose keys verified the WIA | `attestation_trust_domain`, when set |
| | `wallet-instance-attestation:instance` | `sub` | no |

The rules:

- **Only verified claims.** A validator builds its selectors itself, after every check in the table above has
  passed, from claims of the evidence whose signature it verified. A claim that is not a JSON string gives no
  selector, and neither does an absent or empty one. What the client's configuration supplies rather than the
  evidence - the cloud types' `attestation_trust_domain`, and so the SPIFFE ID they synthesise - is not a selector;
  it stays in `subject()` and `trustDomain()`. Nor is anything parsed out of a claim that does not say what it is:
  the GCP validator reads no project claim, and the email's domain is not one - a user-managed account is
  `<name>@<project-id>.iam.gserviceaccount.com` ([Google, service account types](https://cloud.google.com/iam/docs/service-account-types),
  read 2026-09-28), but Google's service agents are `...@gcp-sa-<service>.iam.gserviceaccount.com` in the same
  shape.
- **Only listed names.** The names are constants in each validator. A token's extra claims, however named (a
  `selectors` claim, a claim called `gke-sa-token:namespace`, a `kubernetes.io` object), add nothing.
- **Values as the evidence states them.** They are compared by exact string equality, the way
  `SpiffeBinding.matches` compares an instance subject: case-sensitive, never trimmed. SPIFFE-ID §2.4 says "The
  scheme and trust domain name of the SPIFFE ID are case-insensitive", but the binding match and the trust-domain
  pin compare them exactly, and a selector does the same.
- **Bounds, refused above.** At most 32 values in all, and at most 2048 UTF-8 bytes in one. Evidence over either is
  refused (`invalid_svid`, or `invalid_instance_attestation` for the wallet); it is never truncated, because a cut
  set could drop the one selector a condition turns on. 2048 bytes is the SPIFFE ID's own limit - SPIFFE-ID §2.3:
  "SPIFFE implementations MUST support SPIFFE URIs up to 2048 bytes in length and SHOULD NOT generate URIs of length
  greater than 2048 bytes" - so every SPIFFE ID a conforming implementation must accept fits. 32 is about ten times
  the longest list today (three names, one value each); the room is for SPIRE's selectors, below, and the bound keeps
  what X-B09 matches per issuance small.
- **Nothing after the validator.** Not the request's parameters, not the binding's `metadata`, not the introspected
  attributes (step 5 in `AttestationIssuanceServlet`), not the caller-asserted context (step 5a). `InstanceIdentity`
  cannot be changed once built, and `EvidenceSelectors.of` is package-private, so the servlet's package cannot build
  a non-empty set.
- **Nothing on the wire.** `AttestationMinter` reads the identity's format, subject, `workloadClaims`, digest,
  evidence type and expiry, and not its selectors, so a minted attestation is the same with or without them.

`EvidenceSelectorsTest` holds each rule: each validator's selectors from a real-shaped token; for every validator,
extra and unknown claims, an oversized value, and a forged or expired token refused for that fault before any
selector is built; non-string claims; the bounds; and, for 200 random
seeds, binding metadata, asserted context and SPIRE answers that leave the selectors as they were, and a minted
attestation with the same members and the same `workload` as one minted from the same identity without them.

### SPIRE

`SpireSelectorIntrospector`'s selectors are not evidence selectors. It is a plain HTTP GET of the endpoint
`OIDF_ATTESTER_SPIRE_ENTRIES_URL` names, nothing authenticates the answer, and a failed lookup gives none. Its
output stays where it was, in `workload.attributes` (`selectors` and `spire`), and never reaches `selectors()`.
Anything that reads those attributes in a minted attestation is reading what that endpoint said, signed by the
attester ([F-0140](../../docs/findings/F-0140.yaml)); do not condition policy on them, and name an https URL.

Plan items X-B07 and X-B08 (Phase 5) replace it with a read-only SPIRE reader and its PingFederate client, over
mTLS from a PingFederate-managed key pair. That reader is to be the one way `spire:` selectors arrive. The
`spiffe-jwt` validator is to call it after the SVID has passed every check, keyed by the verified SPIFFE ID, and to
add what it reads through `EvidenceSelectors.of` with source `spire`, names from a fixed list of SPIRE selector
types (`spire:k8s` to `ns:payments` and `sa:payment-agent`, say), and the same bounds. `spire` will then be the one
source that is not an evidence type id, as a second verified source about the same instance. Where several
registration entries match, only the selectors common to all of them are to count (the plan's intersection across
entries). A failed read is to refuse the issuance (`closed`) or issue without `spire:` selectors (`downscope`),
whichever failure mode is configured.

## The instance-key proof

`InstanceKeyProofValidator` checks the proof's signature under the presented `instance_key`, its `typ`
(`oauth-attestation-instance-proof+jwt`), an `aud` containing the client's `attestation_issuer`, a `jti`, and its
validity window (plan item S4c, finding F-0036). CAS §4.3 lists "`iat` (REQUIRED), `exp` (REQUIRED, SHOULD be ≤ 5
minutes after `iat`)"; §5.3.1 says the opposite of `iat` ("not listed as required but, when present, MUST be
validated for freshness"). The attester follows §4.3 and makes its SHOULD a limit:

- `iat` and `exp` are both required, and `exp` must be after `iat` by at most 300 s;
- the proof is refused before `iat - 60 s` and after `exp + 60 s`;
- every such refusal is `invalid_instance_proof` with one description, which says what to send and never echoes
  what was sent (CAS §4.6: "The Instance Key Proof failed (signature, `aud`, expiry, replay, challenge)");
- the proof's `jti` is remembered in `oidf:cas:jti:*` until `exp + 60 s`, the last second the proof could be
  accepted, rather than for 300 s from first use. A proof whose window closes while the request is being checked
  is refused as stale before the store is asked.

It still meets every MUST of §5.3.1: `aud` and `jti` are required, `iat` is validated and `exp` honoured. The
discovery document's `proof_claims_required` lists `iat` and `exp`. Before 0.6.0 a proof without `iat` had no end,
and the same proof was accepted again once the store forgot its `jti` after 300 s.

## Minting

`AttestationMinter`: `iss` (the client's `attestation_issuer`), `sub` = `client_id`, `iat`/`exp`
(`attestation_issued_ttl`, at most `OIDF_ATTESTER_MAX_ISSUED_TTL`, and never past the evidence's own `exp`),
`cnf` (the instance key), `workload`
(binding metadata + introspected attributes), `authorization_details` when an entitlement was granted,
`agent_id` when a registry is configured. Signed by the client's own attester key (`AttesterSigningKey`):
**OpenBao transit** (`attestation_signing_key_ref`, key never leaves the vault) or an inline private JWK
(`attestation_signing_jwk`, dev). `agent_id` (via [`agent-registry`](../../libs/agent-registry)) is
opt-in: nothing in this module configures `AgentRegistrySupport`; unconfigured = no claim, configured but
broken = `server_error`, never a silent attestation without identity.

What `workload` says about the evidence is `instance_attestation_sha256`, `instance_attestation_type`
(the evidence type that validated it: `spiffe-jwt`, `gke-sa-token`, `wallet-instance-attestation`, ...) and
`instance_attestation_exp`. The digest is the SHA-256, lower-case hex, of the evidence's first two segments,
header and payload - its JWS Signing Input (RFC 7515 §2), which is what its signature covers. An auditor
holding a captured token computes it with `printf %s "${token%.*}" | sha256sum`. The signature segment is
left out because a verifier accepts one signature in many encodings: jose4j 0.9.6 verifies a token with
trailing whitespace, with stray characters or padding in its signature, with non-canonical trailing bits and,
for ECDSA, as the `(r, n-s)` twin, and each of those has a different SHA-256 as a whole string. The evidence itself never leaves the attester: 0.3.0 embedded it as
`workload.svid` (every SPIFFE-shaped type) and `workload.instance_attestation` (the wallet WIA), and since
its audience is the attester, anyone who read an attestation could present it and be issued one for their
own key (finding F-0002). The plugin and PingFederate's token mappings forward whatever `workload` carries,
so removing it here removes it from the PDP and the tokens too; `AttestationIssuanceServletTest` decodes
the minted JWT and looks for the token.

Client config is the PF client's `attestation_*` extended properties (`AttestationIssuanceConfig`),
resolved through `PfIssuanceClientResolver`, with a CIMD document and/or an OpenID Federation entity
prepended when configured (`AttesterResolvers`). The names, their types and what a wrong value does are in the
[issuance-client-properties](src/main/resources/META-INF/oidf-settings/issuance-client-properties.json) catalogue.
`attestation_asserted_context_resolver` is read by `AttestationIssuanceConfig` but is not one of the names
`PfIssuanceClientResolver` reads off a PF client, so on a PF client it has no effect
([F-0230](../../docs/findings/F-0230.yaml)).

## Evidence binding

Once the key proof and every other check have passed - last, just before minting, so a request refused by
any of those checks never takes the binding - the evidence binds to `(instance key thumbprint, client)` in
the shared store (`EvidenceBindingStore`, `oidf:cas:evidence:<digest>`, Redis `SET NX PX` with a
`GET`-and-compare fallback, or the in-memory store per node) for as long as the evidence lives. A request
that fails after the binding, at the signer say, keeps it; that presenter passed every check. The first
presenter wins; the same key and client may present the same evidence again (a workload re-attesting from
the evidence it still holds); a different key or client is refused with 401 `instance_attestation_bound`
and the audit event `attestation.evidence.conflict` (failure reason `evidence_bound_elsewhere`, subject the
client, fields `evidence_sha256`, `evidence_type`, `instance_subject`, `presented_jkt` for the key refused,
and `bound_jkt` and `bound_client` for the key and client that hold the binding). The event goes through
`FederationEvents`, so it reaches PingFederate's audit log the way the federation events do
([docs/federation/operations.md](../../docs/federation/operations.md)). The issuance log line names the
digest and the key it was issued for (`instance_jkt`).

Because the digest covers header and payload only, the same token re-encoded meets the same binding, and two
tokens with the same header and payload are the same evidence whatever their signatures. Only a key the
attester trusts for that subject can produce a second one.

A workload that regenerates its instance key while its evidence is still live meets its own binding. The
SPIRE agent caches a JWT-SVID per SPIFFE ID and audience and returns the cached one until less than half its
lifetime is left (spiffe/spire main, fetched 2026-09-27: `FetchJWTSVID` in `pkg/agent/manager/manager.go`,
`JWTSVIDExpiresSoon` in `pkg/common/rotationutil/rotationutil.go`), and a projected cloud token is the same
file until it rotates. There are three ways out: keep the instance key for the evidence's life, persisting it
across restarts; wait for the cached evidence to rotate; or, on a SPIRE that has it, register the entry with
a `jti` claim, which makes the agent bypass its cache and mint a fresh SVID for every fetch. A conflict
right after a restart is most likely this, not a theft. Replicas that share a SPIFFE ID share the agent's
cached SVID the same way, so give each its own SPIFFE ID or a `jti`.

Residual risk, as the plan states it: a thief who uses the evidence first wins; detectable, not
preventable, without key-bound evidence. The binding is then the thief's, and the rightful holder is the
one refused and audited; the lifetime cap below bounds how long a stolen token stays presentable. Evidence
with nothing to digest (a format whose evidence is not one token) is not bound.

A challenge, replay or binding store that cannot answer is 503 `temporarily_unavailable` (CAS §4.6; the
code is RFC 6749's, §4.1.2.1), never a refusal about the request. The caller retries with the same
evidence and a fresh proof, because the proof's challenge or `jti` may have been spent before the store
stopped answering. The issuer's challenges, proof jtis and bindings live under `oidf:cas:*`. Its challenges
come from its own endpoint, `GET /federation/attestation/challenge`, since plan item S4b; before that the
attester consumed the authorization server's, from `oidf:as:challenge:*`, which it now refuses (CAS §4.1: a
challenge issued by one party must not be accepted by the other).

## The ceiling and the grant

Every ceiling here is held to the containment model in [libs/rar-model](../../libs/rar-model/README.md), and read by
its reader so a limit is compared exactly as it was written (plan item S1b):

- **At configuration.** `attestation_entitlement` (the client's ceiling, OPTIONAL) and each instance's `entitlement`
  in `attestation_instances` must be details the model accepts. A client whose ceiling it refuses has an invalid
  configuration (`invalid_client`): the PingFederate client store skips that client, and a CIMD or federation
  source refuses its whole mapping list, as it already did for any invalid entry. An instance's ceiling under a client ceiling is `authorize(instance, client, INHERIT)`,
  and the result is what the binding keeps: within the client's, with every field the client's constrains and the
  instance's leaves out taken from the client's. This used to check the instance's and keep it as written, so an
  instance that left out `max_txn_eur` had no limit whatever the client's said (F-0034). Without a client ceiling
  the instance's stands alone - CAS §6.1: "MUST be a subset of the client-level `entitlement` when both are
  present".
- **At issuance.** CAS §7: "effective = requested ∩ ceiling(instance)". An empty or absent request is issued the
  full ceiling (rule 2). Otherwise the grant is `authorize(requested, ceiling, INHERIT)`: each requested detail
  fitted to the first ceiling entry of its type that contains it, every field that entry constrains and the request
  leaves out filled from it, and the whole checked against the ceiling before it is minted (rule 1). A request
  outside the ceiling is `access_denied` (403; rule 3 with the `"reject"` this attester advertises); one the model
  cannot compare - malformed, too large, an undeclared field, an unmodelled type, or `_principal_sub` /
  `_agent_id`, which have no business in an issuance request - is `invalid_request`, naming the detail and the
  field and never the value.
- **Asserted context.** An asserted-context resolver's ceiling narrows the binding's with the model's meet
  (`intersect`): the largest details within both, pairwise by type. An evidenced EMEA-and-APAC entry under an
  asserted EMEA one is EMEA; it used to be dropped whole. Two ceilings the model cannot combine are this
  attester's own configuration, so `server_error`. Plan item X-B10 (Phase 5) rebuilds the asserted context on this.

The token gate in [client-attestation](../../libs/client-attestation/README.md#the-token-gate) holds a token request
to what is minted here, strictly: a request there must restate every field its attestation carries. The vector file
in `libs/rar-model`'s test-jar runs through the mint, the configuration and the asserted context as
`CasVectorRunnerTest`, and every attestation it mints is then read by the token gate.

## Configuration

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `challengeRequired`, `customClaimsRequired` (init-params; `customClaimsRequired` also `oidf.attestation.custom.claims.required` / `OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED`) | `false`, none | `challengeRequired` is read by the issuance servlet and the two discovery servlets, `customClaimsRequired` by issuance + CAS metadata - keep them consistent | Not checked: a value other than `true` is `false` |
| `openBaoUrl`/`openBaoToken` (init-params on the issuance servlet, used only when both are set; otherwise both come from `oidf.openbao.url`/`OIDF_OPENBAO_URL`, then `OPENBAO_ADDR`/`BAO_ADDR`/`VAULT_ADDR`, token likewise) | unset | Transit signing | Per request: a client whose `attestation_signing_key_ref` needs the vault is `server_error` |
| `OIDF_ATTESTER_FEDERATION_ENTITY`, `OIDF_ATTESTER_SIGNING_JWK` (sysprop `oidf.attester.*` or env) | unset | The entity is an extra client-metadata source, consulted before CIMD and the PF store; the JWK is the attester's private signing key, applied to every client the entity or the CIMD document describes and never read from them. A federation entity is trusted only through a chain to one of the pinned anchors (`OIDF_FEDERATION_TRUST_ANCHOR_JWKS`), and an entity the anchor stops vouching for loses its clients within 300 s | An entity named with no anchor pinned: first request, the attester refuses to build its resolvers |
| `OIDF_ATTESTER_CIMD_URL` (`oidf.attester.cimd.url`) | unset | A Client ID Metadata Document as a client source - honoured only under `OIDF_DEPLOYMENT_PROFILE=development` (plan item M-1, finding F-0067): the document hands the attester every client's bindings and trust roots, so whoever answers at the URL chooses the keys the attester accepts. X-B02 replaces it | Set outside development: first request, the `cimd` plugin is left out with an ERROR naming the variable, the discovery document's `resolver_plugins_active` omits `cimd`, and so does the CAS document's `client_metadata_sources_supported` even when `OIDF_CIMD_TRUST_BUNDLES` is set; clients only that document describes are unknown here, the other sources keep serving |
| `OIDF_DEPLOYMENT_PROFILE` | unset (production) | `development` honours `OIDF_ATTESTER_CIMD_URL`, lets an authorization_details type no model names fall back to the common fields, lets `OIDF_ATTESTER_MAX_EVIDENCE_LIFETIME_SECONDS` exceed a day, and clamps a client's `attestation_issued_ttl` to `OIDF_ATTESTER_MAX_ISSUED_TTL` instead of refusing the client; anything else, unset included, is production. Read through libs/platform's `DeploymentProfile` (plan item PR-1) | Not checked beyond that: a typo is production |
| `OIDF_RAR_MODELS_FILE`, `OIDF_RAR_MODELS` (env only) | unset (the built-in models) | The models document every ceiling here is held to, read once per classloader ([client-attestation](../../libs/client-attestation/README.md#configuration)); the token gate reads the same variables, and so does the RAR plugin from plan item S1c | A document the library refuses, an unreadable file, or both set: the issuance servlet does not start - it starts lazily, so `/federation/attestation` fails from its first request - and the log names the variable |
| `OIDF_ATTESTER_MAX_EVIDENCE_LIFETIME_SECONDS` (`oidf.attester.max.evidence.lifetime.seconds`) | 86400 | The longest lifetime the attester accepts of a piece of evidence: of the whole (`exp - iat`) when it has an `iat`, and of what is left (`exp - now`, with 60 s allowed for a clock behind the issuer's) always. Longer-lived evidence is refused (`invalid_svid` / `invalid_instance_attestation`, naming the variable). A binding lives as long as its evidence, so this bounds how long a stolen token stays presentable | Not a positive number, or above 86400 under the production profile: first request, 500 `server_error` naming the variable |
| `OIDF_ATTESTER_MAX_ISSUED_TTL` (`oidf.attester.max.issued.ttl`) | 3600 | The longest lifetime, in seconds, the attester gives an attestation (plan item S4c). A client whose `attestation_issued_ttl` is above it is refused in production (`invalid_client`, naming the property, not its value) and clamped to it with a WARN in development. Above 64800 s (18 hours) is refused in both profiles: the AI Agent Profile §5, item 1, "An issued Client Attestation's `exp` SHALL NOT exceed `iat` + 18 hours" | Not a whole number, or outside 60 to 64800: first request, 500 `server_error` naming the variable, in either profile |
| `OIDF_ATTESTER_REQUIRE_SINGLE_AUDIENCE_EVIDENCE` (`oidf.attester.require.single.audience.evidence`) | `false` | `true` refuses evidence whose `aud` names more than one party: such evidence is presentable to each of them, so the attester cannot know it was the intended one | Neither `true` nor `false`: first request, 500 `server_error` naming the variable |
| `OIDF_REDIS_URL` and its companions | unset | The shared store the challenges, proof jtis and evidence bindings live in; see [client-attestation](../../libs/client-attestation/README.md#configuration) for the URL, the CA file and the namespaces | As documented there; an unreachable store is 503 `temporarily_unavailable` here |
| `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` + `OIDF_ATTESTER_OP_ISSUER` + `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` (`OIDF_FEDERATION_IGNORE_SSL_ERRORS`; the superseded `OIDF_TRUST_CONTROLLER_HOST`, `OIDF_TRUST_ANCHOR_JWKS` and `OIDF_TRUST_CONTROLLER_IGNORE_SSL` still read, with a warning) or `OIDF_WALLET_PROVIDER_JWKS` (sysprop/env) | unset | Wallet-provider trust: federation-backed preferred, static map otherwise. `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` is the anchor's public JWK Set (the `jwks` claim of its entity configuration), captured once out of band; the keys are never fetched, and there is no fall-back to the static map (OpenID Federation 1.0 §4) | A host named without the anchor keys: first request, wallet trust is refused naming the variable |
| `OIDF_ATTESTER_SPIRE_ENTRIES_URL`, `OIDF_ENTRA_AGENT_DIRECTORY` (sysprop/env) | unset | SPIRE selector introspection; the Entra Agent ID asserted-context resolver (`OIDF_CIMD_TRUST_BUNDLES` only adds `cimd` to the CAS document's `client_metadata_sources_supported`, and only under `OIDF_DEPLOYMENT_PROFILE=development`) | Not checked: an unreachable SPIRE endpoint yields no selectors; an unparseable directory registers no resolver |
| `challengeEndpointEnabled`, `attestationSigningAlgValuesSupported`, `customClaimsSupported` (init-params on the CAS metadata servlet; `customClaimsSupported` also `oidf.attestation.custom.claims.supported` / `OIDF_ATTESTATION_CUSTOM_CLAIMS_SUPPORTED`) | `true` / `RS256,PS256,ES256` / none | What the CAS document advertises | Not checked |
| `challengeCacheMaxEntries`, `challengeTtlSeconds`, `challengeRateLimitPerWindow`, `challengeRateLimitWindowSeconds`, `challengeRateLimitMaxCallers` (init-params on `AttestationIssuanceChallengeServlet`) | 8192 / 300 / 60 / 60 / 16384 | The in-memory size and the lifetime of the attester's challenges (with Redis only the lifetime applies), and its per-caller cap. The authorization server's endpoint reads the same names for its own challenges; neither reaches the other's | Not an integer: ignored with a warning, the default used. A rate-limit value of 0 or less: the default. A TTL that is not positive, or in memory a size that is neither positive nor -1: the endpoint fails to start and its challenges keep the settings they had. With Redis only the TTL is checked; the size is not used |

### Error codes added in 0.4.0

| Code | HTTP | When |
|---|---|---|
| `instance_attestation_bound` | 401 | The evidence is already bound to a different instance key or client (and `attestation.evidence.conflict` was audited) |
| `temporarily_unavailable` | 503 | The challenge, replay or evidence-binding store could not answer; retry later with the same evidence and a fresh proof |

## Build and deploy

```bash
mvn -pl servlets/attestation-issuer -am package     # → target/attestation-issuer-<version>.jar (tests on)
```

Versions from `bom/pom.xml`. Ships two ways: bundled into `oidf.war` by [`oidf-war`](../oidf-war),
and staged by `build/pingfederate/stage-modules.sh` into the `pf-runtime.war` merge (root
context, so `/federation/attestation` serves without an `/oidf` prefix). `agent-registry` travels with
it in both - the issuance servlet imports it and fails at first use without it on the classpath.
