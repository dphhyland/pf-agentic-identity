# attestation-issuer

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Extracted with history from `pf-oidf-modules` 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The **Client Attestation issuer** - the issuing side of OAuth Attestation-Based Client Authentication.
A workload proves what it is (a SPIFFE SVID, a cloud identity token, a Wallet Instance Attestation) and
walks away with a short-lived Client Attestation bound to its own instance key, which it then presents
at the AS token endpoint. Verification lives in [`client-attestation`](../../libs/client-attestation);
the AS-side wiring in [`pf-integration`](../pf-integration), on which this module depends (client store,
wallet-provider trust, PF signing key). Written up as a spec draft in
[docs/openid-client-attestation-service-1_0.md](../../docs/openid-client-attestation-service-1_0.md).

Plain `@WebServlet` classes on the webapp classloader (not a PF-INF plugin): the jar goes into a war's
`WEB-INF/lib` and PF's Jetty scans it. Package `com.pingidentity.ps.oidf.issuer` holds the logic
(renamed from `.common` on 2026-08-15); `com.pingidentity.ps.oidf.servlet.attestation` keeps its FQCNs.

## Endpoints

| Path | Class | What |
|---|---|---|
| `POST /federation/attestation` | `AttestationIssuanceServlet` | Issuance. JSON body: `instance_key` (JWK), `instance_attestation` (alias `svid`), `proof`, optional `authorization_details` / `asserted_context`; a `client_id` is accepted but ignored and an `agent_id` is rejected. The client is resolved **from the evidence**: it is validated against every attestation client's config and the one whose trust bundle verifies it *and* whose bindings contain the resulting identity is the match. Then: instance-key proof (challenge + `jti` replay), deployment-required custom proof claims, RAR ceiling (`RarEntitlement.authorize`), optional asserted-context narrowing, `agent_id`, mint. `200 {"attestation","expires_in"}`, `Cache-Control: no-store`. |
| `GET /.well-known/client-attester`, `/federation/.well-known/client-attester` | `AttesterConfigurationServlet` | This deployment's discovery document: endpoints, evidence types (read off the validator registry), `evidence_audience`, `pop_audience` (PF's OP issuer - the "aud trap"), active resolver plugins. Cacheable, parameterless. |
| `GET /federation/attester-configuration?client_id=` | same | Per-client view: issuer, evidence audience, trust domain, RAR type names. Ceiling, bindings and signing config are deliberately not exposed. |
| `GET /.well-known/client-attestation-service` | `ClientAttestationServiceMetadataServlet` | The fixed CAS 1.0 §5 document: required request members, required proof claims (`aud`, `jti`, `challenge` when required, plus custom), claims minted. Reads the same config the issuance servlet enforces, so advertisement and enforcement cannot drift. |
| `POST /federation/attestation-challenge` | `ClientAttestationChallengeServlet` (in `client-attestation`) | The challenge endpoint - it ships in the lib jar, not here. |

## Evidence validators

`InstanceAttestationValidators.defaults()` is the catalogue; adding a type is registering one plugin.
Ids (the client's `attestation_evidence`): `spiffe-jwt` (`SpiffeInstanceAttestationValidator`),
`gke-sa-token`, `gcp-id-token`, `eks-sa-token`, `aws-sts-web-identity`, `aks-sa-token`,
`azure-mi-token` (each resolves to a SPIFFE identity, `format() == "spiffe"`), and
`wallet-instance-attestation` (`WalletInstanceAttestationValidator`, format `wallet`). The wallet entry
is registered with an *unconfigured* key resolver so the id is always discoverable and a WIA fails
loudly until wallet-provider trust is configured. `SpireSelectorIntrospector` (optional) merges SPIRE
registration selectors into the `workload` claim.

## Minting

`AttestationMinter`: `iss` (the client's `attestation_issuer`), `sub` = `client_id`, `iat`/`exp`
(`attestation_issued_ttl`), `cnf` (the instance key), `workload` (binding metadata + introspected
attributes), `authorization_details` when an entitlement was granted, `agent_id` when a registry is
configured. Signed by the client's own attester key (`AttesterSigningKey`): **OpenBao transit**
(`attestation_signing_key_ref`, key never leaves the vault) or an inline private JWK
(`attestation_signing_jwk`, dev). `agent_id` (via [`agent-registry`](../../libs/agent-registry)) is
opt-in: nothing in this module configures `AgentRegistrySupport`; unconfigured = no claim, configured but
broken = `server_error`, never a silent attestation without identity.

Client config is the PF client's `attestation_*` extended properties (`AttestationIssuanceConfig`),
resolved through `PfIssuanceClientResolver`, with a CIMD document and/or an OpenID Federation entity
prepended when configured (`AttesterResolvers`).

## Configuration

| Setting | Where | Notes |
|---|---|---|
| `challengeRequired`, `customClaimsRequired` | init-param (`customClaimsRequired` also `oidf.attestation.custom.claims.required` / `OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED`) | `challengeRequired` is read by all three servlets, `customClaimsRequired` by issuance + CAS metadata - keep them consistent. |
| `openBaoUrl`/`openBaoToken` | init-param, else `oidf.openbao.url`/`OIDF_OPENBAO_URL` (then `OPENBAO_ADDR`/`BAO_ADDR`/`VAULT_ADDR`), token likewise | Transit signing. |
| `OIDF_ATTESTER_CIMD_URL`, `OIDF_ATTESTER_FEDERATION_ENTITY`, `OIDF_ATTESTER_SIGNING_JWK` | sysprop `oidf.attester.*` or env | Extra client-metadata sources. |
| `OIDF_TRUST_CONTROLLER_HOST` + `OIDF_ATTESTER_OP_ISSUER` (`OIDF_TRUST_CONTROLLER_IGNORE_SSL`) or `OIDF_WALLET_PROVIDER_JWKS` | sysprop/env | Wallet-provider trust: federation-backed preferred, static map otherwise. |
| `OIDF_ATTESTER_SPIRE_ENTRIES_URL`, `OIDF_ENTRA_AGENT_DIRECTORY` | sysprop/env | SPIRE selector introspection; the Entra Agent ID asserted-context resolver (`OIDF_CIMD_TRUST_BUNDLES` only adds `cimd` to the CAS document's `metadata_sources`). |
| `challengeEndpointEnabled`, `attestationSigningAlgValuesSupported`, `customClaimsSupported` | init-param on the CAS metadata servlet | |

## Build and deploy

```bash
mvn -pl servlets/attestation-issuer -am package     # → target/attestation-issuer-0.1.0.jar (tests on)
```

Versions from `bom/pom.xml`. Ships two ways: bundled into `oidf.war` by [`oidf-war`](../oidf-war),
and staged by `deploy/pingfederate/build/stage-modules.sh` into the `pf-runtime.war` merge (root
context, so `/federation/attestation` serves without an `/oidf` prefix). `agent-registry` travels with
it in both - the issuance servlet imports it and fails at first use without it on the classpath.
