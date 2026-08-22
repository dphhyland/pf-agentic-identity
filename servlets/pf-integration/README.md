# pf-integration

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly the standalone repo [`dphhyland/pf-integration`](https://github.com/dphhyland/pf-integration) — still live for existing consumers, **backports only**. Absorbed with history 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The PingFederate glue for [`client-attestation`](../../libs/client-attestation) and
[`openid-federation`](../../libs/openid-federation): the federation entity servlet, OpenID Federation
§12.1 automatic + §12.2 explicit registration into PF's client store, the OGNL issuance-criteria hooks,
and the token-endpoint filters that give PF `attest_jwt_client_auth`. Compiles against the PF SDK
(`provided`) - it builds only where `pf-protocolengine` + `pingfederate-sdk` are in `~/.m2`. How the
filter and the OGNL hooks sit in the wider attestation pipeline - with standards alignment, test
coverage and the open gaps - is
[docs/client-attestation-architecture.md](../../docs/client-attestation-architecture.md).

Everything here is a plain `@WebServlet` / `javax.servlet.Filter`, not a PF-INF plugin: the jar sits in
a war's `WEB-INF/lib`, PF's Jetty annotation-scans it, and it runs on the webapp classloader. The
`finalName` is `oidf`, so this module produces **`oidf.jar`** - the war is assembled by
[`oidf-war`](../oidf-war) (its own module, to avoid a reactor cycle with `attestation-issuer`).

## Packages

- `com.pingidentity.ps.oidf.pf` - PF-facing infrastructure: `ClientStore` / `PfMgmtClientStore`
  (PF's `ClientManager`), `PfJwksSigningKeyProvider` (PF's active JWKS RSA key, via
  `JwksEndpointKeyAccessor`), `FederationAttesterKeyResolver` + `FederationWalletProviderKeyResolver`
  (attester / wallet-provider keys trusted only when the entity's trust chain resolves to the anchor),
  `FallbackAttesterKeyResolver` (static dev list first, federation for everything else), `PfDataSources`.
  Renamed from `.common` on 2026-08-15 (split-package unwind).
- `com.pingidentity.ps.oidf.servlet.clientregistration` (+ `.utils`) and
  `com.pingidentity.ps.oidf.servlet.trustanchor` - **unchanged FQCNs**: they are config-facing (OGNL
  criteria in the deploying repo's Terraform ([pf-oidf-modules](https://github.com/dphhyland/pf-oidf-modules/blob/main/deploy/pingfederate/terraform)), filter
  classes in `build/pingfederate/assemble-pf-runtime-war.sh`).

## Endpoints

| Path | Class | What |
|---|---|---|
| `GET /.well-known/openid-federation`, `/federation/entity`, `/federation/fetch`, `/federation/list`, `/federation/resolve` | `OpenIdFederationServlet` (`loadOnStartup=1`) | The federation entity: entity configuration + subordinate/fetch/list/resolve, signed with PF's own JWKS key. Prewarms subordinates at deploy, so the first token exchange never carries a cold fetch. |
| `GET`/`POST /federation/agents/*`, `/federation/resources/*` | `HostedEntityServlet` | Entity Configurations for entities this authority hosts (`…/{id}/.well-known/openid-federation`); `POST` to the collection root enrols one (static admin bearer, constant-time compare). |
| `POST /federation/register` | `OpenIdRegistrationServlet` | §12.2 explicit registration: `entity-statement+jwt` or `trust-chain+json` in, signed `explicit-registration-response+jwt` out, PF client provisioned. The path is what `FederationService` advertises as `federation_registration_endpoint`. |
| `GET /federation/registered-clients` | `RegisteredClientsServlet` | Clients this module put into PF (`status=registered` / `auto_registered`). Unauthenticated - a demo/operator surface. |

Filters - not annotated (an annotation would bind them to the module's own context, not PF's), so
`build/pingfederate/assemble-pf-runtime-war.sh` writes them into `pf-runtime.war`'s `web.xml`:

| Filter name | Class | Over | Does |
|---|---|---|---|
| `ClientAttestationAuth` | `ClientAttestationAuthFilter` | `/as/token.oauth2` | `attest_jwt_client_auth`: verifies `OAuth-Client-Attestation` (+`-PoP` or `DPoP`), publishes the verified context for the issuance criterion and the token attribute mapping, then forwards a wrapped request that authenticates to PF as native `private_key_jwt` - a `client_assertion` signed with **that client's own key**, whose public half is already in the client's registered JWKS. Fail-closed on a bad attestation; **no attestation header = pass-through untouched**, so it can never widen access. Keys from `OIDF_BRIDGE_SIGNING_KEYS` + `OIDF_BRIDGE_SIGNER_BACKING`; **nothing configured = the filter refuses to start**, unless `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false`. |
| `OidfAutoRegistration` | `TokenEndpointAutoRegistrationFilter` | `/as/token.oauth2` | §12.1: a client whose `client_assertion` carries a `trust_chain` header is validated and materialised in PF's client store before PF authenticates it (leaf must advertise `client_registration_types` ⊇ `automatic`). Fail-open. An `auto_registered` client is refreshed from its re-validated chain (`ClientStore.update`) - that is §12.1 key rotation; manually-registered clients are never touched. |
| `SsfLogoutSignal` | `…servlet.ssf.LogoutEventFilter` | `/idp/init_logout.openid` | Lives in [`ssf`](../ssf); listed here because the same script registers it. |

## OGNL hooks (engine classloader)

`ClientAttestationUtils.validateClientAttestation(#this)` and `OIDFederationUtils.validateTrustChain(#this, …)`
are the token-endpoint issuance criteria ([`access-token-mappings.tf`](https://github.com/dphhyland/pf-oidf-modules/blob/main/deploy/pingfederate/terraform/access-token-mappings.tf), in the deploying repo);
`attestationClaim(#this, name)` and `delegationActChain(#this)` feed access-token attribute mappings.
Both hooks read `context.HttpRequest` / `context.ClientId` from the criteria map. Attester trust:
`oidf.mock.attesters` (static JWKS file, dev) first, federation trust chain otherwise; the AS-side
required-claims policy comes from `oidf.attestation.required.claims` or `extproperties.attestation_required_claims`.

The OGNL hooks run on PF's **engine** classloader, which does not see `pf-runtime.war`'s `WEB-INF/lib` -
so the deploy also copies the jars into `server/default/deploy/`. The filter and the criterion therefore
verify the same request on two classloaders with two replay caches; each sees a PoP `jti` once, genuine
replays fail in both. Webapp and engine talk only through string-keyed request attributes.

## Configuration

Servlet init-params first, then env (`FederationConfiguration.setting` / `RegistrationConfiguration.setting`):

| Setting | init-param / env | Notes |
|---|---|---|
| Trust anchors | `trustAnchorIssuers` / `OIDF_FEDERATION_TRUST_ANCHORS` | **Required at boot** - `OpenIdFederationServlet` is `loadOnStartup=1` and throws without one, taking `pf-runtime.war` down with it. |
| Trust controller | `trustControllerHost` / `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` (+ `…_BASE_URL`, `ignoreSslErrors` / `OIDF_FEDERATION_IGNORE_SSL_ERRORS`) | Read by the servlets, the auto-registration filter and the OGNL hooks directly - the hooks cannot wait for `/federation/register` to have populated `RegistrationConfiguration`. |
| Federation entity | `subordinates` / `OIDF_FEDERATION_SUBORDINATES`, `signingAlgorithm` / `OIDF_FEDERATION_SIGNING_ALG` (RS256/PS256), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS`, `cors*` init-params | |
| Registration | `subordinateStatementCacheMaxEntries` (256, `-1` unbounded), `trustChainEntryMaxAgeSeconds` (60), `acceptedSigningAlgorithms`, `signingAlgorithm` (RS256/PS256) | init-params only - on the registration servlet and (bar `signingAlgorithm`) the auto-registration filter |
| Hosted entities | `authorityEntityId` / `oidf.authority.entity_id` / `OIDF_AUTHORITY_ENTITY_ID` (required by `HostedEntityServlet`), `adminToken`, `openBaoUrl`/`openBaoToken`, `jdbcUrl`+`jdbcUsername`+`jdbcPassword` or `dataStoreId` (`OIDF_AUTHORITY_*`) | init-param, then sysprop, then env |
| Bridge signing | `OIDF_BRIDGE_SIGNER_BACKING` (`vault`\|`config`) + `OIDF_BRIDGE_SIGNING_KEYS` (path to a JSON map of client id -> `{"key_ref": …}` or `{"jwk": {…}}`); `OIDF_BRIDGE_VAULT_ADDR`/`_TOKEN` when `vault` | Per client. Exactly one form each, and the declared backing is enforced - an inline JWK under `vault` is refused, so a demo key cannot ride into production in a config file. A client with no key cannot authenticate; every other client is unaffected. Nothing configured at all is a **boot failure**, not a silent degradation, unless `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false` |
| ~~`OIDF_BRIDGE_PRIVATE_JWK`~~, ~~`OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK`~~ | — | **Superseded; both refuse startup if set.** The first held one deployment-wide key; the second kept its outgoing public half in every client's JWKS during a rotation overlap. Neither has meaning once signing is per client, and a setting that looks configured while doing nothing is worse than one that is absent |

## Build and deploy

```bash
mvn -pl servlets/pf-integration -am package     # → target/oidf.jar (tests on)
```

Versions come from `bom/pom.xml` (no parent pom). Consumers: `attestation-issuer` and `ssf` depend on
this jar; `oidf-war` bundles it into `oidf.war`; `build/pingfederate/stage-modules.sh` stages it
into the `pf-runtime.war` merge (root context - endpoints serve without an `/oidf` prefix) and the
engine deploy dir.
