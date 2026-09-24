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
| `GET /.well-known/openid-federation`, `/federation/fetch`, `/federation/list`, `/federation/resolve` (and the non-standard, unadvertised `/federation/entity`) | `OpenIdFederationServlet` (`loadOnStartup=1`) | The federation entity (OpenID Federation 1.0 §8): its entity configuration; fetch by `sub` (§8.1); list with repeatable `entity_type` and `intermediate` (§8.2); resolve to a signed `resolve-response+jwt` against the pinned anchors (§8.3), for this entity, its subordinates and the entities it hosts unless `OIDF_FEDERATION_RESOLVE_DISCOVERY=any`. Errors are §8.9 JSON. Signed with PF's own JWKS key. Prewarms subordinates at deploy, so the first token exchange never carries a cold fetch. |
| `GET`/`POST /federation/agents/*`, `/federation/resources/*` | `HostedEntityServlet` | Entity Configurations for entities this authority hosts (`…/{id}/.well-known/openid-federation`); `POST` to the collection root enrols one (static admin bearer, constant-time compare). |
| `POST /federation/register` | `OpenIdRegistrationServlet` | §12.2 explicit registration: `entity-statement+jwt` or `trust-chain+json` in, PF client provisioned, and a signed `explicit-registration-response+jwt` answered **200** (§12.2.3) - `aud` the RP, `exp` the registration's expiry, `trust_anchor` the anchor reached, `authority_hints` the RP's Immediate Superior, `jwks` a verbatim copy of the RP's own. Refusals are §8.9 JSON. The path is what `FederationService` advertises as `federation_registration_endpoint`. |
| `GET /federation/registered-clients` | `RegisteredClientsServlet` | Clients this module put into PF (`status=registered` / `auto_registered`). Unauthenticated - a demo/operator surface. |

Filters - not annotated (an annotation would bind them to the module's own context, not PF's), so
`build/pingfederate/assemble-pf-runtime-war.sh` writes them into `pf-runtime.war`'s `web.xml`:

| Filter name | Class | Over | Does |
|---|---|---|---|
| `ClientAttestationAuth` | `ClientAttestationAuthFilter` | `/as/token.oauth2` | `attest_jwt_client_auth`: verifies `OAuth-Client-Attestation` (+`-PoP` or `DPoP`), publishes the verified context for the issuance criterion and the token attribute mapping, then forwards a wrapped request that authenticates to PF as native `private_key_jwt` - a `client_assertion` signed with **that client's own key**, whose public half is already in the client's registered JWKS. Fail-closed on a bad attestation; **no attestation header = pass-through untouched**, so it can never widen access. Keys from `OIDF_BRIDGE_SIGNING_KEYS` + `OIDF_BRIDGE_SIGNER_BACKING`; **nothing configured = the filter refuses to start**, unless `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false`. |
| `OidfAutoRegistration` | `TokenEndpointAutoRegistrationFilter` | `/as/token.oauth2` | §12.1 and §12.3, before PF authenticates the request. The client is the `client_assertion`'s `sub`, else `client_id`. One PF doesn't know is registered from the chain in the assertion's `trust_chain` header (leaf must advertise `client_registration_types` ⊇ `automatic`), checked as it stands - nothing is fetched on a presented chain's say-so - and otherwise by discovery from the client's own configuration. An RP that publishes keys for `openid_relying_party` is registered with them. An `auto_registered` one is renewed in its last `OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS`, or at once when the request presents a newer entity configuration with other keys or metadata (§12.5 - how key rotation works); an older one is never used. Past its expiry it is renewed from the presented chain or by discovery, or refused: **401 `invalid_client`**, or **503 `temporarily_unavailable`** (with `Retry-After`) when the federation can't be reached or too many registrations are under way. An explicit registration is only ever renewed by its RP registering again. Clients this module didn't register are never touched. **Fail-closed** from 0.3.0 (`OIDF_AUTO_REGISTRATION_FAIL_CLOSED=false` restores 0.2.0's pass-through). Starts the expiry sweeper. |
| `OidfFrontChannelAutoRegistration` | `FrontChannelAutoRegistrationFilter` | `/as/authorization.oauth2`, `/as/par.oauth2` | §12.1.1: an RP PF doesn't know sends its request with its Entity Identifier as `client_id` and proves it holds its keys - a signed request object, or at PAR a `private_key_jwt` assertion. The request object is held to §12.1.1.1 before anything is fetched (`aud` this OP alone, `iss` and `client_id` the RP, no `sub`, `jti`, `exp`); the RP's chain is resolved (its `trust_chain` header tried as it stands, else discovery); it is registered from its `openid_relying_party` metadata with the keys it publishes for that type (`jwks`, `signed_jwks_uri` or `jwks_uri`), once the proof verifies against them, and its `jti` is spent. Registered with signed requests required (or PAR-only, if it proved itself at PAR), PKCE, its redirect URIs, and `code` / `openid` unless it declared otherwise. A `request_uri` is never dereferenced here. Refusals: JSON at PAR, an error page - never a redirect - at the authorization endpoint (§12.1.3). Mapped after `Fapi2Profile` and `OAuthErrorDescription` (checked by the assemble script). |
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
| Trust anchor keys | `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` / `oidf.federation.trust.anchor.jwks` | **Required whenever the trust controller is set.** The anchor's public JWK Set - the `jwks` claim of its entity configuration - captured once, out of band (OpenID Federation 1.0 §4), with `tools/pin-trust-anchor.py`. Nothing validates a chain without it: the OGNL criteria refuse, `/federation/register` fails its init, and both token-endpoint filters log an error at startup and refuse per request. They deliberately do not fail init, because this war also serves the entity's own `/.well-known/openid-federation`, which a PF that is its own anchor must publish before its keys can be captured. A value that is set but is not a usable public key set (private or symmetric keys, missing or duplicate `kid`) does fail filter init. Statically trusted attesters (`oidf.mock.attesters`) resolve without it. On an anchor key rollover (§11.2) add the new key to this set before the anchor starts signing with it. |
| Federation entity | `subordinates` / `OIDF_FEDERATION_SUBORDINATES`, `signingAlgorithm` / `OIDF_FEDERATION_SIGNING_ALG` (RS256/PS256), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS`, `organizationName` / `OIDF_FEDERATION_ORGANIZATION_NAME`, `clientRegistrationTypes` / `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES` (default `automatic,explicit`), `resolveDiscovery` / `OIDF_FEDERATION_RESOLVE_DISCOVERY` (`known` or `any`), `cors*` init-params | The resolve endpoint is on whenever trust anchors are pinned (`OIDF_FEDERATION_TRUST_ANCHOR_JWKS`), and resolves against all of them |
| Registration | `subordinateStatementCacheMaxEntries` (256, `-1` unbounded), `trustChainEntryMaxAgeSeconds` (60), `acceptedSigningAlgorithms`, `signingAlgorithm` (RS256/PS256) | init-params only - on the registration servlet and (bar `signingAlgorithm`) the auto-registration filter |
| Front-channel registration (§12.1.1) | `OIDF_AUTO_REGISTRATION_FRONT_CHANNEL` (`true`), `OIDF_AUTO_REGISTRATION_AUTHZ_ERROR_MODE` (`page` \| `passthrough`), `OIDF_AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS` (`allow` \| `refuse`), `OIDF_AUTO_REGISTRATION_DEFAULT_SCOPES` (`openid`), `OIDF_AUTO_REGISTRATION_REQUIRE_PAR` (`false`), `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE` (`true`), `OIDF_AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES` (65536), `OIDF_FEDERATION_ERROR_PAGE` (a file with `${error}`, `${errorDescription}`, `${trackingId}`; unset uses a built-in page) | An encrypted request object can only be read as far as its header, so under `allow` PingFederate checks its claims and signature, after the RP is registered from its published metadata; `refuse` turns such requests away. An error page that is named but cannot be read stops the filter starting |
| Registration work limits (§18.1) | `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS` (8), `OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS` (2000) | Shared by both registration filters. One registration of a client at a time; so many at once across all clients; the rest get a 503 with `Retry-After`. There is no per-client rate limit on purpose - a stranger could spend it in the real client's name - so put a per-source rate limit in front of PingFederate if unauthenticated load is a worry |
| Registration lifetime (§12.3) | `OIDF_REGISTRATION_MAX_TTL_SECONDS` (86400), `OIDF_REGISTRATION_MIN_TTL_SECONDS` (60), `OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS` (300), `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT` (`refuse` \| `disable` \| `log`, default `refuse`), `OIDF_REGISTRATION_SWEEP_INTERVAL_SECONDS` (300, `0` off), `OIDF_AUTO_REGISTRATION_FAIL_CLOSED` (`true`); each also as a system property (`oidf.registration.max.ttl.seconds`, …, `oidf.auto.registration.fail.closed`) | A registration ends at its chain's expiry or the maximum, whichever is sooner; a chain that expires sooner than the minimum registers nothing. `disable` also disables the client, `log` only records the expiry. A value that doesn't parse - including a fail-closed switch that is neither `true` nor `false` - stops the filter starting |
| Hosted entities | `authorityEntityId` / `oidf.authority.entity_id` / `OIDF_AUTHORITY_ENTITY_ID` (required by `HostedEntityServlet`), `adminToken`, `openBaoUrl`/`openBaoToken`, `jdbcUrl`+`jdbcUsername`+`jdbcPassword` or `dataStoreId` (`OIDF_AUTHORITY_*`) | init-param, then sysprop, then env |
| Bridge signing | `OIDF_BRIDGE_SIGNER_BACKING` (`vault`\|`config`) + `OIDF_BRIDGE_SIGNING_KEYS` (path to a JSON map of client id -> `{"key_ref": …, "attesters": […]}` or `{"jwk": {…}, "attesters": […]}`); `OIDF_BRIDGE_VAULT_ADDR`/`_TOKEN` when `vault` | Per client. Exactly one key form each, and the declared backing is enforced - an inline JWK under `vault` is refused, so a demo key cannot ride into production in a config file. A client with no key cannot authenticate; every other client is unaffected. Nothing configured at all is a **boot failure**, not a silent degradation, unless `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false` |
| Attester binding | `"attesters": ["https://attester.example"]` in each client's `OIDF_BRIDGE_SIGNING_KEYS` entry; `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING` (default `true`) | Federation trust says an attester is genuine; this says it is *this client's*. An attestation from a trusted attester the client is not bound to is a 401. A client entry with no `attesters` is a 401 too, by default - any trusted attester could otherwise vouch for it. `=false` lets unbound clients accept any trusted attester; an explicit binding is still enforced |
| ~~`OIDF_BRIDGE_PRIVATE_JWK`~~, ~~`OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK`~~ | — | **Superseded; both refuse startup if set.** The first held one deployment-wide key; the second kept its outgoing public half in every client's JWKS during a rotation overlap. Neither has meaning once signing is per client, and a setting that looks configured while doing nothing is worse than one that is absent |

## Upgrading from 0.2.0

- **Declare the four new extended properties** before deploying - `federation_registration_expires_at`,
  `federation_trust_anchor`, `federation_entity_type` and `federation_registration_disabled_at` (the full
  list is [docs/extended-properties.json](../../docs/extended-properties.json)). PF drops a property it
  doesn't know, and a client whose expiry is dropped looks expired on every request.
- **Clients registered before 0.3.0 have no recorded expiry, so they count as expired.** An automatic
  one is renewed on its next token request and carries on. An explicit one is refused until its RP
  registers again. To give RPs time, set `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log` for the migration -
  expiries are then recorded and logged but not enforced - and set it back afterwards.
- **An explicit registration now lasts only as long as its chain**, often an hour. RPs must register
  again before the response's `exp`, as §12.3 says.
- **The token endpoint is fail-closed.** A failed registration or an expired one is answered with a 401
  or 503 rather than passed on to PF.
- **The OGNL criterion refuses an expired registration** before it looks at the chain, so a deployment
  that relies on the criterion alone (no token-endpoint filter) enforces §12.3 too.
- **The sweeper disables expired clients** every five minutes. It never deletes one, and a renewal
  enables it again. A client an operator disabled stays disabled.
- **RPs can now register at the authorization and PAR endpoints** (`OIDF_AUTO_REGISTRATION_FRONT_CHANNEL=false`
  turns it off). The assemble script maps the new filter; a war assembled by an older script has no
  front-channel registration.
- **An RP that publishes keys for `openid_relying_party` is registered with them**, at every endpoint - not
  with its Federation Entity Keys, as before. An RP that publishes none keeps the old behaviour at the token
  endpoint; at the authorization and PAR endpoints it cannot register.
- **A chain presented in a request is checked as it stands**, and nothing is fetched on its say-so. A
  client whose presented chain is incomplete is found by discovery instead, which costs a few fetches.
- **The registration filters' init-params are parsed strictly.** A value that doesn't parse stops the filter
  starting; it used to mean the default, quietly.

## Build and deploy

```bash
mvn -pl servlets/pf-integration -am package     # → target/oidf.jar (tests on)
```

Versions come from `bom/pom.xml` (no parent pom). Consumers: `attestation-issuer` and `ssf` depend on
this jar; `oidf-war` bundles it into `oidf.war`; `build/pingfederate/stage-modules.sh` stages it
into the `pf-runtime.war` merge (root context - endpoints serve without an `/oidf` prefix) and the
engine deploy dir.
