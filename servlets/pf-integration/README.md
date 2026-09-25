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
| `GET /.well-known/openid-federation`, `/federation/fetch`, `/federation/list`, `/federation/resolve`, `/federation/trust_mark`, `/federation/trust_marked_list`, `/federation/historical_keys`; `POST /federation/trust_mark_status` (and the non-standard, unadvertised `/federation/entity`) | `OpenIdFederationServlet` (`loadOnStartup=1`) | The federation entity (OpenID Federation 1.0 §8): its entity configuration; fetch by `sub` (§8.1); list with repeatable `entity_type` and `intermediate` (§8.2); resolve to a signed `resolve-response+jwt` against the pinned anchors (§8.3), carrying the subject's Trust Marks that verified against the anchor reached and expiring with the soonest of them, for this entity, its subordinates and the entities it hosts unless `OIDF_FEDERATION_RESOLVE_DISCOVERY=any`. As a Trust Mark Issuer (types in `OIDF_FEDERATION_TRUST_MARK_TYPES`): the mark of a type it issues an entity (§8.6, `application/trust-mark+jwt`), a mark's status (§8.4, POST only, a signed `trust-mark-status-response+jwt`) and the entities holding a type (§8.5); the list endpoint's `trust_marked` and `trust_mark_type` filters work. With `OIDF_FEDERATION_HISTORICAL_KEYS=true` it notices, when it starts, that PF's signing key changed since last time, and publishes the keys it signed with before (§8.7, a signed `jwk-set+jwt`); starting with a key that was revoked is refused. Errors are §8.9 JSON. Signed with PF's own JWKS key. Prewarms subordinates at deploy, so the first token exchange never carries a cold fetch. |
| `GET`/`POST /federation/agents/*`, `/federation/resources/*` | `HostedEntityServlet` | Entity Configurations for entities this authority hosts (`…/{id}/.well-known/openid-federation`); `POST` to the collection root enrols one (static admin bearer, constant-time compare), optionally with its own `metadataPolicy` - and, with `hosted_entity_enrol` in `OIDF_PDP_DECISION_POINTS`, once the policy decision point agrees (a denial is 403 `access_denied`). The federation servlet configures hosting at start-up when `OIDF_AUTHORITY_ENTITY_ID` is set in the environment or a system property, so hosted entities are served from the first request. |
| `POST /federation/register` | `OpenIdRegistrationServlet` | §12.2 explicit registration: `entity-statement+jwt` or `trust-chain+json` in, PF client provisioned, and a signed `explicit-registration-response+jwt` answered **200** (§12.2.3) - `aud` the RP, `exp` the registration's expiry, `trust_anchor` the anchor reached, `authority_hints` the RP's Immediate Superior, `jwks` a verbatim copy of the RP's own. Refusals are §8.9 JSON. The path is what `FederationService` advertises as `federation_registration_endpoint`. |
| `GET`/`POST /federation/admin/trust-marks` (`/revoke`, `/audit`), `/federation/admin/keys` (`/revoke`), `/federation/admin/entities` (`/audit`, `/suspend`, `/reactivate`, `/revoke`, `/metadata`, `/metadata-policy`, `/rotate-key`) | `FederationAdminServlet`, `HostedEntityAdmin` | Grants and revokes the Trust Marks this entity issues, lists grants by `sub` or `trust_mark_type`, and shows one grant's history; lists the keys PF signed with before and revokes one (reason `unspecified`, `compromised` or `superseded`, or none - the key in use is revoked by rotating it first); lists every hosted entity whatever its status, shows one with its metadata and policy and its history, and runs its lifecycle - suspend, reactivate, revoke (permanent), replace its metadata, replace its own `metadata_policy` (refused with `invalid_metadata` unless it composes with the domain default, which it can only narrow), move it to a new hosting key (refused unless the key signs). The admin bearer token (`OIDF_AUTHORITY_ADMIN_TOKEN`, constant-time; unset answers 401). Only a configured type, and a hosted-only type only to an active hosted entity. Every change records its actor - `admin:` and eight hex digits of the token's SHA-256, plus `X-Federation-Actor` when sent - in the grant's history and PF's audit log. Granting again revokes every mark minted under the grant before. |
| `GET /federation/registered-clients` | `RegisteredClientsServlet` | Clients this module put into PF (`status=registered` / `auto_registered`). Unauthenticated - a demo/operator surface. |

Filters - not annotated (an annotation would bind them to the module's own context, not PF's), so
`build/pingfederate/assemble-pf-runtime-war.sh` writes them into `pf-runtime.war`'s `web.xml`:

| Filter name | Class | Over | Does |
|---|---|---|---|
| `ClientAttestationAuth` | `ClientAttestationAuthFilter` | `/as/token.oauth2` | `attest_jwt_client_auth`: verifies `OAuth-Client-Attestation` (+`-PoP` or `DPoP`), publishes the verified context for the issuance criterion and the token attribute mapping, then forwards a wrapped request that authenticates to PF as native `private_key_jwt` - a `client_assertion` signed with **that client's own key**, whose public half is already in the client's registered JWKS. Fail-closed on a bad attestation; **no attestation header = pass-through untouched**, so it can never widen access. Keys from `OIDF_BRIDGE_SIGNING_KEYS` + `OIDF_BRIDGE_SIGNER_BACKING`; **nothing configured = the filter refuses to start**, unless `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false`. |
| `OidfAutoRegistration` | `TokenEndpointAutoRegistrationFilter` | `/as/token.oauth2` | §12.1 and §12.3, before PF authenticates the request. The client is the `client_assertion`'s `sub`, else `client_id`. One PF doesn't know is registered from the chain in the assertion's `trust_chain` header (leaf must advertise `client_registration_types` ⊇ `automatic`), checked as it stands - nothing is fetched on a presented chain's say-so - and otherwise by discovery from the client's own configuration. An RP that publishes keys for `openid_relying_party` is registered with them. An `auto_registered` one is renewed in its last `OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS`, or at once when the request presents a newer entity configuration with other keys or metadata (§12.5 - how key rotation works); an older one is never used. Past its expiry it is renewed from the presented chain or by discovery, or refused: **401 `invalid_client`**, or **503 `temporarily_unavailable`** (with `Retry-After`) when the federation can't be reached or too many registrations are under way. An explicit registration is only ever renewed by its RP registering again. Clients this module didn't register are never touched. **Fail-closed** from 0.3.0 (`OIDF_AUTO_REGISTRATION_FAIL_CLOSED=false` restores 0.2.0's pass-through). Starts the expiry sweeper. |
| `OidfFrontChannelAutoRegistration` | `FrontChannelAutoRegistrationFilter` | `/as/authorization.oauth2`, `/as/par.oauth2` | §12.1.1: an RP PF doesn't know sends its request with its Entity Identifier as `client_id` and proves it holds its keys - a signed request object, or at PAR a `private_key_jwt` assertion. The request object is held to §12.1.1.1 before anything is fetched (`aud` this OP alone, `iss` and `client_id` the RP, no `sub`, `jti`, `exp`); the RP's chain is resolved (its `trust_chain` header tried as it stands, else discovery); it is registered from its `openid_relying_party` metadata with the keys it publishes for that type (`jwks`, `signed_jwks_uri` or `jwks_uri`), once the proof verifies against them, and its `jti` is spent. Registered with signed requests required (or PAR-only, if it proved itself at PAR), PKCE, its redirect URIs, and `code` / `openid` unless it declared otherwise. Every later request from it is held to the same: §12.1.1 says *every* authentication request demonstrates control of the RP's keys, so its proof is checked against §12.1.1.1 again, verified with the keys it is registered with (a `jwks_uri` is fetched at most once a minute) and its `jti` spent. A `request_uri` is never dereferenced here. Refusals: JSON at PAR, an error page - never a redirect - at the authorization endpoint (§12.1.3). Mapped after `Fapi2Profile` and `OAuthErrorDescription` (checked by the assemble script). |
| `SsfLogoutSignal` | `…servlet.ssf.LogoutEventFilter` | `/idp/init_logout.openid` | Lives in [`ssf`](../ssf); listed here because the same script registers it. |

## OGNL hooks (engine classloader)

`ClientAttestationUtils.validateClientAttestation(#this)` and `OIDFederationUtils.validateTrustChain(#this, …)`
are the token-endpoint issuance criteria ([`access-token-mappings.tf`](https://github.com/dphhyland/pf-oidf-modules/blob/main/deploy/pingfederate/terraform/access-token-mappings.tf), in the deploying repo);
`OIDFederationUtils.federationPolicy(#this)` is the token-issuance policy check on its own, for a mapping that
doesn't validate the chain - `validateTrustChain` makes the same check once the chain validates, so a mapping
needs one or the other (see [Asking a policy engine](#asking-a-policy-engine-authzen)).
`attestationClaim(#this, name)` and `delegationActChain(#this)` feed access-token attribute mappings.
Both hooks read `context.HttpRequest` / `context.ClientId` from the criteria map. Attester trust:
`oidf.mock.attesters` (static JWKS file, dev) first, federation trust chain otherwise; the AS-side
required-claims policy comes from `oidf.attestation.required.claims` or `extproperties.attestation_required_claims`.

The OGNL hooks run on PF's **engine** classloader, which does not see `pf-runtime.war`'s `WEB-INF/lib` -
so the deploy also copies the jars into `server/default/deploy/`. The filter and the criterion therefore
verify the same request on two classloaders with two replay caches; each sees a PoP `jti` once, genuine
replays fail in both. Webapp and engine talk only through string-keyed request attributes.

## Asking a policy engine (AuthZEN)

A valid chain says an entity is who it claims to be and what its superiors allow it. Whether this deployment
wants it - this agent, now, with these scopes - is often a question for a policy engine. PF asks one before it
registers a client, and before it enrols a hosted entity if told to, over the AuthZEN 1.0 Access Evaluation API:
PingAuthorize, `services/gm-api`, or any PDP that speaks it.

It asks after the chain has validated and the federation's own checks have passed (a superior's metadata
policy, the Trust Marks the deployment requires), and before anything is stored - at every registration
endpoint, and at every renewal. The PDP hears:

```json
{
  "subject": {"type": "federation_entity", "id": "https://agent.example.com",
              "properties": {"entity_types": ["oauth_client", "federation_entity"],
                             "trust_anchor": "https://ta.example.com",
                             "trust_marks": ["https://ta.example.com/marks/certified"]}},
  "action": {"name": "federation.register.automatic",
             "properties": {"endpoint": "token", "entity_type": "oauth_client"}},
  "resource": {"type": "openid_provider", "id": "https://pf.example.com"},
  "context": {"scope": "read write", "grant_types": ["client_credentials"],
              "chain_expires_at": 1790000000, "request": {"tracking_id": "tid-42"}}
}
```

`action.name` is `federation.register.explicit` at `/federation/register`, and `endpoint` says which of `token`,
`authorization`, `par` or `registration` the request came through. `trust_marks` lists the marks PF verified,
and is there only when the deployment requires marks - each one costs a chain resolution. What the entity asks
for is its metadata after every superior's policy. Its keys and statements are never sent. `X-Request-ID` is
PF's tracking id, so one decision can be followed through both systems' logs.

`{"decision": false}` refuses the registration: 400 `invalid_client_metadata`, or 401 `invalid_client` at the
token endpoint. `{"decision": true}` lets it through, and the permit's `context` can narrow it:

| `context` member | What it does |
|---|---|
| `scope` (a string or an array) | the client keeps only these, of the scopes it asked for |
| `grant_types`, `response_types` | likewise |
| `registration_ttl_seconds` | the registration ends no later than this from now; less than `OIDF_REGISTRATION_MIN_TTL_SECONDS` refuses it |
| `require_trust_mark` (a string or an array) | the entity needs a verified mark of each type, or it is refused |
| `reason_admin`, `reason_user` | why: the first goes to the logs only, the second is shown to the caller only with `OIDF_PDP_SURFACE_USER_REASON=true` |

A permit narrows and never widens - a scope the entity didn't ask for isn't given, and a registration's end is
only ever brought forward. An explicit registration's response reports what was registered, after narrowing.
Anything else in `context` is recorded as ignored or, with `OIDF_PDP_UNKNOWN_CONTEXT=reject`, refuses the permit
(AuthZEN §5.5 allows either).

No answer is not a permit. A PDP that can't be reached, answers anything but a 200, or sends something that
isn't a decision leaves the registration refused with a 503 and `Retry-After` (AuthZEN §10.1.2).
`OIDF_PDP_FAIL_OPEN=true` registers it unnarrowed instead, and says so at WARN (`federation.pdp.failopen`).

A denial at renewal is like any failed renewal: the registration stands until it expires
(`federation.registration.refresh_deferred`), and is refused after that. To cut a client off at once, disable
it in PF, or have the PDP decide tokens too (below).

With `hosted_entity_enrol` in `OIDF_PDP_DECISION_POINTS`, `POST /federation/agents` asks too: `action.name`
`federation.hosted_entity.enrol`, `resource` `{"type": "federation_authority", "id": "<authority>"}`, and the
entity's metadata and the admin's fingerprint (never the token) in `context`. It isn't asked by default, so a
PDP with no enrolment policy doesn't start refusing enrolments the day it is switched on.

With `token_issuance` in `OIDF_PDP_DECISION_POINTS`, the issuance criteria ask too, for every token issued through
a mapping that carries one of them: `action.name` `federation.token.issue` with the grant type and how the client authenticated, the
client's anchor and Entity Type as registered, and in `context` the scopes and resources the token would carry
and the client's address (`context.OAuthScopes`, `context.OAuthResources` and `context.ClientIp` from PF's
criteria map). A criterion can only say yes or no, so a permit's obligations are checks there: every scope the
token carries must be in the permit's `scope`, and the grant type in its `grant_types`; `require_trust_mark` can't
be verified at issuance and refuses the token; the rest say nothing about a token and are ignored. A refused
token is PF's usual answer to a failed criterion, and `federation.token.refused` says why. This is the one
decision point that runs on every token, so give the PDP a `OIDF_PDP_CACHE_TTL_SECONDS` - and, because it can
refuse at once, it is how a PDP cuts a client off without waiting for its registration to expire.

`OIDF_REGISTRATION_ALLOWED_SCOPES` is the deployment's own policy - an allow-list every registration's scopes are
narrowed to, with or without a PDP, applied first. Each consult writes `federation.pdp.consulted` to `server.log`
and `audit.log`: the decision, how long it took, the PDP's request id, the names (not the values) of what a
permit narrowed, context it ignored, and `reason_admin`.

## Configuration

Servlet init-params first, then env (`FederationConfiguration.setting` / `RegistrationConfiguration.setting`):

| Setting | init-param / env | Notes |
|---|---|---|
| Trust anchors | `trustAnchorIssuers` / `OIDF_FEDERATION_TRUST_ANCHORS` | **Required at boot** - `OpenIdFederationServlet` is `loadOnStartup=1` and throws without one, taking `pf-runtime.war` down with it. |
| Trust controller | `trustControllerHost` / `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` (+ `…_BASE_URL`, `ignoreSslErrors` / `OIDF_FEDERATION_IGNORE_SSL_ERRORS`) | Read by the servlets, the auto-registration filter and the OGNL hooks directly - the hooks cannot wait for `/federation/register` to have populated `RegistrationConfiguration`. `ignoreSslErrors` covers every federation fetch, an RP's `signed_jwks_uri` and `jwks_uri` included - for a test federation only |
| Trust anchor keys | `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` / `oidf.federation.trust.anchor.jwks` | **Required whenever the trust controller is set.** The anchor's public JWK Set - the `jwks` claim of its entity configuration - captured once, out of band (OpenID Federation 1.0 §4), with `tools/pin-trust-anchor.py`. Nothing validates a chain without it: the OGNL criteria refuse, `/federation/register` fails its init, and both token-endpoint filters log an error at startup and refuse per request. They deliberately do not fail init, because this war also serves the entity's own `/.well-known/openid-federation`, which a PF that is its own anchor must publish before its keys can be captured. A value that is set but is not a usable public key set (private or symmetric keys, missing or duplicate `kid`) does fail filter init. Statically trusted attesters (`oidf.mock.attesters`) resolve without it. On an anchor key rollover (§11.2) add the new key to this set before the anchor starts signing with it. |
| This PF as a trust anchor | `OIDF_FEDERATION_SELF_ANCHOR` / `oidf.federation.self.anchor` (unset) - PF's own Entity Identifier, an https URL | Chains that end at PF are checked with the key PF signs with, read from its key store each time: nothing pinned, and a rotation needs no change. It joins any pinned anchors, after them. Pinning PF's own keys in `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` as well is refused - that copy would go stale at the first rotation. Name PF in `OIDF_FEDERATION_TRUST_ANCHORS` too, so its entity configuration says it is an anchor |
| Federation entity | `subordinates` / `OIDF_FEDERATION_SUBORDINATES`, `signingAlgorithm` / `OIDF_FEDERATION_SIGNING_ALG` (RS256/PS256), `attesterJwks` / `OIDF_FEDERATION_ATTESTER_JWKS`, `organizationName` / `OIDF_FEDERATION_ORGANIZATION_NAME`, `clientRegistrationTypes` / `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES` (default `automatic,explicit`), `resolveDiscovery` / `OIDF_FEDERATION_RESOLVE_DISCOVERY` (`known` or `any`), `cors*` init-params | The resolve endpoint is on whenever trust anchors are pinned (`OIDF_FEDERATION_TRUST_ANCHOR_JWKS`), and resolves against all of them |
| Registration | `subordinateStatementCacheMaxEntries` (256, `-1` unbounded), `trustChainEntryMaxAgeSeconds` (60), `acceptedSigningAlgorithms`, `signingAlgorithm` (RS256/PS256) | init-params only - on the registration servlet and (bar `signingAlgorithm`) the auto-registration filter |
| Front-channel registration (§12.1.1) | `OIDF_AUTO_REGISTRATION_FRONT_CHANNEL` (`true`), `OIDF_AUTO_REGISTRATION_AUTHZ_ERROR_MODE` (`page` \| `passthrough`), `OIDF_AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS` (`allow` \| `refuse`), `OIDF_AUTO_REGISTRATION_DEFAULT_SCOPES` (`openid`), `OIDF_AUTO_REGISTRATION_REQUIRE_PAR` (`false`), `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE` (`true`), `OIDF_AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES` (65536), `OIDF_FEDERATION_ERROR_PAGE` (a file with `${error}`, `${errorDescription}`, `${trackingId}`; unset uses a built-in page) | An encrypted request object can only be read as far as its header, so under `allow` PingFederate checks its claims and signature, after the RP is registered from its published metadata; `refuse` turns such requests away. An error page that is named but cannot be read stops the filter starting |
| Registration work limits (§18.1) | `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS` (8), `OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS` (2000) | Shared by both registration filters. One registration of a client at a time; so many at once across all clients; the rest get a 503 with `Retry-After`. There is no per-client rate limit on purpose - a stranger could spend it in the real client's name - so put a per-source rate limit in front of PingFederate if unauthenticated load is a worry |
| Registration lifetime (§12.3) | `OIDF_REGISTRATION_MAX_TTL_SECONDS` (86400), `OIDF_REGISTRATION_MIN_TTL_SECONDS` (60), `OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS` (300), `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT` (`refuse` \| `disable` \| `log`, default `refuse`), `OIDF_REGISTRATION_SWEEP_INTERVAL_SECONDS` (300, `0` off), `OIDF_AUTO_REGISTRATION_FAIL_CLOSED` (`true`); each also as a system property (`oidf.registration.max.ttl.seconds`, …, `oidf.auto.registration.fail.closed`) | A registration ends at its chain's expiry or the maximum, whichever is sooner; a chain that expires sooner than the minimum registers nothing. `disable` also disables the client, `log` only records the expiry. A value that doesn't parse - including a fail-closed switch that is neither `true` nor `false` - stops the filter starting |
| Trust Marks (§7) - validating | `OIDF_FEDERATION_REQUIRED_TRUST_MARKS` (unset: none), `OIDF_FEDERATION_TRUST_MARK_STATUS_CHECK` (`false`); also as `oidf.federation.required.trust.marks` and `oidf.federation.trust.mark.status.check` | The marks registration requires, by the Entity Type an entity registers as: `{"*": ["<trust mark type>"], "openid_relying_party": ["<trust mark type>"]}` - the `*` list applies to every type and each type's list adds to it; every mark listed is required. An entity without a verified mark of each is refused at every registration endpoint: 400 `invalid_client_metadata`, or 401 `invalid_client` at the token endpoint. A mark counts when its issuer's own chain reaches the anchor the entity's did, that anchor's `trust_mark_issuers` accepts the issuer for the type, its signature verifies with the issuer's key, it is current, and it carries a valid delegation where the anchor names an owner for the type. With the status check on, the issuer's status endpoint must also say `active` - for registration and for the marks a resolve response carries. A value that is not such an object stops PF starting |
| Trust Marks (§7) - issuing | `OIDF_FEDERATION_TRUST_MARK_TYPES` (`{"<type>": {"lifetime_seconds": 86400, "subjects": "hosted" \| "any", "delegation": "<jwt>", "ref": "https://…", "logo_uri": "https://…"}}`; unset: issues none), `OIDF_FEDERATION_TRUST_MARKS` (`[{"trust_mark_type", "trust_mark"}]` from other issuers, carried in PF's own configuration), `OIDF_FEDERATION_TRUST_MARK_ISSUERS` and `OIDF_FEDERATION_TRUST_MARK_OWNERS` (published only when PF is a trust anchor); each also as a system property (`oidf.federation.trust.mark.types`, …) | Grants are made through `/federation/admin/trust-marks` and kept in the authority's store (`OIDF_AUTHORITY_JDBC_URL` or `OIDF_AUTHORITY_DATA_STORE_ID`, set as env or system properties so the federation servlet finds it at start-up; migration `V102__trust_mark.sql`), in memory - with a warning - when none is set. A hosted entity's configuration carries the marks PF issues it. As an anchor PF names itself in `trust_mark_issuers` for the types it issues. A value that doesn't parse stops PF starting |
| Key history (§8.7) | `OIDF_FEDERATION_HISTORICAL_KEYS` (`false`), `OIDF_FEDERATION_KEY_HISTORY_GRACE_SECONDS` (86400); also as `oidf.federation.historical.keys` and `oidf.federation.key.history.grace.seconds` | PF reads its signing key when it starts, so a rotation is noticed at the next start: the old key is published as retired, valid for the grace period - at least the longest lifetime of anything PF signs; Trust Marks default to a day. Kept in the authority's store (migration `V103__federation_key_history.sql`); in memory a rotation across a restart goes unrecorded |
| Hosted entities | `authorityEntityId` / `oidf.authority.entity_id` / `OIDF_AUTHORITY_ENTITY_ID` (required by `HostedEntityServlet`), `adminToken`, `openBaoUrl`/`openBaoToken`, `jdbcUrl`+`jdbcUsername`+`jdbcPassword` or `dataStoreId` (`OIDF_AUTHORITY_*`); `OIDF_AUTHORITY_METADATA_POLICY` (the `metadata_policy` every hosted entity starts from, by Entity Type) | init-param, then sysprop, then env. Set them as env or system properties rather than init-params so the federation servlet and the admin API find them before `HostedEntityServlet` starts. The domain default policy is checked at start-up; an entity's own policy can only narrow it |
| Policy decisions (AuthZEN 1.0) | `OIDF_PDP_MODE` (`off` \| `local` \| `authzen`, default `local`), `OIDF_PDP_URL` (the PDP's base URL; evaluation at `/access/v1/evaluation` under it), `OIDF_PDP_EVALUATION_URL` (the endpoint itself, when it is elsewhere), `OIDF_PDP_DISCOVER` (`false`; `true` reads the endpoint from the PDP's `/.well-known/authzen-configuration`), `OIDF_PDP_AUTH` (`none` \| `bearer` \| `header`) with `OIDF_PDP_AUTH_TOKEN` and `OIDF_PDP_AUTH_HEADER` (`CLIENT-TOKEN`, as the RAR plugin sends it), `OIDF_PDP_FAIL_OPEN` (`false`), `OIDF_PDP_UNKNOWN_CONTEXT` (`ignore` \| `reject`), `OIDF_PDP_CACHE_TTL_SECONDS` (`0`: no cache), `OIDF_PDP_CONNECT_TIMEOUT_MS` (2000), `OIDF_PDP_REQUEST_TIMEOUT_MS` (3000), `OIDF_PDP_SURFACE_USER_REASON` (`false`), `OIDF_PDP_DECISION_POINTS` (`explicit_registration,automatic_registration`; add `hosted_entity_enrol` for enrolments, `token_issuance` for every token), `OIDF_REGISTRATION_ALLOWED_SCOPES` (unset: no limit); each also as a system property (`oidf.pdp.mode`, …, `oidf.registration.allowed.scopes`) | See [Asking a policy engine](#asking-a-policy-engine-authzen). `off` asks nobody, `local` only the allow-list. The PDP's URLs must be https (`OIDF_FETCH_ALLOW_HTTP=true` allows http, for a development PDP) and are let through the outbound URL policy as the operator's own; a discovered endpoint on another host is screened like any fetch. The cache keeps permits and denials - never failures - keyed on the whole request bar its tracking id. A value that doesn't parse, `authzen` without a URL, `bearer` or `header` without a token, a list of nothing, or an allow-list beside `off` stops PF starting |
| Subordinate constraints (§6.2) | `OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS` / `oidf.federation.subordinate.constraints` (`{"max_path_length": 0, "naming_constraints": {...}, "allowed_entity_types": [...]}`) | Carried by every Subordinate Statement PF issues, hosted or configured. Checked for syntax at start-up; a bad value stops PF starting |
| Bridge signing | `OIDF_BRIDGE_SIGNER_BACKING` (`vault`\|`config`) + `OIDF_BRIDGE_SIGNING_KEYS` (path to a JSON map of client id -> `{"key_ref": …, "attesters": […]}` or `{"jwk": {…}, "attesters": […]}`); `OIDF_BRIDGE_VAULT_ADDR`/`_TOKEN` when `vault` | Per client. Exactly one key form each, and the declared backing is enforced - an inline JWK under `vault` is refused, so a demo key cannot ride into production in a config file. A client with no key cannot authenticate; every other client is unaffected. Nothing configured at all is a **boot failure**, not a silent degradation, unless `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false` |
| Attester binding | `"attesters": ["https://attester.example"]` in each client's `OIDF_BRIDGE_SIGNING_KEYS` entry; `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING` (default `true`) | Federation trust says an attester is genuine; this says it is *this client's*. An attestation from a trusted attester the client is not bound to is a 401. A client entry with no `attesters` is a 401 too, by default - any trusted attester could otherwise vouch for it. `=false` lets unbound clients accept any trusted attester; an explicit binding is still enforced |
| ~~`OIDF_BRIDGE_PRIVATE_JWK`~~, ~~`OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK`~~ | — | **Superseded; both refuse startup if set.** The first held one deployment-wide key; the second kept its outgoing public half in every client's JWKS during a rotation overlap. Neither has meaning once signing is per client, and a setting that looks configured while doing nothing is worse than one that is absent |

## Upgrading from 0.2.0

- **Declare the four new extended properties** before deploying - `federation_registration_expires_at`,
  `federation_trust_anchor`, `federation_entity_type` and `federation_registration_disabled_at` (the full
  list is [docs/extended-properties.json](../../docs/extended-properties.json)). PF drops a property it
  doesn't know, silently, and a client whose expiry is dropped looks expired on every request. A registration
  whose client comes back from PF without `status` is now refused (500) and the client disabled: without it a
  federation client looks like one an administrator made - never expired, never renewed, its requests held to
  nothing - which the conformance rig found, because it declared none of them.
- **`token_endpoint_auth_method` is no longer written as an extended property.** PingFederate 13.1 counts the
  name as standard client metadata and refuses to declare it, so it was never kept; nothing read it. An
  attesting client is marked by `attestation_required` alone.
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
- **Resolve responses carry the subject's verified Trust Marks**, and expire when the first of them does if
  that is before the chain. Registration requires no mark unless `OIDF_FEDERATION_REQUIRED_TRUST_MARKS` says so.
- **PF can issue Trust Marks.** Nothing changes until `OIDF_FEDERATION_TRUST_MARK_TYPES` is set; then apply
  `V102__trust_mark.sql` to the authority's database before deploying, or grants live in memory.
- **Apply `V101__hosted_entity_actor.sql` before deploying** if hosted entities live in a database: every change
  now writes who made it, and without the column every enrolment and status change fails. Each change and its
  audit line are now one transaction.
- **PF can publish its key history** once `OIDF_FEDERATION_HISTORICAL_KEYS=true` - apply `V103__federation_key_history.sql`
  first. The first start records the key in use; only rotations after that are published.
- **Registrations can wait for a policy decision.** Nothing changes by default: `OIDF_PDP_MODE=local` with no
  allow-list asks nobody. With `OIDF_PDP_MODE=authzen` every registration waits for the PDP, and is refused with a
  503 when no decision comes - so check PF can reach the PDP, and that it has a policy for `federation.register.*`,
  before switching it on.
- **An automatically registered RP proves itself on every request at the authorization and PAR endpoints**, not
  only the one that registered it: a request object that carries `sub`, lacks `jti`, `exp`, `iss` or `aud`, reuses
  a `jti` or isn't signed with a key the RP is registered with is refused, as §12.1.1 and §12.1.1.1 say.
- **The entity configuration describes the OP as PF's own discovery does.** Its `openid_provider` and
  `oauth_authorization_server` blocks now start from PF's `/.well-known/openid-configuration` and
  `/.well-known/oauth-authorization-server`, read in-process, with federation's and attestation's parameters on
  top - they used to carry a handful of endpoints, and none of the parameters OpenID Connect Discovery requires.
  The entity configuration is bigger, and anything PF's discovery advertises is now advertised to the federation.
- **PF can be its own trust anchor without pinning its own keys**: `OIDF_FEDERATION_SELF_ANCHOR`.
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
