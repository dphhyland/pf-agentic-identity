# Configuration

Every setting the federation support reads, what it defaults to, what it does, and what happens when it's
wrong. [Operations](operations.md) shows them in use. A test keeps this page honest: every `OIDF_*` name the
federation code reads has to appear here, or the build fails.

## How a setting is read

Most settings are environment variables, and each can also be a Java system property: the same name in lower
case with `.` for `_` (`OIDF_PDP_MODE` is `oidf.pdp.mode`). The system property wins. They are read once, when the
first component asks, and kept for as long as PingFederate runs; change one and restart.

The exceptions:

- The federation servlet's own settings (this entity's metadata, CORS) are servlet init-params first, then the
  environment variable, with no system property. Nothing in this repo sets an init-param; they matter only if you
  edit `web.xml`.
- The hosted-entity settings are init-param, then system property, then environment variable. Three of their
  system properties keep an underscore: `oidf.authority.entity_id`, `oidf.authority.admin_token`,
  `oidf.authority.data_store_id`.
- The `OIDF_FETCH_*` settings and `OIDF_EVENTS_MAX_VALUE_LENGTH` are environment variables only.

**When a setting is wrong**, one of these happens, and each row below says which:

- **PingFederate doesn't start** - the component that reads it fails at deploy, taking `pf-runtime.war` with it,
  and the log names the setting. Most settings are like this: a value that doesn't parse is refused rather than
  quietly read as the default. A switch is `true` or `false`, in any case, and anything else is refused - unless
  its row says otherwise.
- **First request** - a servlet that starts lazily fails on its first request, and only its paths fail.
- **Per request** - nothing at start-up; the requests that need it fail.

## Trust anchors

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` | Unset | The pinned trust anchor keys every chain validates to. One JWK Set, for the anchor `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` names, or a map of anchor to JWK Set - `{"https://ta.example.org": {"keys": [...]}}` - in order of preference. Public keys only, each with its own `kid`. Registration, the OGNL criteria, the attestation filter, resolve, endpoint client authentication and the attestation issuer's wallet trust all use it | A set with a private or symmetric key, or a missing or repeated `kid`: the registration filters don't start. A single set with no controller host counts as nothing pinned. Pinning PingFederate's own keys as well as `OIDF_FEDERATION_SELF_ANCHOR`: the registration filters don't start |
| `OIDF_FEDERATION_SELF_ANCHOR` | Unset | PingFederate's own Entity Identifier (an https URL): PingFederate is a trust anchor, checked with the key it signs with, read from its key store each time, after any pinned anchors. Nothing to pin, and a key rotation needs no change | Not an https URL with a host: PingFederate doesn't start |
| `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` | Unset | The federation's trust anchor, as a bare Entity Identifier: the anchor a single pinned JWK Set belongs to, the one the OGNL criteria and the attestation filter check against (it must be one of the pinned anchors), and exempt from the fetch rules | **Set with no anchor keys**: the registration filters log an error and skip automatic registration - requests go straight to PingFederate's own client authentication; the OGNL criteria refuse; resolve is off. **Unset, with no anchor map and no self anchor**: the token-endpoint filter doesn't start, so neither does PingFederate |
| `OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL` | The controller host | Where the trust controller's own Entity Configuration is fetched, when it is served under a context path (`https://pf.example/oidf`) | Not checked; a wrong value shows up as failed fetches |
| `OIDF_FEDERATION_TRUST_ANCHORS` (init-param `trustAnchorIssuers`) | **Required** | This entity's superiors, comma-separated: published as its `authority_hints`. When PingFederate's own issuer is in the list, PingFederate is an anchor instead: no `authority_hints`, and it publishes `trust_mark_issuers` and `trust_mark_owners` | Unset or blank: PingFederate doesn't start |
| `OIDF_TRUST_CONTROLLER_HOST`, `OIDF_TRUST_ANCHOR_JWKS`, `OIDF_TRUST_CONTROLLER_IGNORE_SSL` | - | **Superseded** by their `OIDF_FEDERATION_` names. Still read when the new name is unset, with a warning in the log at start-up | Set to a different value from the new name: PingFederate doesn't start. The values are compared as strings, so the same JSON written differently counts as different |

## This entity

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FEDERATION_SUBORDINATES` (init-param `subordinates`) | None | Entities this one vouches for, comma-separated. `/federation/fetch` issues a statement about each, with the keys their own configurations publish; `/federation/list` lists them; PingFederate publishes fetch and list endpoints | Not checked; a bad entry fails when it is fetched |
| `OIDF_FEDERATION_SIGNING_ALG` (init-param `signingAlgorithm`) | `RS256` | How this entity signs its statements: `RS256` or `PS256`, with PingFederate's current RSA key | Anything else: PingFederate doesn't start |
| `OIDF_FEDERATION_ORGANIZATION_NAME` (init-param `organizationName`) | Unset | `organization_name` in this entity's `federation_entity` metadata | - |
| `OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES` (init-param `clientRegistrationTypes`) | `automatic,explicit` | What `client_registration_types_supported` advertises; `federation_registration_endpoint` is published only with `explicit`. Advertising only: registration works whatever it says | Unknown values are published as given |
| `OIDF_FEDERATION_RESOLVE_DISCOVERY` (init-param `resolveDiscovery`) | `known` | `known`: resolve answers only for this entity, its subordinates and the entities it hosts (§18.1). `any`: for anyone | Anything else: PingFederate doesn't start |
| `OIDF_FEDERATION_ATTESTER_JWKS` (init-param `attesterJwks`) | Unset | The co-hosted attester's keys, published as `oauth_client_attester.jwks` so other authorisation servers can trust its attestations through the federation | Not a JWK Set, or a key that isn't public (private members, or a symmetric key): PingFederate doesn't start - it would otherwise publish the key |
| `OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS` | Unset | The `constraints` (§6.2) on every Subordinate Statement PingFederate issues: `{"max_path_length": 0, "naming_constraints": {"permitted": [...], "excluded": [...]}, "allowed_entity_types": [...]}` | Not valid constraints (including `federation_entity` in `allowed_entity_types`): PingFederate doesn't start |
| init-params `corsEnabled`, `corsAllowOrigin`, `corsAllowMethods`, `corsAllowHeaders`, `corsMaxAge` | `true`, `*`, `GET, OPTIONS`, `Accept, Content-Type`, `3600` | CORS headers on every federation endpoint | `corsMaxAge` not a number: PingFederate doesn't start. `corsEnabled`: anything but `true` means false |
| init-params `tokenEndpointAuthMethodsSupported`, `clientAttestationSigningAlgValuesSupported`, `clientAttestationPopSigningAlgValuesSupported`, `dpopSigningAlgValuesSupported`, `clientAttestationPopMethodsSupported`, `attestationChallengeEndpointEnabled` | The attestation profile's values | What the `openid_provider` metadata advertises about client attestation | - |

Two init-params the federation servlet reads have no effect: `trustControllerHost` (the controller comes from
`OIDF_FEDERATION_TRUST_CONTROLLER_HOST`) and `clientAttestationFormatsSupported`.

## Fetching

Every fetch the federation makes on a stranger's say-so - a chain's statements, an RP's key set, a Trust Mark's
status - goes through the outbound URL policy.

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FETCH_ALLOW_HTTP` | `false` | `true` allows `http://` - for a development federation or PDP only | Anything but `true` means false |
| `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS` | `false` | `true` lets fetches reach private, loopback and link-local addresses. Without it a host is refused if any of its addresses is one | Anything but `true` means false |
| `OIDF_FETCH_HOST_ALLOWLIST` | Empty | Hosts, comma-separated, exempt from the private-address rule (a name covers its subdomains). https is still required | - |
| `OIDF_FETCH_MAX_BODY_BYTES` | `262144` | The largest response any federation fetch reads | Not a positive number: the default |
| `OIDF_FEDERATION_IGNORE_SSL_ERRORS` (init-param `ignoreSslErrors` on the federation servlet) | `false` | `true` turns off certificate checks on federation fetches, for a test federation only. PDP calls always check | Anything but `true` means false |

## Registration

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_AUTO_REGISTRATION_FRONT_CHANNEL` | `true` | Automatic registration of relying parties at the authorization and PAR endpoints (§12.1.1). `false` passes those requests straight through | PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_FAIL_CLOSED` | `true` | A registration that fails, or an expired one that can't be renewed, is refused with the reason - 401 or 503 at the token endpoint, the error mode below at the authorization endpoint, JSON at PAR. `false` passes such requests on to PingFederate | PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_AUTHZ_ERROR_MODE` | `page` | How a refusal at the authorization endpoint is answered: `page`, this module's error page and never a redirect; `passthrough`, the request goes on to PingFederate unregistered | PingFederate doesn't start |
| `OIDF_FEDERATION_ERROR_PAGE` | Built-in page | An HTML file for that page, with `${error}`, `${errorDescription}` and `${trackingId}`, read once at start-up | Can't be read: PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_ENCRYPTED_REQUEST_OBJECTS` | `allow` | `allow`: an encrypted request object registers the RP from its header, and PingFederate checks the rest after decrypting. `refuse`: such requests are refused | PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_DEFAULT_SCOPES` | `openid` | Space-separated scopes for a front-channel RP whose metadata names none | - |
| `OIDF_AUTO_REGISTRATION_REQUIRE_PAR` | `false` | `true` registers every front-channel RP as PAR-only | PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE` | `true` | Front-channel RPs are registered requiring PKCE | PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_MAX_REQUEST_OBJECT_BYTES` | `65536` | The largest request object or PAR client assertion read at the front channel | Below 1: PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS` | `8` | Chains each registration filter checks at once - the token-endpoint and front-channel filters have a pool each. The rest get a 503 with `Retry-After` | Below 1: PingFederate doesn't start |
| `OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS` | `2000` | How long a request waits for another registration of the same client in the same filter | Negative: PingFederate doesn't start |
| `OIDF_REQUIRE_METADATA_POLICY` | `true` | A registration whose chain has no superior setting a metadata policy for the role being registered is refused (400 `invalid_client_metadata`) | Not `true` or `false`: PingFederate doesn't start |
| init-params `subordinateStatementCacheMaxEntries`, `trustChainEntryMaxAgeSeconds`, `acceptedSigningAlgorithms` (on `/federation/register` and both registration filters) | `256` (`-1` unbounded), `60`, any asymmetric algorithm | The statement cache's size; the oldest a statement in a presented chain may be; which algorithms a chain's statements may use | A number that isn't one, a cache size below 1 (bar `-1`) or an age of 0 or less: that component doesn't start |
| init-params `trustControllerHost`, `trustControllerBaseUrl`, `signingAlgorithm` (on `/federation/register` only) | - | The first two must agree with the environment's; the third signs the registration response (`RS256` or `PS256`) | Disagrees, or another algorithm: first request |

## Registration lifetime

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_REGISTRATION_MAX_TTL_SECONDS` | `86400` | The longest a registration lasts: it ends at its chain's expiry or this, whichever is sooner (§12.3) | Below the minimum: PingFederate doesn't start |
| `OIDF_REGISTRATION_MIN_TTL_SECONDS` | `60` | A chain that would leave a registration less than this registers nothing | Negative, or above the maximum: PingFederate doesn't start |
| `OIDF_REGISTRATION_REFRESH_BEFORE_EXPIRY_SECONDS` | `300` | How long before its end an automatic registration is renewed | Negative: PingFederate doesn't start |
| `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT` | `refuse` | What an expired registration that can't be renewed meets: `refuse`, the request is refused; `disable`, and the client disabled until a renewal; `log`, the expiry is logged and nothing is enforced - the sweeper doesn't run either. The OGNL criterion follows it too | PingFederate doesn't start |
| `OIDF_REGISTRATION_SWEEP_INTERVAL_SECONDS` | `300` | How often a background task disables federation clients whose registration has ended (`0` turns it off). One runs per PingFederate | Negative: PingFederate doesn't start |

## Trust Marks

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FEDERATION_REQUIRED_TRUST_MARKS` | None required | The marks an entity needs before it registers, by role: `{"*": ["<type>"], "openid_relying_party": ["<type>"]}` - the `*` list applies to every role and each role's list adds to it | Not that shape: PingFederate doesn't start |
| `OIDF_FEDERATION_TRUST_MARK_STATUS_CHECK` | `false` | `true`: a mark also needs its issuer's status endpoint to say `active` (§8.4), at registration and in resolve responses | PingFederate doesn't start |
| `OIDF_FEDERATION_TRUST_MARK_TYPES` | Issues none | The types PingFederate issues: `{"<type>": {"lifetime_seconds": 86400, "subjects": "hosted" or "any", "delegation": "<jwt>", "ref": "https://...", "logo_uri": "https://..."}}`, everything but the type optional. Grants are made through the admin API and kept in the authority's database, or in memory | Not that shape, a lifetime that isn't positive, or a `ref` that isn't https: PingFederate doesn't start |
| `OIDF_FEDERATION_TRUST_MARKS` | None | Marks other issuers gave PingFederate, carried in its own configuration: `[{"trust_mark_type": "...", "trust_mark": "<jwt>"}]` | Not that shape, or a mark whose type doesn't match: PingFederate doesn't start |
| `OIDF_FEDERATION_TRUST_MARK_ISSUERS` | None | As an anchor: who may issue each type, `{"<type>": ["<entity id>"]}` (`[]` is anyone). PingFederate adds itself for the types it issues | Not that shape: PingFederate doesn't start |
| `OIDF_FEDERATION_TRUST_MARK_OWNERS` | None | As an anchor: who owns each type, `{"<type>": {"sub": "<entity id>", "jwks": {...}}}` | Not that shape: PingFederate doesn't start |

## Key history

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FEDERATION_HISTORICAL_KEYS` | `false` | `true` records PingFederate's signing key at each start and publishes the ones it retired at `/federation/historical_keys` (§8.7). Kept in the authority's database, or in memory | PingFederate doesn't start. Starting while signing with a revoked key: PingFederate doesn't start |
| `OIDF_FEDERATION_KEY_HISTORY_GRACE_SECONDS` | `86400` | How long a retired key still vouches for what it signed before it was retired | Negative: PingFederate doesn't start |

## Hosted entities and the admin API

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_AUTHORITY_ENTITY_ID` (init-param `authorityEntityId`) | Hosts nothing | This authority's Entity Identifier; hosted agents are `<id>/federation/agents/<slug>` and `<id>/federation/resources/<slug>` | Unset: `/federation/agents` fails on its first request |
| `OIDF_AUTHORITY_ADMIN_TOKEN` (init-param `adminToken`) | Unset: every admin request is a 401 | The bearer token for enrolment, `/federation/admin/*` and `/federation/registered-clients`, compared in constant time | - |
| `OIDF_AUTHORITY_JDBC_URL`, `OIDF_AUTHORITY_JDBC_USERNAME`, `OIDF_AUTHORITY_JDBC_PASSWORD` (init-params `jdbcUrl`, `jdbcUsername`, `jdbcPassword`) | Unset | A direct database for hosted agents, Trust Mark grants and the key history, for development. Wins over the data store below | Driver missing: hosting isn't configured, and with Trust Mark types or key history on PingFederate doesn't start. Wrong credentials: first use |
| `OIDF_AUTHORITY_DATA_STORE_ID` (init-param `dataStoreId`) | Unset | A PingFederate JDBC data store, whose pool the stores use. With neither this nor a JDBC URL, everything is in memory, with a warning, and gone at the next restart | Unknown id: first use |
| `OIDF_OPENBAO_URL`, `OIDF_OPENBAO_TOKEN` (init-params `openBaoUrl`, `openBaoToken`) | Unset; also read from `OPENBAO_ADDR`/`BAO_ADDR`/`VAULT_ADDR` and `OPENBAO_TOKEN`/`BAO_TOKEN`/`VAULT_TOKEN` | OpenBao for hosted agents' signing keys, one transit key each | Missing: a hosted agent's configuration answers 500 |
| `OIDF_AUTHORITY_METADATA_POLICY` | None | The metadata policy every hosted agent starts from, by role: `{"oauth_client": {"scope": {"subset_of": [...]}}}`. An agent's own policy can only narrow it | Not a valid policy: PingFederate doesn't start |
| `OIDF_REGISTERED_CLIENTS_ENABLED` (init-param `registeredClientsEnabled`) | `false` | Turns on `GET /federation/registered-clients`, a list of the clients this module registered, behind the admin token. Off, it answers 404 | Anything but `true` means false |

## Policy decisions (AuthZEN 1.0)

All of these are checked when PingFederate starts, whatever the mode.

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_PDP_MODE` | `local` | `off`: nobody decides. `local`: only `OIDF_REGISTRATION_ALLOWED_SCOPES`, and with none set nothing is asked. `authzen`: that, then the PDP | Anything else, or `authzen` with no URL: PingFederate doesn't start |
| `OIDF_PDP_URL` | Unset | The PDP's base URL and identifier; it is asked at `/access/v1/evaluation` under it | Not https with a host (http only with `OIDF_FETCH_ALLOW_HTTP=true`): PingFederate doesn't start |
| `OIDF_PDP_EVALUATION_URL` | Unset | The evaluation endpoint itself, when it is somewhere else; wins over the two ways below | As above |
| `OIDF_PDP_DISCOVER` | `false` | `true` reads the evaluation endpoint from the PDP's `/.well-known/authzen-configuration`, whose `policy_decision_point` must equal `OIDF_PDP_URL` | Without `OIDF_PDP_URL`: PingFederate doesn't start. A discovery that fails counts as no decision |
| `OIDF_PDP_AUTH`, `OIDF_PDP_AUTH_TOKEN`, `OIDF_PDP_AUTH_HEADER` | `none`, unset, `CLIENT-TOKEN` | `bearer` sends `Authorization: Bearer <token>`; `header` sends the token in the named header | `bearer` or `header` with no token: PingFederate doesn't start |
| `OIDF_PDP_DECISION_POINTS` | `explicit_registration automatic_registration` | Where the PDP is asked; add `hosted_entity_enrol` and `token_issuance` if you want them | A name that isn't one of the four: PingFederate doesn't start |
| `OIDF_PDP_FAIL_OPEN` | `false` | With no decision: `false` refuses (503); `true` goes ahead without narrowing and logs `federation.pdp.failopen` | PingFederate doesn't start |
| `OIDF_PDP_UNKNOWN_CONTEXT` | `ignore` | `reject` treats a permit carrying context this deployment doesn't understand as a denial | PingFederate doesn't start |
| `OIDF_PDP_CACHE_TTL_SECONDS` | `0` | How long answers are kept - permits and denials, never failures | Negative: PingFederate doesn't start |
| `OIDF_PDP_CONNECT_TIMEOUT_MS`, `OIDF_PDP_REQUEST_TIMEOUT_MS` | `2000`, `3000` | How long to wait for the PDP | Not above 0: PingFederate doesn't start |
| `OIDF_PDP_SURFACE_USER_REASON` | `false` | `true` shows the client the PDP's `reason_user` when it refuses | PingFederate doesn't start |
| `OIDF_REGISTRATION_ALLOWED_SCOPES` | No limit | This deployment's own policy: every registration is narrowed to these scopes | Beside `OIDF_PDP_MODE=off`: PingFederate doesn't start |

## Client authentication at the federation endpoints

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_FEDERATION_ENDPOINT_AUTH` | No endpoint takes it | Which endpoints take `private_key_jwt` client authentication (§8.8): `{"federation_fetch_endpoint": "required", "federation_resolve_endpoint": "optional"}`, any of the seven federation endpoints, each `none`, `optional` or `required`. Spent `jti` values are kept where attestation keeps its replays (Redis when `OIDF_REDIS_URL` is set) | Not that shape, or an endpoint that isn't one: PingFederate doesn't start. Set without trust anchors: PingFederate doesn't start |
| `OIDF_FEDERATION_ENDPOINT_AUTH_SIGNING_ALGS` | `RS256 PS256 ES256` | What a client may sign its assertion with, and what the Entity Configuration advertises | An algorithm that isn't an asymmetric JWS one: PingFederate doesn't start, even with endpoint authentication off |

## Events and logging

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_EVENTS_AUDIT` | `true` | Federation events marked as audit also go to PingFederate's `audit.log`; every event goes to `server.log` either way | Neither `true` nor `false`: audit stays on, with a warning |
| `OIDF_EVENTS_MAX_VALUE_LENGTH` | `512` | The longest value an event line carries; longer ones are cut. Below 16 means 16 | Not a number: the default, with a warning |

## Neighbours: attestation and FAPI

The same modules carry client attestation and a FAPI 2.0 filter. Their settings, briefly - the
[pf-integration README](../../servlets/pf-integration/README.md#configuration) has the detail.

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY` | `true` | The attestation filter doesn't start without bridge signing configured | Not `true` or `false`: PingFederate doesn't start |
| `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING` | `true` | A client whose bridge-key entry names no `attesters` is refused (401) | Not `true` or `false`: PingFederate doesn't start |
| `OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT` | `false` | An agent this authority hosts must be active and inside its `notAfter` to authenticate - a revoked one is refused (401) whatever this says. `true` refuses an attested agent the authority does not host at all | Anything but `true` counts as `false` |
| `OIDF_BRIDGE_SIGNER_BACKING`, `OIDF_BRIDGE_SIGNING_KEYS`, `OIDF_BRIDGE_VAULT_ADDR`, `OIDF_BRIDGE_VAULT_TOKEN` | Unset | Per-client bridge keys: `vault` (OpenBao transit keys) or `config` (inline JWKs, development only), from the JSON file `OIDF_BRIDGE_SIGNING_KEYS` names | Wrong or unreadable: per request (500) |
| `OIDF_BRIDGE_PRIVATE_JWK`, `OIDF_BRIDGE_PREVIOUS_PUBLIC_JWK` | - | **Superseded** - bridge keys are per client now | Set at all: the attestation filter doesn't start |
| `OIDF_FAPI2_CLIENTS` | Unset | The clients the FAPI 2.0 filter holds to issuer-only assertion audiences and PS256/ES256/EdDSA DPoP proofs | - |
