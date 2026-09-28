# Configuration

Every setting the federation support reads, what it defaults to, what it does, and what happens when it's
wrong. The rows are generated: each component's settings catalogue is the one place a row is written, and
[docs/configuration](../configuration/README.md) holds a page per component, which CI keeps equal to the
catalogues while `tools/settings-scan.py` keeps the catalogues equal to the code. This page says how a setting is
read and what "wrong" means, points each part of the federation at the pages its settings are on, and keeps what
a row has no room for. [Operations](operations.md) shows the settings in use.

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

A generated row's Setting column lists every place its setting is read from, in the order they are tried.

## When a setting is wrong

One of these happens, and each generated row says which, in bold, at the start of its "When it's wrong" cell:

- **Doesn't start** - the component that reads it fails at deploy, taking `pf-runtime.war` with it, and the log
  names the setting. Most settings are like this: a value that doesn't parse is refused rather than quietly read
  as the default. A switch is `true` or `false`, in any case, and anything else is refused - unless its row says
  otherwise.
- **First request** - a servlet that starts lazily fails on its first request, and only its paths fail.
- **Per request** - nothing at start-up; the requests that need it fail.
- **Not checked** - nothing checks the value; the row says what a wrong one leads to.

## Where the rows are

| Part of the federation | Pages |
|---|---|
| Trust anchors | [federation-runtime](../configuration/federation-runtime.md), [federation-entity](../configuration/federation-entity.md) (`OIDF_FEDERATION_TRUST_ANCHORS`) |
| This entity | [federation-entity](../configuration/federation-entity.md), [federation-runtime](../configuration/federation-runtime.md) (`OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS`) |
| Fetching | [outbound-fetch](../configuration/outbound-fetch.md), [federation-runtime](../configuration/federation-runtime.md) (`OIDF_FEDERATION_IGNORE_SSL_ERRORS`), [federation-entity](../configuration/federation-entity.md) (the init-param `ignoreSslErrors`) |
| Registration and its lifetime | [federation-runtime](../configuration/federation-runtime.md), [registration](../configuration/registration.md) (the init-params of `/federation/register` and the registration filters) |
| Trust Marks and key history | [federation-runtime](../configuration/federation-runtime.md) |
| Hosted entities and the admin API | [hosted-entities](../configuration/hosted-entities.md), [hosted-entity-signing](../configuration/hosted-entity-signing.md) (OpenBao), [federation-runtime](../configuration/federation-runtime.md) (`OIDF_AUTHORITY_METADATA_POLICY`), [registration](../configuration/registration.md) (`OIDF_REGISTERED_CLIENTS_ENABLED`) |
| Policy decisions (AuthZEN 1.0) | [federation-runtime](../configuration/federation-runtime.md) |
| Client authentication at the federation endpoints | [federation-runtime](../configuration/federation-runtime.md) |
| Events and logging | [pf-audit](../configuration/pf-audit.md) |
| Neighbours: attestation and FAPI | [federation-runtime](../configuration/federation-runtime.md) (the attestation filter and bridge keys), [attestation-token-endpoint](../configuration/attestation-token-endpoint.md), [rar-models](../configuration/rar-models.md), [fapi2-profile](../configuration/fapi2-profile.md) |

What follows, part by part, is what the rows leave out.

## Trust anchors

- `OIDF_FEDERATION_TRUST_ANCHOR_JWKS` as a map is written `{"https://ta.example.org": {"keys": [...]}}`.
  Registration, the OGNL criteria, the attestation filter, resolve, endpoint client authentication and the
  attestation issuer's wallet trust all use it. A single set with no controller host counts as nothing pinned.
- `OIDF_FEDERATION_SELF_ANCHOR` is tried after any pinned anchors. There is nothing to pin, and a key rotation
  needs no change.
- `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` must be one of the pinned anchors. Set with no anchor keys, the
  registration filters log an error and requests go straight to PingFederate's own client authentication, and
  resolve is off. Unset, with no anchor map and no self anchor, the token-endpoint filter doesn't start, so neither
  does PingFederate.
- `OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL` is for a controller served under a context path, such as
  `https://pf.example/oidf`.
- `OIDF_FEDERATION_TRUST_ANCHORS` is required, though its row's default reads "Unset": unset or blank, the
  federation servlet doesn't start.
- The superseded `OIDF_TRUST_CONTROLLER_HOST`, `OIDF_TRUST_ANCHOR_JWKS` and `OIDF_TRUST_CONTROLLER_IGNORE_SSL` are
  compared with their new names as strings, so the same JSON written differently counts as different, and
  PingFederate doesn't start.

## This entity

- With `OIDF_FEDERATION_SUBORDINATES` set, PingFederate publishes fetch and list endpoints.
- `OIDF_FEDERATION_ATTESTER_JWKS` with a key that isn't public stops PingFederate starting because it would
  otherwise publish the key.
- `OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS` is written `{"max_path_length": 0, "naming_constraints": {"permitted":
  [...], "excluded": [...]}, "allowed_entity_types": [...]}`.
- The init-params `tokenEndpointAuthMethodsSupported`, `clientAttestationSigningAlgValuesSupported`,
  `clientAttestationPopSigningAlgValuesSupported`, `dpopSigningAlgValuesSupported`,
  `clientAttestationPopMethodsSupported` and `attestationChallengeEndpointEnabled` default to the attestation
  profile's values.
- Two init-params the federation servlet reads have no effect: `trustControllerHost` (the controller comes from
  `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`) and `clientAttestationFormatsSupported`.

## Fetching

Every fetch the federation makes on a stranger's say-so - a chain's statements, an RP's key set, a Trust Mark's
status - goes through the outbound URL policy.

## Registration

- With `OIDF_AUTO_REGISTRATION_FAIL_CLOSED` on, a refusal is a 401 or 503 at the token endpoint, the
  `OIDF_AUTO_REGISTRATION_AUTHZ_ERROR_MODE` answer at the authorization endpoint, and JSON at PAR.
- The init-params `subordinateStatementCacheMaxEntries`, `trustChainEntryMaxAgeSeconds` and
  `acceptedSigningAlgorithms` are read on `/federation/register` and both registration filters;
  `trustControllerHost`, `trustControllerBaseUrl` and `signingAlgorithm` on `/federation/register` only.

## Registration lifetime

- The OGNL criterion follows `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT` too.

## Trust Marks

- `OIDF_FEDERATION_TRUST_MARK_TYPES` is written `{"<type>": {"lifetime_seconds": 86400, "subjects": "hosted" or
  "any", "delegation": "<jwt>", "ref": "https://...", "logo_uri": "https://..."}}`. Grants are made through the
  admin API and kept in the authority's database, or in memory.
- `OIDF_FEDERATION_TRUST_MARKS` is written `[{"trust_mark_type": "...", "trust_mark": "<jwt>"}]`.

## Key history

- The key history (`OIDF_FEDERATION_HISTORICAL_KEYS`) is kept in the authority's database, or in memory.

## Hosted entities and the admin API

- `OIDF_AUTHORITY_METADATA_POLICY` is written by role, `{"oauth_client": {"scope": {"subset_of": [...]}}}`.

## Policy decisions (AuthZEN 1.0)

All of these are checked when PingFederate starts, whatever the mode.

- With `OIDF_PDP_MODE=local` and no `OIDF_REGISTRATION_ALLOWED_SCOPES`, nothing is asked.
- With `OIDF_PDP_DISCOVER=true`, a discovery that fails counts as no decision.

## Client authentication at the federation endpoints

- `OIDF_FEDERATION_ENDPOINT_AUTH` is written `{"federation_fetch_endpoint": "required",
  "federation_resolve_endpoint": "optional"}`, naming any of the seven federation endpoints. Spent `jti` values
  are kept where attestation keeps its replays (Redis when `OIDF_REDIS_URL` is set).

## Events and logging

Nothing beyond the rows.

## Neighbours: attestation and FAPI

The same modules carry client attestation and a FAPI 2.0 filter. The
[pf-integration README](../../servlets/pf-integration/README.md#configuration) has the detail.

- `OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT`: a revoked hosted agent is refused (401) whatever it says.
- `OIDF_RAR_MODELS_FILE` and `OIDF_RAR_MODELS` are environment variables only, with no system property. A document
  the model refuses stops `pf-runtime.war` (PingFederate's runtime endpoints answer 503) when attestation
  authentication is configured; otherwise the attester fails from its first request and the issuance criterion
  per request.
