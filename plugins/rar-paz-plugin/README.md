# pf-rar-paz-plugin

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly a standalone local repo, absorbed with history 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

A PingFederate **`AuthorizationDetailProcessor`** (RFC 9396 Rich Authorization Requests) that acts as a
Policy Enforcement Point at token issuance: it works out who the decision is about, refuses the types that
need a person when there is none, forwards each requested `authorization_details` entry - together with the
client attestation's vouched subject / entitlement / workload - to a PDP decision, **denies unless the
decision is PERMIT**, and applies any returned statements (downscoping / obligations). Two PDP dialects:
PingAuthorize's native governance engine, or an OpenID AuthZEN 1.0 PDP.

Modelled on Ping's reference `RARAuthDetailsProcessor` but closes its gaps: it honours the decision (the
reference read only `statements` and could never deny), maps a real principal rather than a hardcoded
`"joe"`, passes the attested entitlement so policy can enforce `requested ⊆ attested`, confines the
insecure-TLS switch to development deployments, and implements a real `isEqualOrSubset` for refresh-time
narrowing.

Status: unit-tested (the count is in the coverage dashboard a Build run publishes), and client credentials,
CIBA, refresh, token exchange and the code flow driven against it on the rig on 2026-09-27 (PingFederate
13.1.3.0, this jar at 0.4.0-SNAPSHOT) by
[`conformance/verify-rar-principal.sh`](../../conformance/verify-rar-principal.sh), with an upgrade from the
v0.3.0 jar rehearsed on the way - the evidence is under "Verified on the rig" below. The device flow and the
JWT-bearer grant were not driven (U-0066, U-0017). The earlier live verification against PingAuthorize (2026-08-15, on the agentic
demo's PingFederate 13.0.3) still describes the governance-engine dialect.

**PingFederate 13.1 only.** The plugin reads the request through
`AuthorizationDetailContext.getJakartaRequest()` and the user key through `getUserKey()`, which 13.0 does not
have, so it does not link there. The last build for 13.0.x is v0.1.5.

## Layout

| Path | What |
|---|---|
| [`src/`](src) · [`pom.xml`](pom.xml) | the plugin (`com.pingidentity.ps.oidf.rar`) + tests; `PF-INF` marker; shaded jackson |
| [`paz/`](paz) | PingAuthorize Trust Framework + policy-authoring scripts (PAP REST API) — **author-local** compose, see its README |
| [`probe-decision.sh`](probe-decision.sh) | POSTs the plugin's exact governance-engine request shape to a PDP |
| [`../../conformance/verify-rar-principal.sh`](../../conformance/verify-rar-principal.sh) | boots the rig with this jar and drives every flow at a stub PDP; the evidence below |
| [`.claude/skills/pf-rar-paz-plugin/`](.claude/skills/pf-rar-paz-plugin) | build/deploy/configure knowledge as a reusable skill |

## How it loads

A PF SDK plugin: `src/main/resources/PF-INF/authorization-detail-processors` names the class, the jar is
`pf.plugins.pf-rar-paz-plugin.jar` (PF only picks up `pf.plugins.*` in `server/default/deploy`), and PF
loads it on a per-plugin **isolated** classloader. That is why jackson is shaded and relocated into
`com.pingidentity.ps.oidf.rar.shaded.jackson` — a bare jackson jar beside the plugin would fail to link.
The PF SDK and servlet API are `provided`; HTTP is the JDK's `java.net.http`. The package name is in the
descriptor, so it was left alone by the split-package unwind that renamed the libraries.

## Architecture

```
authorization_details entry ─▶ AttestationAwareRarProcessor.enrich()
   ├─ AttestationSubject   ← request attribute com.pingidentity.ps.oidf.rar.attestation_context
   ├─ PrincipalResolver    ← context.getUserKey() read per flow (grant_type, request path):
   │                          client credentials -> client · refresh -> authenticated · CIBA -> identity_hint
   │                          token exchange -> subject_token (a filter-verified attribute) else none
   │                          any other non-blank key -> authenticated · blank -> none
   │                          login_hint / _principal_sub -> client_asserted, in development only
   ├─ types requiring an authenticated principal: refused before any PDP call when none or client
   ├─ GovernanceEngineRequestBuilder | AuthZenRequestBuilder   (PDP Dialect field)
   ├─ GovernanceEngineClient | AuthZenPdpClient  ─POST─▶ PDP    (PdpClient seam, JdkHttpTransport)
   ├─ deny unless decision.isPermit()   (fail-open only when the PDP is unreachable, and only if configured)
   └─ StatementApplier: merge statements/obligations into the granted detail (dot-path)
```

Only `AttestationAwareRarProcessor` touches the SDK; the resolver, the builders, clients, `DecisionResponse`,
`StatementApplier` and `RarContainment` are plain code, tested without PF.

**`RarContainment`** duplicates the containment semantics of `RarEntitlement` in
[`libs/client-attestation`](../../libs/client-attestation) on purpose — kept local so the plugin builds
and loads standalone on its isolated classloader rather than shading the library in — and its javadoc
carries the TODO to consolidate the two. Same set-valued fields (`actions`, `locations`, `datatypes`,
`privileges`, `sales_regions`); if one changes, change both.

## Who the decision is about

`AuthorizationDetailContext.getUserKey()` is a different thing in each flow, so the plugin labels it. What
PingFederate 13.1.3 passes, read with `javap` from `pf-protocolengine` (the callers of
`AuthorizationDetailsUtil.enrich`, 2026-09-27) and then driven on the rig the same day:

| Flow | PingFederate passes as the user key | `principal_source` | Rig, 2026-09-27 |
|---|---|---|---|
| client credentials | the client id (`ClientCredentialsGrantProcessor`) | `client` | user key = the client id; `sales_agent` reaches the PDP as `subject {type: client}`; `payment_initiation` refused before the PDP, 400 `invalid_authorization_details` |
| refresh, with `authorization_details` in the request | the grant's unique user identifier (`RefreshTokenGrantProcessor`) | `authenticated` | user key = `suite-user`; the grant's attributes arrive under the SDK's `IN_PARAMETER_AUTH_DETAILS_USER_INFO` parameter |
| refresh, without | - (the stored details are reissued; plan "Found" item 2) | - | the plugin is not called |
| CIBA, at `/as/bc-auth.ciba` (the request URI read as the container maps it: path parameters, escapes and dot segments resolved; U-0094) | the request policy's `IDENTITY_HINT_SUBJECT` (`CibaAuthenticationRequestHandler`) | `identity_hint` | user key = `suite-user` from `login_hint`; then the ciba-sim approves, the poll issues a token and a refresh token |
| token exchange | `null` (`TokenExchangeRequest`; and enrich is skipped when the requested token type is `id-jag`) | `subject_token` only when the token-endpoint filter published `verified_subject_token_sub` in the attestation context, else `none` | user key none; `principal_source: none`; `payment_initiation` refused before the PDP. The filter publishes no verified subject yet (`delegationActChain` decodes the subject token without verifying it), so this is always `none` today |
| authorization code | the authentication result's `subject` attribute, once, at the resume after login (`OAuthResumableRequestHandlerBase`, path `/as/<id>/resume/as/authorization.ping`); PAR does not enrich, and there is no second pass at consent | `authenticated`, or `none` when the contract has no `subject` | as the rig ships (an HTML-form adapter with `username` and no `subject`): user key none, the payment refused after the user signed in; with `subject` mapped on the adapter by expression from `username`: user key = `suite-user`, decided about `suite-user`, token issued for `suite-user` |
| device flow | the approving user, as far as `javap` shows: `UserAuthorizationRequestHandler` enriches at the user's approval with the mapped attributes | `authenticated` (assumed; U-0066) | not driven |
| JWT bearer | `JwtGrantProcessor` has no call to enrich (`javap`) | - | not driven (U-0017) |

Two names are the caller's own: the `login_hint` request parameter and the `_principal_sub` marker a
front-end folds into `authorization_details`. They are used only when the resolution above found nobody,
"Trust a client-asserted principal" is on, AND `OIDF_DEPLOYMENT_PROFILE=development` - labelled
`client_asserted`, and gone at 1.0 (plan decision 9). In production the switch is inert and configure says so.
`_principal_sub` is stripped from the detail on every path. The request attribute
`com.pingidentity.ps.oidf.rar.resource_owner_sub` is no longer read.

**Give the authentication contract a `subject`.** The one thing a deployment does to give the plugin a
principal in the browser flow: the user key at resume is the `subject` attribute of the authentication result,
so an adapter or policy contract without one leaves the plugin knowing nobody after the user has signed in,
and the payment and account types are refused. The mapped attributes also reach `enrich` under
`AuthorizationDetailProcessor.IN_PARAMETER_AUTH_DETAILS_USER_INFO`; the plugin does not read them, because
which of a deployment's attributes names the person is the deployment's decision, said by mapping `subject`.

**Types requiring an authenticated principal** (default `payment_initiation,account_information`) are refused
before any PDP call when the principal is `none` or `client`. `identity_hint`, `subject_token` and (in
development) `client_asserted` pass, labelled, so policy can be stricter. A single `-` empties the list.

The principal is logged hashed: `principal=sha256:<first 16 hex>` and `userKey=` likewise, so a server log
never carries a user key, and the same person still matches across lines. The same goes for a refusal's text:
PingFederate 13.1.3 logs a processor's exception with every cause at ERROR (seen on the rig, 2026-09-27), and a
PDP's error body can name whom it was asked about, so the plugin carries a failure as text with the principal
and the user key replaced by their hashes, and chains no PDP exception. The plugin logs through
`java.util.logging`, which PingFederate writes to `server.log` as `ERROR [SystemErr]` whatever the level
(F-0075).

## What fails open, and what does not

"Fail open on engine error" grants the cleaned detail through exactly one failure class, the PDP being
unreachable (`PdpUnavailableException`): a connection refused or reset, an unresolved name, a connect or
request deadline, or HTTP 429, 502, 503 or 504. Everything else refuses whatever the switch says:

| Answer | Result |
|---|---|
| 2xx, `application/json` (or `+json`), a decision | the decision - PERMIT or not |
| 429, 502, 503, 504 | unavailable: fails open when configured, else denied |
| any other status - 401/403 from a wrong secret, 400, 404, 500, a redirect | denied |
| 2xx with another content type, an empty or malformed body, no boolean `decision` (AuthZEN), a `decision` that is not a string or an `authorised` that is not a boolean (governance engine) | denied |
| a body with content after the JSON object, or a member named twice | denied |
| a status line or header the client cannot parse (`ProtocolException` anywhere in the cause chain), whatever text it carries | denied |
| TLS failure (`SSLException` anywhere in the cause chain), even before a byte is sent | denied |

The JDK client copies wire text it cannot parse into its protocol error's message, so the plugin reads a
reset from the exception's class, or from a message that starts with the JDK's own "Connection reset", and
never searches a message for it. Before this, a DENY carrying a header named `connection reset` was granted
with fail-open on (F-0093, found in review on 2026-09-27 and closed in the same change).

The switch that turned deny-unless-PERMIT off ("Deny unless PERMIT") is gone; the decision is always
deny-unless-PERMIT. A value stored under the old name is carried by PingFederate and never read: 13.1.3
hands an instance with no parent its stored configuration as it is (`ConfigurationUtil.createCompositeConfiguration`)
and the admin API's `PluginConfigTranslator` raises no error for an undeclared field - both read with `javap`,
2026-09-27. On the rig the same day, an archive exported under 0.3.0 (the instance held the field, `true`)
imported under this jar, the instance on disk still held it beside the declared fields, the plugin configured
and decided, and saving the instance again dropped it.

## Reserved attribute names (governance-engine dialect)

The requested fields are written first and the server's attributes last, so nothing requested can overwrite
them; and a requested field whose attribute name is one the server writes is refused outright, which turns
into a denial. Reserved: `UserID`, `principal_source`, `actor`, `actor_iss`, `client_id`,
`attestation.entitlement`, `attestation.workload`, `attestation.cnf_thumbprint`, `attestation.iss`, and the
`req_<field>` and `att_<field>` mirror of every set-valued field (`actions`, `locations`, `datatypes`,
`privileges`, `sales_regions`) - in every request, whether or not it writes that mirror, because an
`att_actions` the builder leaves unwritten (the attestation constrains no actions) would otherwise reach the
PDP as the caller's own ceiling (F-0073). With the default attribute prefix (`idp`, prefixed with the type) a
requested field never lands on those names; with an empty prefix and the type prefix off it could, and
`"UserID": "alice"` inside a detail would otherwise have named the principal. The AuthZEN dialect keeps the
requested fields under `resource.properties` and has nothing to reserve.

## Attestation-context bridge

`servlets/pf-integration`'s `ClientAttestationUtils` publishes the verified attestation as a request
attribute after `attest_jwt_client_auth` succeeds; this plugin reads it via
`AuthorizationDetailContext.getJakartaRequest()`. A string-keyed plain `Map`, so neither module depends on
the other across classloaders:

- **key:** `com.pingidentity.ps.oidf.rar.attestation_context` (`AttestationSubject.REQUEST_ATTRIBUTE`)
- **value:** `sub` and `client_id` (both the registered client / agent *type*), `agent_id` (the
  attester-minted instance identifier, when one was minted), `iss` (the attester that minted it - an
  `agent_id` is unique only within its issuing authority), `entitlement` (the attested
  `authorization_details` ceiling), `workload` (SPIFFE id / attestor / selectors, plus flat `spiffe_id`
  and `attested_by`), `cnf_thumbprint`; and, once the filter verifies token-exchange subject tokens,
  `verified_subject_token_sub` (`AttestationSubject.VERIFIED_SUBJECT_TOKEN_KEY`), the only thing the
  `subject_token` principal source reads.

Absent context (a non-attestation client) falls back to `context.getClientId()` and sends no
entitlement — policy decides on the request alone.

## PDP dialects

Selected by the **PDP Dialect** field (`governance-engine`, default, or `authzen`). Enforcement,
fail-open, timeout and the shared-secret header are dialect-independent.

| | `governance-engine` | `authzen` |
|---|---|---|
| Wire | `{domain: <prefix>.<type>, service, action, attributes}` — values JSON-stringified for the Trust Framework, plus flat `req_<field>` / `att_<field>` mirrors (attribute names cannot contain `.`) | AuthZEN 1.0 `{subject, action, resource, context}`; point **PDP URL** at `/access/v1/evaluation` |
| Principal / agent | `UserID` = the resolved principal, else client id; `principal_source`; `actor` = `agent_id` when minted and distinct, with `actor_iss` | `subject = {type: user\|client, id}` (`client` when the principal source is `client`, or the client was the fallback); `context.principal_source`; `context.actor = {type: agent, id: agent_id, iss}` (RFC 8693 delegation) |
| Attested ceiling | `attestation.entitlement / workload / cnf_thumbprint / iss` | `context.attestation.{entitlement, workload, cnf_thumbprint, iss}` |
| Decision | `decision: PERMIT\|DENY\|…` (a string) + `authorised` (a boolean, which wins when present) | boolean `decision`, required |
| Obligations | `statements: [{name, payload}]` | response `context` mapped into the same statement pipeline: `context.statements` verbatim, every other member one statement; `id` / `reason_*` never merged |

## Configuration (PF admin fields — same names the config-as-code sets)

| Field | Default | When it is wrong |
|---|---|---|
| PDP Dialect | `governance-engine` | `authzen` for an AuthZEN PDP; anything else is the governance engine |
| PDP URL | required, `https://` (a placeholder the validator refuses) | must be `https`; `http` only with `OIDF_DEPLOYMENT_PROFILE=development` (unset is production). The admin console and API refuse the field. An archive import runs no validator, so there `configure` throws, and the plugin refuses every request that reaches the instance with `invalid_authorization_details`; what PingFederate itself does with such an instance is U-0068 |
| PDP Domain Prefix / PDP Service / PDP Action | `idpartners.authorization_details` / `Authorization` / `authorize` | governance-engine dialect only |
| Attribute Prefix / Prefix Attributes with Type | `idp` / on | an empty prefix with the type prefix off lets a requested field reach a reserved name, which is then refused |
| Shared Secret Header / Shared Secret | `CLIENT-TOKEN` / required, **stored encrypted** | the same field name as before; a value stored in the clear by an older jar still works (below) but re-save it |
| Types requiring an authenticated principal | `payment_initiation,account_information` | refused before any PDP call with `principal_source` `none` or `client`; comma- or space-separated; a single `-` means none |
| Fail open on engine error | off | grants through an unreachable PDP only (above); never a wrong secret, a bad answer or a TLS failure |
| Trust a client-asserted principal | off | `login_hint` / `_principal_sub` as the subject when nobody else is known - in development only, inert elsewhere, gone at 1.0 |
| Trust the PAR-carried agent marker | off | where the attestation is not in the request (the authorization endpoint), take the agent instance from the `_agent_id` the attestation filter put in each entry at PAR; only for clients that must use PAR |
| Skip TLS verification (dev only) / Request timeout (ms) | off / 10000 | trusts any PDP certificate only with `OIDF_DEPLOYMENT_PROFILE=development`; elsewhere it is inert and configure logs a WARNING. The JDK client checks the hostname either way (below) |

A switch missing from a stored configuration - an instance saved before the field existed (a 0.3.0 instance
has no "Types requiring an authenticated principal"), or an archive written by hand that leaves it out -
reads as the default above, which is the secure value for every switch. The admin API fills a missing field
with the descriptor's default when it creates an instance: the rig's probe instance, posted with five fields,
was stored with all fifteen (2026-09-27). The version PingFederate shows for the plugin is the jar's
`Implementation-Version`, the project version it was built as.

`OIDF_DEPLOYMENT_PROFILE` is read straight from the environment until PR-1 (the platform library)
centralises the profile; `development` (any case) is development, anything else including unset is production.

Supported RAR types are declared in code (`sales_agent`, `payment_initiation`, `account_information`),
plus any the deployment names in `OIDF_RAR_EXTRA_TYPES` or the `oidf.rar.extra.types` system property
(comma- or space-separated; the property wins). PingFederate 13.1 binds a type to a processor instance
under OAuth Server → Authorization Detail Types (`/oauth/authorizationDetailTypes`, field
`authorizationDetailProcessorRef`) and a client lists the types it may use (`authorizationDetailTypes`,
the type names); the rig script does both through the admin API.

**Choosing the encrypted field.** The secret is an encrypted `TextFieldDescriptor` (the three-argument
constructor, `javap` on the 13.1.3 SDK) rather than a `SecretReferenceFieldDescriptor`: the latter holds a
reference into a configured secret manager, which neither the rig nor any consumer runs, and the encrypted
field gives the archive the same treatment PingFederate gives its own client secrets - obfuscated under the
master key, handed to the plugin in the clear. S2c can add the reference form once the platform library's
secret handling exists.

**Upgrade rehearsal, plan to-verify item 7 (2026-09-27, 13.1.3.0; U-0022).** The rig was booted with the
v0.3.0 jar from the GitHub release, an instance created through the admin API with a plaintext "Shared Secret",
one decision made (the stub PDP received the secret header), and the archive exported: it holds
`<urn:Field name="Shared Secret">` in the clear. The container was then restarted on this jar and the archive
imported (`POST /configArchive/import?forceImport=true`, 200). What followed:

- the admin API reads the field back as an `encryptedValue` (`OBF:JWE:...`), while the instance on disk still
  holds the plaintext, and the undeclared "Deny unless PERMIT" beside it;
- PingFederate logged one ERROR after the import, `[PluginConfigUtil] There was a problem deobfuscating the
  value for the field: Shared Secret`, and none at the decisions that followed;
- the plugin was handed the value as stored: the stub PDP received the same secret header as before;
- saving the instance again (a `PUT` of what the admin API read back) stored the secret encrypted - on disk a
  191-character value beginning `eyJhbGci`, a JOSE header, and no plaintext - dropped "Deny unless PERMIT", and the next decision sent the same header
  with no new ERROR.

So a stored plaintext value survives the switch; save each instance again after upgrading to store it
encrypted. `OLD_PLUGIN_JAR=<the v0.3.0 jar> conformance/verify-rar-principal.sh` repeats the rehearsal and
prints each of those facts, never the secret.

**TLS to the PDP.** Give the PDP a certificate whose subject alternative name is the host PF dials. "Skip
TLS verification" trusts any certificate, but the JDK HTTP client still checks the hostname during the
handshake. Do not switch that check off with `-Djdk.internal.httpclient.disableHostnameVerification=true`,
as older notes for this plugin said: the JDK reads the property once for the whole JVM, so every
`java.net.http` client in that PingFederate stops checking hostnames - this repo's federation fetches, the
OpenBao signer and the SSF servlet's push, poll and introspection calls, not only this plugin's. Any
certificate from a trusted CA would then pass for any host. (Read from the JDK in the 13.1.3 image,
OpenJDK 21.0.12.1: `AbstractAsyncSSLConnection` takes the flag from a static field, 2026-09-26.)

## Verified on the rig

`conformance/verify-rar-principal.sh` boots the rig on its own slot (by default `PF_RIG_NAME=pfai-rar`, ports
45031/45080/45999) with this jar lent to it by `conformance/docker-compose.rar-plugin.yml` (a bind mount under
`/opt/in`, which the base image copies over `/opt/out` at start; `OIDF_DEPLOYMENT_PROFILE=development` so the
plugin may dial the stub over plain http), starts `conformance/rar-principal/stub-pdp.py` on the host (an
AuthZEN PDP that answers PERMIT and appends every request to a JSONL file), configures a processor instance,
the three built-in types, a bearer-token exchange policy and a secret-authenticated client through the
admin API, drives client credentials, CIBA, refresh, token exchange and the code flow, prints per flow the user key PingFederate passed (matched by
SHA-256 against the plugin's log line) and the `principal_source` the PDP received, removes what it
configured and takes the rig down, image included. `SKIP_UP=1 KEEP_RIG=1` reuses a running rig;
`ONLY_CONFIGURE=1` leaves the configuration in place for driving a flow by hand. The evidence in the table and
the upgrade rehearsal above are its run of 2026-09-27T03:40Z, on this plugin at commit b497275
(`conformance/.rar-principal/summary.txt`, `pdp-requests.jsonl` and PingFederate's `server.log`, git-ignored).
That `server.log` carries neither the test user's name nor the shared secret: the plugin's lines hash the
principal, and the refusals PingFederate logs with their causes carry only the plugin's own text.

Not verified there: the device flow's user key (U-0066), the JWT-bearer grant (U-0017; `javap` finds no call
to enrich in `JwtGrantProcessor`), the `subject` recipe on an authentication *policy* contract rather than an
adapter mapping (U-0067), and what PingFederate makes of an instance whose `configure` threw (U-0068; the rig
runs as `development`, where a plaintext URL is allowed).

## Build, test, deploy

```bash
mvn -pl plugins/rar-paz-plugin -am package     # → target/pf.plugins.pf-rar-paz-plugin.jar (tests on)
```

Versions come from the repo BOM (`bom/pom.xml`); the two `provided` PF jars must be in `~/.m2` — the
`install:install-file` lines in `.github/actions/pf-provided-jars/action.yml`. Deploy recipe in
[`idp-agentic-demo/pingfederate/rar-paz/`](https://github.com/dphhyland/idp-agentic-demo/blob/main/pingfederate/rar-paz) — the config-as-code moved there on 2026-08-21, beside the PingAuthorize services that answer it. Its
`Dockerfile.fragment` still adds the JVM-wide hostname flag the TLS note above warns against (checked
2026-09-26); removing it is that repo's change. Note this repo's own `build/pingfederate/` image is
the OIDF-only AS and deliberately does **not** bake this plugin; the rig borrows it through the compose
override above.
