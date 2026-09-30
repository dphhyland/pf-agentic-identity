---
name: pf-rar-paz-plugin
description: >-
  Build, deploy, and configure the pf-rar-paz-plugin — a PingFederate
  AuthorizationDetailProcessor (RFC 9396 Rich Authorization Requests) that governs each
  authorization_details entry via a PingAuthorize governance-engine or AuthZEN decision. Fires when
  working with RAR/authorization_details on PingFederate, governing token issuance with
  PingAuthorize, this plugin's Java code, its PF config, its build/deploy, or the question of who
  the PDP is deciding about in a given OAuth flow.
---

# pf-rar-paz-plugin

A PingFederate SDK `AuthorizationDetailProcessor` that turns RFC 9396
`authorization_details` into a **policy decision**: for each requested entry it works out who the
decision is about, holds the entry to the **RAR containment model** (`libs/rar-model`, shaded in), POSTs
to a **PingAuthorize governance-engine** or **AuthZEN** endpoint, **denies unless the decision is
PERMIT**, applies returned statements (downscoping/obligations), and refuses a result the model does not
find within the request - **the PDP may narrow, never widen**. A refresh must stay within its grant by
the model's strict `contains`. It is a Policy Enforcement Point at **token issuance** — complementary to
per-API-call PEPs.

**PingFederate 13.1 only.** It reads the request through
`AuthorizationDetailContext.getJakartaRequest()` and the user key through `getUserKey()`, which 13.0
does not have. The last build for 13.0.x is v0.1.5, on the frozen `pf-13.0` branch.

## When this fires
- RFC 9396 / RAR / `authorization_details` on **PingFederate** specifically.
- Governing **token issuance/exchange** with **PingAuthorize** (as opposed to per-request API gating).
- Editing this plugin's Java (`com.pingidentity.ps.oidf.rar.*`), its PF config, or its build/deploy.
- "Why was this payment refused before the PDP was asked?" - the principal rules and the model below.
- "Why did a PERMIT with statements, or a refresh, come back `invalid_authorization_details`?" - the
  containment model below.
- Consent/approval pages that should show the *specific* authorized operation, not just a scope.

## Architecture (one screen)
```
authorization_details entry ─▶ AttestationAwareRarProcessor.enrich()
  ├─ PrincipalResolver: context.getUserKey() labelled per flow (grant_type + request path)
  │    · client_credentials -> client (the key IS the client id)
  │    · refresh_token -> authenticated (the grant's user; only a refresh that restates
  │      authorization_details reaches the plugin at all)
  │    · /as/bc-auth.ciba -> identity_hint (the request policy's IDENTITY_HINT_SUBJECT)
  │    · token-exchange -> subject_token only from a filter-verified attribute, else none
  │    · anything else with a non-blank key -> authenticated; blank -> none
  │    · login_hint / _principal_sub -> client_asserted: switch on AND development only
  ├─ ModelGate: the attestation context's rar_models_fingerprint must be the plugin's (when there is
  │    a context), and the detail, markers stripped, one its type's RAR model reads - before any PDP call
  ├─ "Types requiring an authenticated principal" (payment_initiation, account_information):
  │    refused before any PDP call when the source is none or client
  ├─ PdpClient — the dialect seam, chosen at configure() time:
  │    · governance-engine (default) → GovernanceEngineRequestBuilder + GovernanceEngineClient
  │    · authzen                     → AuthZenRequestBuilder + AuthZenPdpClient
  │    PdpDecisions in front of it: per-request memo, optional decision cache, AuthZEN batch;
  │    under it CircuitBreaker.Guarded over PdpTransport (platform's OutboundHttp, shaded)
  ├─ deny unless decision.isPermit(); fail open ONLY on PdpUnavailableException, if configured
  ├─ StatementApplier: merge obligations into a deep copy of the detail
  └─ ModelGate: the result must be within the request (contains, the request as the ceiling)
isEqualOrSubset(requested, granted) -> ModelGate: contains(granted, requested), strict
```
All I/O + mapping live in framework-agnostic collaborators (`PrincipalResolver`, `GovernanceEngine*`,
`AuthZen*`, `Decision*`, `PdpClient`/`HttpTransport`, `PdpResponses`, `StatementApplier`,
`ModelGate`), unit-tested without the SDK. Only `AttestationAwareRarProcessor` touches the PF
SDK; its tests use the package-private `(PdpClient, GovernanceEngineConfig[, ModelGate])` constructors
and `configure(Configuration, profile)` as seams. `RarContainment` is gone (S1c): every containment
question goes to the model.

## Key facts that bite
1. **The user key is a different thing per flow, and null in the browser flow unless the
   authentication contract has `subject`.** Verified on the rig 2026-09-27 (13.1.3.0): PingFederate
   asks the plugin once in the code flow, at the resume after login
   (`/as/<id>/resume/as/authorization.ping`), with the authentication result's `subject` attribute as
   the key. An HTML-form adapter with only `username` gives none, and a payment is then refused after
   the user signed in. Map `subject` on the adapter or policy contract (on the rig: an EXPRESSION
   `#this.get("username")`). Do not read `IN_PARAMETER_AUTH_DETAILS_USER_INFO` to guess a principal.
2. **Client credentials is the client, and a payment for a client is refused before the PDP.** The
   default type list is `payment_initiation,account_information`; a single `-` empties it. Token
   exchange is `none` unless the filter published `verified_subject_token_sub` (a PingFederate-signed subject token, 0.6.0).
3. **Fail-open means unreachable, nothing else.** Connection refused/reset, unresolved name, the
   connect or total deadline, all 32 call places taken, the circuit breaker open, HTTP
   429/502/503/504. A 401 from a wrong secret, a non-JSON body, a 500, a response over 64 KiB, a
   status line or header platform's client cannot parse and a TLS failure all deny, whatever the
   switch says, and none of them counts towards the breaker. `PdpTransport.classify` reads platform's
   failure reason, and a reset from the cause's class or the JDK's own message prefix, never by
   searching a message: wire text can reach a protocol error's message (F-0093). There is no
   "Deny unless PERMIT" switch any more; a stored value under that name is carried by PingFederate
   and ignored (the settings catalogue lists it under `removed` from 0.6.0; F-0231). In production
   "Fail open on engine error" needs `pdp-fail-open` in `OIDF_ACCEPTED_RISKS`: refused on save and at
   configure without it.
4. **The PDP URL must be https unless `OIDF_DEPLOYMENT_PROFILE=development`** (unset is production):
   refused by the field's validator in the console/API, and again at configure for an archive import.
   From 0.6.0 production also refuses "Skip TLS verification (dev only)" and "Trust a client-asserted
   principal" on, the same two ways (`ProfileRules`, from the catalogue's classes). PingFederate 13.1.3
   imports such an instance (HTTP 200), shows it in the admin API as saved, configures it at first use
   and logs `Unexpected exception thrown attempting to configure plugin` at ERROR; a request with its
   types gets `invalid_authorization_details`, and other flows keep serving (rig, 2026-09-30, U-0068).
   The rig runs as `development`, so the plugin may dial the host's stub over http.
5. **The shared secret is an encrypted field under the same name.** A plaintext value stored by an
   older jar survives an upgrade (one `PluginConfigUtil` deobfuscation ERROR, then used as stored;
   rehearsed on the rig 2026-09-27); save the instance again to store it obfuscated.
6. **Plugin loading needs a `PF-INF/<type>` marker + shaded deps.** `src/main/resources/PF-INF/
   authorization-detail-processors` lists the class. Jackson, `libs/rar-model` and `libs/platform` (with
   its HttpCore) are relocated INTO the jar under `com.pingidentity.ps.oidf.rar.shaded` (PF isolates each
   deploy jar's classloader); `ShadedJarCheck` fails the build on any unrelocated class or link, a
   service file not relocated, or a resource twice. A `META-INF/services` marker does NOT work.
7. **Binding a type to the instance is per type and per client on 13.1**: `/oauth/authorizationDetailTypes`
   (`authorizationDetailProcessorRef`), and the client's `authorizationDetailTypes` lists type names.
8. **TLS to an internal PDP: give the PDP certificate a SAN that matches the host PF dials.** From
   0.6.0 the plugin calls the PDP through platform's `OutboundHttp`, which checks the host name on
   every connection and has no switch to stop it, in every "PDP TLS trust" mode (`jvm-default`,
   `pingfederate-trusted-cas`, `pinned-ca`) and with "Skip TLS verification (dev only)". The JVM-wide
   `jdk.internal.httpclient.disableHostnameVerification` only ever governed `java.net.http`, so it
   does nothing for this plugin, and the production profile refuses it (PR5, F-0035): take it out.
   The call's total deadline is "Request timeout (ms)", 2500 by default, held to 1000-10000.
9. **Reserved attribute names (governance engine).** `UserID`, `principal_source`, `actor`,
   `actor_iss`, `client_id`, `attestation.*`, and `req_<field>`/`att_<field>` for every set-valued
   field whether or not the request writes that mirror: the server writes them last, and a requested
   field that maps onto one is refused. Only reachable with an empty attribute prefix and the type
   prefix off.
10. **Logs carry the principal hashed, and PF logs the exception chain.** `principal=sha256:<16 hex>`
    in the plugin's lines; a PDP failure is carried as redacted text because PingFederate 13.1.3 logs
    a processor's exception with every cause at ERROR. The plugin's own lines arrive in `server.log`
    as `ERROR [SystemErr]` (java.util.logging on stderr), whatever their level.
11. **Secret header spelling.** The plugin defaults to `CLIENT-TOKEN` (hyphen); a PingAuthorize Server
    configured with `JSON_API_HEADER_NAME=CLIENT_TOKEN` (underscore) wants that. Mixing the two gives
    auth failures that look like policy failures - and from 0.4.0 they deny rather than fail open.
    Nothing in `paz/` or `probe-decision.sh` has a default secret: they read `PAZ_DECISION_SECRET` /
    `PAZ_PDP_SECRET` or the `_FILE` variant and refuse to run without one.
12. **`isPermit()` trusts `authorised` over `decision`.** `{"authorised":true,"decision":"DENY"}`
    is a PERMIT (governance engine). `authorised` must be a JSON boolean and `decision` a string,
    or the answer is refused. AuthZEN needs a boolean `decision`. Either dialect refuses content
    after the object and a member named twice.
13. **The RAR model refuses what it cannot compare, before and after the PDP.** An undeclared field,
    an unmodelled type (outside `development`), a flat `amount` without `currency` or a negative limit
    is refused before any PDP call. After a PERMIT, a statement may lower, drop or add a constraint the
    request left open; one that raises, adds or changes what was requested, or writes a field the type
    does not declare, is refused. An AuthZEN `context` member (and a `context.statements` entry, by
    the first part of its name) reaches the detail only when "AuthZEN context members merged into
    details" names it for the type - default `sales_agent: @model; account_information: @model`, so
    nothing for `payment_initiation`; any other is dropped, counted in
    `oidf_rar_context_dropped_total` and logged by name. A new field needs a models document with `extends` (`OIDF_RAR_MODELS_FILE`), and a new
    type also needs `OIDF_RAR_EXTRA_TYPES` for PingFederate to bind it.
14. **The attestation filter and the plugin must load one model set.** The filter publishes
    `rar_models_fingerprint` in the attestation context (0.4.0 on); the plugin refuses a context
    without it or with another value. Deploy the plugin and the filter from one release, with one
    `OIDF_RAR_MODELS_FILE` for the whole PF process. No context at all - a client the filter did not
    verify, the authorization endpoint's resume, CIBA's backchannel request, PingFederate's consent and
    grant-reuse checks - is decided without the check.
15. **A refresh is compared with its grant only when it restates `authorization_details`,** strictly:
    more, another payee or another currency than the grant is `invalid_authorization_details`. A bare
    refresh reissues the stored details without asking the PDP; the plugin is asked only where approved
    consent is reused ("bypass authorization for approved consents" on, the client not bypassing the
    approval page), whether the stored details are within the consent, and a no revokes the grant
    (javap, 13.1.3).
16. **`validate` holds each detail to the model where it arrives, and refuses the plugin's types on the
    JWT-bearer grant.** PingFederate calls `validate` at PAR, the authorization endpoint, CIBA, device, token
    exchange and the token endpoint - except a token exchange requesting an ID-JAG, where 13.1.3 calls neither
    `validate` nor `enrich` and copies the request's details into the ID-JAG (F-0325, javap; do not enable ID-JAG
    on an SP connection for a client that may send these types); an undeclared field, a wrong JSON type, an unmodelled type (development:
    common fields) or a size limit is `invalid_authorization_details` there, with the model's reason and no
    value; no PDP, no principal. On the JWT-bearer grant PingFederate never calls `enrich` (U-0017, rig
    2026-09-30), so a type not listed in "Types allowed on the JWT-bearer grant" (default none) is refused
    with "authorization_details of this type are not accepted on the JWT-bearer grant"; a listed type passes
    `validate`'s model check and is issued without a PDP decision, and the field refuses a type requiring an
    authenticated principal (F-0108). Plain RFC 7523: `validate` sees the request's details before the
    assertion is verified, and PingFederate issues none of them; ID-JAG (`typ` `oauth-id-jag+jwt`): it sees
    the assertion's own details after the signature is verified, and they are issued as they are.
17. **One PDP decision per detail per HTTP request, and one call for all of them with a batch URL.**
    PingFederate calls `enrich` once per detail, in order, on the request's thread
    (`AuthorizationDetailsUtil.enrich`, a `List.forEach`; javap, 13.1.3). The memo, a request
    attribute per instance, answers a repeat of the same (type, canonical detail, principal, client).
    With "AuthZEN batch URL" set (authzen only), the first `enrich` of a token request sends every
    detail in its `authorization_details` parameter in one AuthZEN 1.0 `evaluations` call; an answer
    with the wrong number of evaluations, or one that is not a boolean decision, denies them all. At
    the authorization endpoint the details are not a parameter, so each is asked on its own. "Decision
    cache types" never takes `payment_initiation` or a type requiring an authenticated principal.
    Metrics `oidf_rar_pdp_calls_total`, `oidf_rar_pdp_answers_total` and `oidf_rar_pdp_breakers` are in
    the plugin's own MXBean, `com.pingidentity.ps.oidf:type=Metrics,copy="com.pingidentity.ps.oidf.rar.shaded.platform.metrics from ..."`.
    So are `oidf_events_total{code, outcome}` for the decision events (`rar.decision.permitted`,
    `.denied` with a reason class, `.failopen`; catalogue `META-INF/oidf-events/rar.json`), which go to
    `server.log` only: the plugin's copy of platform has no audit sink.

## How to build
```bash
mvn -pl plugins/rar-paz-plugin -am package   # from the repo root → target/pf.plugins.pf-rar-paz-plugin.jar
```
JDK 17+ (the pom targets release 17). Jacoco gates the decision methods at 100% per METHOD (the
resolver, enrich, the status and transport classification, the URL rule, the reserved-name check).
Versions come from the repo BOM (`bom/pom.xml`). The PF SDK is not on Maven Central -
`pf-protocolengine` + `pingfederate-sdk` 13.1.3.0 are extracted from the public PF image into
`~/.m2` by `.github/actions/pf-provided-jars/action.yml`; run its `install:install-file` lines once.

## How to verify on a running PingFederate
`conformance/verify-rar-principal.sh` boots the rig with the jar (a compose override mounts it),
starts a stub AuthZEN PDP on the host, configures an instance + types + a client through the admin
API and drives client credentials, CIBA, refresh, token exchange and the code flow, printing the
user key PF passed and the `principal_source` per flow. `OLD_PLUGIN_JAR=` adds the upgrade
rehearsal; `SKIP_UP=1 KEEP_RIG=1` reuses a running rig. Read the README's "Verified on the rig".

## How to deploy + configure
This repo deploys nothing; the recipe lives in `idp-agentic-demo/pingfederate/rar-paz/`.
- Bake the jar with its `Dockerfile.fragment` (jar → `server/default/deploy/`, optional
  consent template). That fragment also adds the JVM-wide hostname flag - leave it out (fact 8).
  The plugin does not need it, and a production deployment refuses it.
- Create the processor instance + the types + enable them on the client:
  `idp-agentic-demo/pingfederate/rar-paz/config-as-code/{create-processor-instance,enable-on-client}.sh`.
- Start from the reference policies in `paz/policies` (one per built-in type): `paz/author-policies.py`
  writes them into a Policy Editor and `paz/decision-tests.py` runs their permit, deny and narrowing
  cases; `paz/paz-compose.yml` brings up a Policy Editor for both. Wire contract: top-level `README.md`.
- Confirm the jar that runs is the one you built: compare its size or hash in
  `server/default/deploy/` with the fresh build - a platform can go on serving the last
  good image.

## Wire contract (governance-engine JSON API)
```
POST <PDP URL>                         <secret-header>: <secret>
{ "domain":"<domainPrefix>.<type>", "service":"Authorization", "action":"authorize",
  "attributes": { "<attrPrefix>.<type>.<field>":"<json>", "att_<field>":"…", "req_<field>":"…",
                  "UserID":"<principal>", "principal_source":"authenticated|client|identity_hint|subject_token|client_asserted|none",
                  "actor":"<agent, if attested>", "actor_iss":"<its attester>", "client_id":"…",
                  "attestation.entitlement":"<json>", "attestation.cnf_thumbprint":"…", "attestation.iss":"…" } }
 → { "decision":"PERMIT|DENY|…", "authorised":true|false, "statements":[{"name":"a.b","payload":…}] }
```
