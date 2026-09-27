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
decision is about, POSTs to a **PingAuthorize governance-engine** or **AuthZEN** endpoint, **denies
unless the decision is PERMIT**, and applies returned statements (downscoping/obligations). It is a
Policy Enforcement Point at **token issuance** — complementary to per-API-call PEPs.

**PingFederate 13.1 only.** It reads the request through
`AuthorizationDetailContext.getJakartaRequest()` and the user key through `getUserKey()`, which 13.0
does not have. The last build for 13.0.x is v0.1.5, on the frozen `pf-13.0` branch.

## When this fires
- RFC 9396 / RAR / `authorization_details` on **PingFederate** specifically.
- Governing **token issuance/exchange** with **PingAuthorize** (as opposed to per-request API gating).
- Editing this plugin's Java (`com.pingidentity.ps.oidf.rar.*`), its PF config, or its build/deploy.
- "Why was this payment refused before the PDP was asked?" - the principal rules below.
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
  ├─ "Types requiring an authenticated principal" (payment_initiation, account_information):
  │    refused before any PDP call when the source is none or client
  ├─ PdpClient — the dialect seam, chosen at configure() time:
  │    · governance-engine (default) → GovernanceEngineRequestBuilder + GovernanceEngineClient
  │    · authzen                     → AuthZenRequestBuilder + AuthZenPdpClient
  ├─ deny unless decision.isPermit(); fail open ONLY on PdpUnavailableException, if configured
  └─ StatementApplier: merge obligations into the granted detail
```
All I/O + mapping live in framework-agnostic collaborators (`PrincipalResolver`, `GovernanceEngine*`,
`AuthZen*`, `Decision*`, `PdpClient`/`HttpTransport`, `PdpResponses`, `StatementApplier`,
`RarContainment`), unit-tested without the SDK. Only `AttestationAwareRarProcessor` touches the PF
SDK; its tests use the package-private `(PdpClient, GovernanceEngineConfig)` constructor and
`configure(Configuration, profile)` as seams.

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
   exchange is `none` until the token-endpoint filter publishes `verified_subject_token_sub`.
3. **Fail-open means unreachable, nothing else.** Connection refused/reset, unresolved name, a
   deadline, HTTP 429/502/503/504. A 401 from a wrong secret, a non-JSON body, a 500, a status line
   or header the client cannot parse (`ProtocolException`) and a TLS failure all deny, whatever the
   switch says. A reset is read from the exception's class or the JDK's own message prefix, never by
   searching a message: the client copies wire text into its protocol errors (F-0093). There is no
   "Deny unless PERMIT" switch any more; a stored value under that name is carried by PingFederate
   and ignored.
4. **The PDP URL must be https unless `OIDF_DEPLOYMENT_PROFILE=development`** (unset is production):
   refused by the field's validator in the console/API, and again at configure for an archive import.
   "Skip TLS verification (dev only)" is inert outside development too (a WARNING at configure), so a
   self-signed PDP is a TLS failure there, which denies. The rig runs as `development`, so the plugin
   may dial the host's stub over http.
5. **The shared secret is an encrypted field under the same name.** A plaintext value stored by an
   older jar survives an upgrade (one `PluginConfigUtil` deobfuscation ERROR, then used as stored;
   rehearsed on the rig 2026-09-27); save the instance again to store it obfuscated.
6. **Plugin loading needs a `PF-INF/<type>` marker + shaded deps.** `src/main/resources/PF-INF/
   authorization-detail-processors` lists the class. Jackson is relocated INTO the jar (PF
   isolates each deploy jar's classloader). A `META-INF/services` marker does NOT work.
7. **Binding a type to the instance is per type and per client on 13.1**: `/oauth/authorizationDetailTypes`
   (`authorizationDetailProcessorRef`), and the client's `authorizationDetailTypes` lists type names.
8. **TLS to an internal PDP: give the PDP certificate a SAN that matches the host PF dials.** The
   JDK HttpClient checks the hostname even when "Skip TLS verification" trusts every certificate (in
   development, the only place it does). Never set
   `-Djdk.internal.httpclient.disableHostnameVerification=true`: it is JVM-wide.
9. **Reserved attribute names (governance engine).** `UserID`, `principal_source`, `actor`,
   `actor_iss`, `client_id`, `attestation.*`, and `req_<field>`/`att_<field>` for every set-valued
   field whether or not the request writes that mirror: the server writes them last, and a requested
   field that maps onto one is refused. Only reachable with an empty attribute prefix and the type
   prefix off.
10. **Logs carry the principal hashed, and PF logs the exception chain.** `principal=sha256:<16 hex>`
    in the plugin's lines; a PDP failure is carried as redacted text because PingFederate 13.1.3 logs
    a processor's exception with every cause at ERROR. The plugin's own lines arrive in `server.log`
    as `ERROR [SystemErr]` (java.util.logging on stderr), whatever their level.
11. **Secret header spelling.** The plugin defaults to `CLIENT-TOKEN` (hyphen); the `paz/`
    compose stack and every script there use `CLIENT_TOKEN` (underscore, the PDP's
    `JSON_API_HEADER_NAME`). Mixing the two defaults gives auth failures that look like policy
    failures - and from 0.4.0 they deny rather than fail open.
12. **`isPermit()` trusts `authorised` over `decision`.** `{"authorised":true,"decision":"DENY"}`
    is a PERMIT (governance engine). `authorised` must be a JSON boolean and `decision` a string,
    or the answer is refused. AuthZEN needs a boolean `decision`. Either dialect refuses content
    after the object and a member named twice.

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
- Create the processor instance + the types + enable them on the client:
  `idp-agentic-demo/pingfederate/rar-paz/config-as-code/{create-processor-instance,enable-on-client}.sh`.
- Author the PDP policy in `paz/` (PAP REST API). Wire contract: top-level `README.md`.
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
