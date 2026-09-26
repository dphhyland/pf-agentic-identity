---
name: pf-rar-paz-plugin
description: >-
  Build, deploy, and configure the pf-rar-paz-plugin — a PingFederate
  AuthorizationDetailProcessor (RFC 9396 Rich Authorization Requests) that governs each
  authorization_details entry via a PingAuthorize governance-engine decision. Fires when
  working with RAR/authorization_details on PingFederate, governing token issuance with
  PingAuthorize, this plugin's Java code, its PF config, or its build/deploy.
---

# pf-rar-paz-plugin

A PingFederate SDK `AuthorizationDetailProcessor` that turns RFC 9396
`authorization_details` into a **policy decision**: for each requested entry it POSTs to a
**PingAuthorize governance-engine** endpoint, **denies unless the decision is PERMIT**, and
applies returned statements (downscoping/obligations). It is a Policy Enforcement Point at
**token issuance** — complementary to per-API-call PEPs.

**PingFederate 13.1 only.** It reads the request through
`AuthorizationDetailContext.getJakartaRequest()`, which 13.0 does not have. The last build for
13.0.x is v0.1.5, on the frozen `pf-13.0` branch.

## When this fires
- RFC 9396 / RAR / `authorization_details` on **PingFederate** specifically.
- Governing **token issuance/exchange** with **PingAuthorize** (as opposed to per-request API gating).
- Editing this plugin's Java (`com.pingidentity.ps.oidf.rar.*`), its PF config, or its build/deploy.
- Consent/approval pages that should show the *specific* authorized operation, not just a scope.

## Architecture (one screen)
```
authorization_details entry ─▶ AttestationAwareRarProcessor.enrich()
  ├─ resolve principal  (resourceOwner → attestation sub → client_id)  → UserID
  │    · resourceOwner: the resource_owner_sub request attribute an authn hook sets;
  │      else login_hint or the "_principal_sub" detail marker, but ONLY with
  │      "Trust a client-asserted principal" on (off by default - both are what the
  │      caller sent). _principal_sub is always stripped before decision/consent/token.
  ├─ PdpClient — the dialect seam, chosen at configure() time:
  │    · governance-engine (default) → GovernanceEngineRequestBuilder + GovernanceEngineClient
  │    · authzen                     → AuthZenRequestBuilder + AuthZenPdpClient
  ├─ deny unless decision.isPermit()
  └─ StatementApplier: merge obligations into the granted detail
```
All I/O + mapping live in framework-agnostic collaborators (`GovernanceEngine*`, `AuthZen*`,
`Decision*`, `PdpClient`/`HttpTransport`, `StatementApplier`, `RarContainment`), unit-tested
without the SDK. Only `AttestationAwareRarProcessor` touches the PF SDK; its tests use the
package-private `(PdpClient, GovernanceEngineConfig)` constructor as the seam, because
`configure()` otherwise hard-wires `JdkHttpTransport`.

**Two PDP dialects, one enforcement path.** The `PDP Dialect` config field selects
`governance-engine` (default) or `authzen`; `Deny unless PERMIT`, fail-open, timeouts and the
shared-secret header behave identically either way, because the split is behind `PdpClient`.
Note `AuthZenRequestBuilder` does NOT implement `DecisionRequestBuilder` — that interface is
the governance-engine builder only. For `authzen`, point `PDP URL` at
`/access/v1/evaluation`; the AuthZEN response `context` is mapped into the same statement
pipeline (`context.statements` verbatim, every other member becoming one statement, with
`id`/`reason_admin`/`reason_user` treated as metadata).

## Key facts that bite
1. **The plugin finds the resource owner itself.** On 13.1 `AuthorizationDetailContext` has
   `getJakartaRequest()`, `getClientId()`, `getScope()` and `getUserKey()`; the javax
   `getRequest()` is deprecated for removal and the plugin no longer calls it. It does not
   use `getUserKey()` yet: PF fills it from a different source per grant type, unchecked on a
   running server, and a client id taken for a user is the failure to avoid. So the principal
   is still looked up out of band (see the architecture above): to attribute the decision to
   the human behind a PAR request, a trusted front-end folds `_principal_sub` into
   `authorization_details`, which the plugin honours only with "Trust a client-asserted
   principal" on (agent → `actor`, RFC 8693 delegation), and strips. `login_hint` does NOT
   reach the processor under PAR.
2. **Plugin loading needs a `PF-INF/<type>` marker + shaded deps.** `src/main/resources/PF-INF/
   authorization-detail-processors` lists the class. Jackson is relocated INTO the jar (PF
   isolates each deploy jar's classloader). A `META-INF/services` marker does NOT work.
3. **TLS to an internal PDP: give the PDP certificate a SAN that matches the host PF
   dials.** The JDK HttpClient checks the hostname in the handshake even when "Skip TLS
   verification" trusts every certificate. Do NOT set
   `-Djdk.internal.httpclient.disableHostnameVerification=true`, which older notes here
   advised: the JDK reads it once for the whole JVM, so every `java.net.http` client in
   PingFederate stops checking hostnames - the federation fetches, the OpenBao signer and the
   SSF push, poll and introspection calls too - and any certificate from a trusted CA then
   passes for any host (read from the 13.1.3 image's JDK, 2026-09-26).
4. **`purpose`/`actionName`-style cross-plane attrs** should carry a `""` defaultValue in the
   PingAuthorize Trust Framework, else absent attrs go INDETERMINATE and DenyOverrides bites.
5. **Secret header spelling.** The plugin defaults to `CLIENT-TOKEN` (hyphen); the `paz/`
   compose stack and every script there use `CLIENT_TOKEN` (underscore, the PDP's
   `JSON_API_HEADER_NAME`). Mixing the two defaults gives auth failures that look like policy
   failures.
6. **`isPermit()` trusts `authorised` over `decision`.** `{"authorised":true,"decision":"DENY"}`
   is a PERMIT. Non-2xx/malformed responses count as engine errors (fail-open applies); a 2xx
   DENY does not.

## How to build
```bash
mvn -pl plugins/rar-paz-plugin -am package   # from the repo root → target/pf.plugins.pf-rar-paz-plugin.jar
```
JDK 17+ (the pom targets release 17). Jacoco gates the decision methods at 100%; the test
count is in `docs/coverage-dashboard.md`. Versions come from the repo BOM (`bom/pom.xml`).
The PF SDK is not on Maven Central - `pf-protocolengine` + `pingfederate-sdk` 13.1.3.0 are
extracted from the public PF image into `~/.m2` by
`.github/actions/pf-provided-jars/action.yml`; run its `install:install-file` lines once.

## How to deploy + configure
This repo deploys nothing; the recipe lives in `idp-agentic-demo/pingfederate/rar-paz/`.
- Bake the jar with its `Dockerfile.fragment` (jar → `server/default/deploy/`, optional
  consent template). That fragment also adds the JVM-wide hostname flag - leave it out
  (fact 3).
- Create the processor instance + enable it on the client:
  `idp-agentic-demo/pingfederate/rar-paz/config-as-code/{create-processor-instance,enable-on-client}.sh`.
- Author the PDP policy in `paz/` (PAP REST API). Wire contract: top-level `README.md`.
- Confirm the jar that runs is the one you built: compare its size or hash in
  `server/default/deploy/` with the fresh build - a platform can go on serving the last
  good image.

## Wire contract (governance-engine JSON API)
```
POST <PDP URL>                         <secret-header>: <secret>
{ "domain":"<domainPrefix>.<type>", "service":"Authorization", "action":"authorize",
  "attributes": { "UserID":"<principal>", "actor":"<agent, if attested>", "client_id":"…",
                  "<attrPrefix>.<type>.<field>":"<json>",  "att_<field>":"…", "req_<field>":"…",
                  "attestation.entitlement":"<json>", "attestation.cnf_thumbprint":"…" } }
 → { "decision":"PERMIT|DENY|…", "authorised":true|false, "statements":[{"name":"a.b","payload":…}] }
```
