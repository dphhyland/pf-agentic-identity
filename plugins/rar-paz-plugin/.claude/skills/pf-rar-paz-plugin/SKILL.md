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

## When this fires
- RFC 9396 / RAR / `authorization_details` on **PingFederate** specifically.
- Governing **token issuance/exchange** with **PingAuthorize** (as opposed to per-request API gating).
- Editing this plugin's Java (`com.pingidentity.ps.oidf.rar.*`), its PF config, or its build/deploy.
- Consent/approval pages that should show the *specific* authorized operation, not just a scope.

## Architecture (one screen)
```
authorization_details entry ─▶ AttestationAwareRarProcessor.enrich()
  ├─ resolve principal  (resourceOwner → attestation sub → client_id)  → UserID
  │    · resourceOwner arrives via an authorization_details "_principal_sub" marker
  │      (the only channel that survives PAR — PF does NOT surface login_hint/params
  │       to the processor); the plugin strips it before the decision/consent/token.
  ├─ GovernanceEngineRequestBuilder → DecisionRequest (domain/service/action/attributes)
  ├─ GovernanceEngineClient ─POST─▶ PingAuthorize /governance-engine
  ├─ deny unless decision.isPermit()
  └─ StatementApplier: merge obligations into the granted detail
```
All I/O + mapping live in framework-agnostic collaborators (`GovernanceEngine*`, `Decision*`,
`StatementApplier`, `RarContainment`), unit-tested without the SDK. Only
`AttestationAwareRarProcessor` touches the PF SDK. The request builder is pluggable
(`DecisionRequestBuilder`) so an AuthZEN `/access/v1/evaluation` shape can be added later.

## Key facts that bite
1. **PF exposes no resource owner to the processor.** `AuthorizationDetailContext` (through
   SDK 13.0.0.3) has only `getRequest()`, `getClientId()`, `getScope()`. To attribute the
   decision to the human, the front-end folds `_principal_sub` into `authorization_details`
   (survives PAR); the plugin reads it as `UserID` (agent → `actor`, RFC 8693 delegation)
   and strips it. `login_hint` does NOT reach the processor under PAR.
2. **Plugin loading needs a `PF-INF/<type>` marker + shaded deps.** `src/main/resources/PF-INF/
   authorization-detail-processors` lists the class. Jackson is relocated INTO the jar (PF
   isolates each deploy jar's classloader). A `META-INF/services` marker does NOT work.
3. **TLS to an internal PDP.** The JDK HttpClient enforces a TLS-1.3 in-handshake hostname
   check a trust-all SSLContext can't disable. Fix = JVM flag
   `-Djdk.internal.httpclient.disableHostnameVerification=true` in `run.sh` (NOT `ENV
   JAVA_OPTS`). Or give the PDP cert a matching SAN.
4. **`purpose`/`actionName`-style cross-plane attrs** should carry a `""` defaultValue in the
   PingAuthorize Trust Framework, else absent attrs go INDETERMINATE and DenyOverrides bites.

## How to build
```bash
mvn -q package                 # → target/pf.plugins.pf-rar-paz-plugin.jar  (+ 23 unit tests)
```
The PF SDK is not on Maven Central — resolve `pf-protocolengine` + `pingfederate-sdk`
(version = `<version.server-sdk>` in the pom) into `~/.m2` from a PF install. See
`integration/README.md`.

## How to deploy + configure
- Bake the jar with `integration/Dockerfile.fragment` (jar → `deploy/`, optional consent
  template, the TLS JVM flag).
- Create the processor instance + enable it on the client:
  `integration/config-as-code/{create-processor-instance,enable-on-client}.sh`.
- Author the PDP policy in `paz/` (PAP REST API). Wire contract: top-level `README.md`.

## Railway deploy command (if applicable)
```bash
railway up <pf-image-dir> --path-as-root --service <svc> --no-gitignore --detach
```
`--path-as-root` (else the subdir Dockerfile isn't found → Railpack fails) and
`--no-gitignore` (else gitignored secrets the Dockerfile COPYs are excluded). Confirm the
jar actually shipped: `railway ssh … "wc -c < …/deploy/pf.plugins.pf-rar-paz-plugin.jar"`
and compare to the freshly built jar's size — Railway can silently serve the last-good image.

## Wire contract (governance-engine JSON API)
```
POST <PDP URL>                         <secret-header>: <secret>
{ "domain":"<domainPrefix>.<type>", "service":"Authorization", "action":"authorize",
  "attributes": { "UserID":"<principal>", "actor":"<agent, if attested>", "client_id":"…",
                  "<attrPrefix>.<type>.<field>":"<json>",  "att_<field>":"…", "req_<field>":"…",
                  "attestation.entitlement":"<json>", "attestation.cnf_thumbprint":"…" } }
 → { "decision":"PERMIT|DENY|…", "authorised":true|false, "statements":[{"name":"a.b","payload":…}] }
```
