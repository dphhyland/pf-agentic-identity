# pf-rar-paz-plugin

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly a standalone local repo, absorbed with history 2026-07-21; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

A PingFederate **`AuthorizationDetailProcessor`** (RFC 9396 Rich Authorization Requests) that acts as a
Policy Enforcement Point at token issuance: it forwards each requested `authorization_details` entry —
together with the client attestation's vouched subject / entitlement / workload — to a PDP decision,
**denies unless the decision is PERMIT**, and applies any returned statements (downscoping / obligations).
Two PDP dialects: PingAuthorize's native governance engine, or an OpenID AuthZEN 1.0 PDP.

Modelled on Ping's reference `RARAuthDetailsProcessor` but closes its gaps: it honours the decision (the
reference read only `statements` and could never deny), maps a real principal rather than a hardcoded
`"joe"`, passes the attested entitlement so policy can enforce `requested ⊆ attested`, scopes the
insecure-TLS switch to a dev flag, and implements a real `isEqualOrSubset` for refresh-time narrowing.

Status: unit-tested (the count is in [the coverage dashboard](../../docs/coverage-dashboard.md)). Verified
live against PingAuthorize, as recorded on 2026-08-15, on the agentic demo's PingFederate 13.0.3 with the
`javax.servlet` build: it governed payment consent end-to-end (PERMIT ≤ limit / DENY over-limit),
attributed the decision to the authenticated principal (`UserID` / AuthZEN `subject`) with the agent
instance as `actor`, and rendered an attribute-focused consent page. The 13.1 build has not yet run in a
live PingFederate.

**PingFederate 13.1 only.** The plugin reads the request through
`AuthorizationDetailContext.getJakartaRequest()`, which 13.0 does not have, so it does not link there.
The last build for 13.0.x is v0.1.5.

## Layout

| Path | What |
|---|---|
| [`src/`](src) · [`pom.xml`](pom.xml) | the plugin (`com.pingidentity.ps.oidf.rar`) + tests; `PF-INF` marker; shaded jackson |
| [`paz/`](paz) | PingAuthorize Trust Framework + policy-authoring scripts (PAP REST API) — **author-local** compose, see its README |
| [`probe-decision.sh`](probe-decision.sh) | POSTs the plugin's exact governance-engine request shape to a PDP |
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
   ├─ principal            ← resource_owner_sub attribute (trusted, an authn hook sets it server-side)
   │                          else login_hint / the _principal_sub detail marker the BFF folds in - but
   │                          ONLY when "Trust a client-asserted principal" is on; off by default, since
   │                          both are simply what the caller sent. _principal_sub is always stripped.
   ├─ principal_source     ← "authenticated" | "client_asserted" | "none", sent to the PDP alongside
   │                          UserID/subject so policy can tell an authn-hook principal from a caller's word
   ├─ GovernanceEngineRequestBuilder | AuthZenRequestBuilder   (PDP Dialect field)
   ├─ GovernanceEngineClient | AuthZenPdpClient  ─POST─▶ PDP    (PdpClient seam, JdkHttpTransport)
   ├─ deny unless decision.isPermit()   (fail-open only if configured)
   └─ StatementApplier: merge statements/obligations into the granted detail (dot-path)
```

Only `AttestationAwareRarProcessor` touches the SDK; the builders, clients, `DecisionResponse`,
`StatementApplier` and `RarContainment` are plain code, tested without PF. The principal is looked up out
of band, as above. SDK 13.1 adds `AuthorizationDetailContext.getUserKey()`, but PF fills it from a
different source for each grant type, and that has not been checked on a running server; used as it
stands, a client id could be taken for a user. So the plugin does not read it yet - that is later work on
the principal. An authenticated principal always wins over a client-asserted one when both are present - a
caller cannot override the authn hook by also sending a hint.

**`RarContainment`** duplicates the containment semantics of `RarEntitlement` in
[`libs/client-attestation`](../../libs/client-attestation) on purpose — kept local so the plugin builds
and loads standalone on its isolated classloader rather than shading the library in — and its javadoc
carries the TODO to consolidate the two. Same set-valued fields (`actions`, `locations`, `datatypes`,
`privileges`, `sales_regions`); if one changes, change both.

## Attestation-context bridge

`servlets/pf-integration`'s `ClientAttestationUtils` publishes the verified attestation as a request
attribute after `attest_jwt_client_auth` succeeds; this plugin reads it via
`AuthorizationDetailContext.getJakartaRequest()`. A string-keyed plain `Map`, so neither module depends on
the other across classloaders:

- **key:** `com.pingidentity.ps.oidf.rar.attestation_context` (`AttestationSubject.REQUEST_ATTRIBUTE`)
- **value:** `sub` and `client_id` (both the registered client / agent *type*), `agent_id` (the
  attester-minted instance identifier, when one was minted), `entitlement` (the attested
  `authorization_details` ceiling), `workload` (SPIFFE id / attestor / selectors, plus flat `spiffe_id`
  and `attested_by`), `cnf_thumbprint`.

Absent context (a non-attestation client) falls back to `context.getClientId()` and sends no
entitlement — policy decides on the request alone.

## PDP dialects

Selected by the **PDP Dialect** field (`governance-engine`, default, or `authzen`). Enforcement,
fail-open, timeout and the shared-secret header are dialect-independent.

| | `governance-engine` | `authzen` |
|---|---|---|
| Wire | `{domain: <prefix>.<type>, service, action, attributes}` — values JSON-stringified for the Trust Framework, plus flat `req_<field>` / `att_<field>` mirrors (attribute names cannot contain `.`) | AuthZEN 1.0 `{subject, action, resource, context}`; point **PDP URL** at `/access/v1/evaluation` |
| Principal / agent | `UserID` = resource owner, else client id; `actor` = `agent_id` when minted and distinct | `subject = {type: user\|client, id}` by the same precedence; `context.actor = {type: agent, id: agent_id}` (RFC 8693 delegation) |
| Attested ceiling | `attestation.entitlement / workload / cnf_thumbprint` | `context.attestation.{entitlement, workload, cnf_thumbprint}` |
| Decision | `decision: PERMIT\|DENY\|…` + `authorised` | boolean `decision`, required |
| Obligations | `statements: [{name, payload}]` | response `context` mapped into the same statement pipeline: `context.statements` verbatim, every other member one statement; `id` / `reason_*` never merged |

## Configuration (PF admin fields — same names the config-as-code sets)

| Field | Default |
|---|---|
| PDP Dialect | `governance-engine` |
| PDP URL | required |
| PDP Domain Prefix / PDP Service / PDP Action | `idpartners.authorization_details` / `Authorization` / `authorize` |
| Attribute Prefix / Prefix Attributes with Type | `idp` / on |
| Shared Secret Header / Shared Secret | `CLIENT-TOKEN` / — |
| Deny unless PERMIT / Fail open on engine error | on / off |
| Trust a client-asserted principal | off — use `login_hint` / `_principal_sub` as the decision subject when no authenticated principal is present; leave off unless a trusted BFF is the only caller (see below) |
| Trust the PAR-carried agent marker | off - where the attestation is not in the request (the authorization endpoint), take the agent instance from the `_agent_id` the attestation filter put in each entry at PAR; only for clients that must use PAR |
| Skip TLS verification (dev only) / Request timeout (ms) | off / 10000 |

A switch missing from a stored configuration - an instance saved before the field existed, or one written
through the admin API or an archive that left it out - reads as the default above, which is the secure
value for every switch. The version PingFederate shows for the plugin is the jar's
`Implementation-Version`, the project version it was built as.

Supported RAR types are declared in code (`sales_agent`, `payment_initiation`, `account_information`),
plus any the deployment names in `OIDF_RAR_EXTRA_TYPES` or the `oidf.rar.extra.types` system property
(comma- or space-separated; the property wins). You enable them per client.

**TLS to the PDP.** Give the PDP a certificate whose subject alternative name is the host PF dials. "Skip
TLS verification" trusts any certificate, but the JDK HTTP client still checks the hostname during the
handshake. Do not switch that check off with `-Djdk.internal.httpclient.disableHostnameVerification=true`,
as older notes for this plugin said: the JDK reads the property once for the whole JVM, so every
`java.net.http` client in that PingFederate stops checking hostnames - this repo's federation fetches, the
OpenBao signer and the SSF servlet's push, poll and introspection calls, not only this plugin's. Any
certificate from a trusted CA would then pass for any host. (Read from the JDK in the 13.1.3 image,
OpenJDK 21.0.12.1: `AbstractAsyncSSLConnection` takes the flag from a static field, 2026-09-26.)

## Build, test, deploy

```bash
mvn -pl plugins/rar-paz-plugin -am package     # → target/pf.plugins.pf-rar-paz-plugin.jar (tests on)
```

Versions come from the repo BOM (`bom/pom.xml`); the two `provided` PF jars must be in `~/.m2` — the
`install:install-file` lines in `.github/actions/pf-provided-jars/action.yml`. Deploy recipe in
[`idp-agentic-demo/pingfederate/rar-paz/`](https://github.com/dphhyland/idp-agentic-demo/blob/main/pingfederate/rar-paz) — the config-as-code moved there on 2026-08-21, beside the PingAuthorize services that answer it. Its
`Dockerfile.fragment` still adds the JVM-wide hostname flag the TLS note above warns against (checked
2026-09-26); removing it is that repo's change. Note this repo's own `build/pingfederate/` image is
the OIDF-only AS and deliberately does **not** bake this plugin.
