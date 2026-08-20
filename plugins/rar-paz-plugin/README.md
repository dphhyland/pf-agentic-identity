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

Status: unit-tested (38 tests) and verified live against PingAuthorize — governs payment consent
end-to-end (PERMIT ≤ limit / DENY over-limit), attributes the decision to the authenticated principal
(`UserID` / AuthZEN `subject`) with the agent instance as `actor`, and renders an attribute-focused
consent page.

## Layout

| Path | What |
|---|---|
| [`src/`](src) · [`pom.xml`](pom.xml) | the plugin (`com.pingidentity.ps.oidf.rar`) + tests; `PF-INF` marker; shaded jackson |
| [`integration/`](integration) | PingFederate integration — `Dockerfile.fragment`, the TLS JVM flag, `config-as-code/` (create processor instance + enable on client), `consent-template/` |
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
   ├─ principal            ← resource_owner_sub attribute | login_hint | the _principal_sub detail
   │                          marker the BFF folds in (the only channel that survives PAR); stripped
   ├─ GovernanceEngineRequestBuilder | AuthZenRequestBuilder   (PDP Dialect field)
   ├─ GovernanceEngineClient | AuthZenPdpClient  ─POST─▶ PDP    (PdpClient seam, JdkHttpTransport)
   ├─ deny unless decision.isPermit()   (fail-open only if configured)
   └─ StatementApplier: merge statements/obligations into the granted detail (dot-path)
```

Only `AttestationAwareRarProcessor` touches the SDK; the builders, clients, `DecisionResponse`,
`StatementApplier` and `RarContainment` are plain code, tested without PF. `AuthorizationDetailContext`
exposes no resource owner (verified through SDK 13.0.0.3), hence the out-of-band principal lookup above.

**`RarContainment`** duplicates the containment semantics of `RarEntitlement` in
[`libs/client-attestation`](../../libs/client-attestation) on purpose — kept local so the plugin builds
and loads standalone on its isolated classloader rather than shading the library in — and its javadoc
carries the TODO to consolidate the two. Same set-valued fields (`actions`, `locations`, `datatypes`,
`privileges`, `sales_regions`); if one changes, change both.

## Attestation-context bridge

`servlets/pf-integration`'s `ClientAttestationUtils` publishes the verified attestation as a request
attribute after `attest_jwt_client_auth` succeeds; this plugin reads it via
`AuthorizationDetailContext.getRequest()`. A string-keyed plain `Map`, so neither module depends on the
other across classloaders:

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
| Skip TLS verification (dev only) / Request timeout (ms) | off / 10000 |

Supported RAR types are declared in code (`sales_agent`, `payment_initiation`, `account_information`);
you only enable them per client.

## Build, test, deploy

```bash
mvn -pl plugins/rar-paz-plugin -am package     # → target/pf.plugins.pf-rar-paz-plugin.jar (38 tests)
```

Versions come from the repo BOM (`bom/pom.xml`); the two `provided` PF jars must be in `~/.m2` — the
`install:install-file` lines in `.github/workflows/build.yml`. Deploy recipe in
[`integration/README.md`](integration/README.md). Note the monorepo's own `build/pingfederate/` image is
the OIDF-only AS and deliberately does **not** bake this plugin.
