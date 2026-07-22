# pf-rar-paz-plugin

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly a standalone local repo, absorbed with history. Absorbed with history 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).


A PingFederate **`AuthorizationDetailProcessor`** (RFC 9396 Rich Authorization Requests) that acts as a
**Policy Enforcement Point**: it forwards each requested `authorization_details` entry — together with the
**client attestation's** vouched subject / entitlement / workload — to a **PingAuthorize governance-engine**
decision, denies unless the decision is `PERMIT`, and applies any returned statements (downscoping /
obligations).

It is modelled on the reference `RARAuthDetailsProcessor` but closes that demo's gaps: it **honours the
decision** (the reference read only `statements` and could never deny), maps a **real subject** (not a
hardcoded `"joe"`), passes the **attested entitlement** so policy can enforce `requested ⊆ attested`, uses a
scoped **insecure-TLS dev flag** instead of an always-on trust-all manager, and implements a real
`isEqualOrSubset` for refresh-time narrowing.

Status: **built, unit-tested (23 tests), and verified live** — governs RFC 9396 payment
consent end-to-end (PERMIT ≤ limit / DENY over-limit), attributes the decision to the
authenticated principal (`UserID`) with the agent as `actor`, and renders an
attribute-focused consent page.

## Repository layout

| Path | What |
|------|------|
| [`src/`](src) · [`pom.xml`](pom.xml) | the plugin (Java) + 23 unit tests; `PF-INF` marker; shaded Jackson |
| [`integration/`](integration) | **PingFederate integration** — `Dockerfile.fragment`, the TLS JVM flag, `config-as-code/` (create processor instance + enable on client), `consent-template/` |
| [`paz/`](paz) | **PingAuthorize** Trust Framework + policy-authoring scripts (PAP REST API) |
| [`.claude/skills/pf-rar-paz-plugin/`](.claude/skills/pf-rar-paz-plugin) | reusable **skill** — build/deploy/configure knowledge for future projects |

Quick start: [`integration/README.md`](integration/README.md).

**Attestation context (optional):** the plugin can bound the decision by a client
attestation's vouched subject/entitlement/workload if an upstream hook publishes them as a
request attribute (`com.pingidentity.ps.oidf.rar.attestation_context`, a plain `Map`). This
is a decoupled string-key contract — no code dependency — so it works with or without an
attester. See "Attestation-context bridge" below.

## Architecture

```
authorization_details entry ─▶ AttestationAwareRarProcessor.enrich()
                                 ├─ read AttestationSubject from HttpServletRequest attribute
                                 ├─ GovernanceEngineRequestBuilder → DecisionRequest
                                 ├─ GovernanceEngineClient ─POST─▶ PingAuthorize /governance-engine
                                 ├─ deny unless decision.isPermit()
                                 └─ StatementApplier: merge obligations into the granted detail
```
All I/O and mapping live in framework-agnostic collaborators (`GovernanceEngine*`, `Decision*`,
`StatementApplier`, `RarContainment`), unit-tested without the PF SDK. Only
[`AttestationAwareRarProcessor`](src/main/java/com/pingidentity/ps/oidf/rar/AttestationAwareRarProcessor.java)
touches the SDK.

## Wire contract (native governance-engine "JSON API")

```
POST <PDP URL>                         <secret-header>: <secret>
{ "domain":  "<domainPrefix>.<type>",
  "service": "Authorization",
  "action":  "authorize",
  "attributes": {
    "UserID": "<attestation sub | client_id>",
    "client_id": "<client_id>",
    "<attrPrefix>.<type>.<field>": "<json-stringified value>",   // each requested field
    "attestation.entitlement": "<json>",                         // the attested ceiling
    "attestation.workload":    "<json>",
    "attestation.cnf_thumbprint": "<thumbprint>" } }
   ↓
{ "decision":"PERMIT|DENY|NOT_APPLICABLE|INDETERMINATE", "authorised":true|false,
  "statements":[ {"name":"a.b","payload":…} ] }
```
The request builder is pluggable (`DecisionRequestBuilder`) so an AuthZEN `/access/v1/evaluation` shape can be
added later without changing the client or processor.

## Attestation-context bridge (Phase 1b contract)

The processor reads attestation context via `AuthorizationDetailContext.getRequest().getAttribute(key)`. On
successful attestation authentication the hook (`ClientAttestationUtils` in `pf-oidf-modules`) sets:

- **key:** `com.pingidentity.ps.oidf.rar.attestation_context` (`AttestationSubject.REQUEST_ATTRIBUTE`)
- **value:** a `Map` with `sub`, `client_id`, `entitlement` (the attested `authorization_details` array, i.e.
  `ClientAttestationResult.entitledAuthorizationDetails()`), and `cnf_thumbprint`.
  *(`workload` is not yet surfaced — it is not parsed into `ClientAttestation`/the result; a small follow-up.)*

When the context is absent (e.g. a non-attestation client), the processor falls back to `context.getClientId()`
as the subject and sends no attested entitlement (policy then decides on the request alone).

## Build

```bash
# PF SDK 13.0.0.3 must be in ~/.m2 (pf-protocolengine, pingfederate-sdk) — see integration/README.md
mvn -o -B package            # offline; jackson pinned to 2.17.1 (all jars present in ~/.m2)
# → target/pf.plugins.pf-rar-paz-plugin.jar
```

## Deploy

Full recipe in [`integration/`](integration): bake the jar with
[`integration/Dockerfile.fragment`](integration/Dockerfile.fragment) (the jar is a shaded
uber-jar — no separate Jackson jars to copy), then create the processor instance + enable it
on the client with [`integration/config-as-code/`](integration/config-as-code). The
processor already declares its RAR types (`sales_agent`, `payment_initiation`,
`account_information`) in code, so you only enable them per client.

### GUI config fields (same fields the config-as-code sets)

| Field | Default | Notes |
|-------|---------|-------|
| Governance engine decision URL | — (**required**) | e.g. `https://<paz>:1443/governance-engine` |
| PDP domain prefix | `idpartners.authorization_details` | `domain` = prefix + `.` + type |
| PDP service / action | `Authorization` / `authorize` | policy target |
| Attribute prefix | `idp` | request-field attribute prefix |
| Prefix attributes with detail type | on | `idp.<type>.<field>` vs `idp.<field>` |
| Shared-secret header / value | `CLIENT-TOKEN` / — | governance-engine auth |
| Deny unless the decision is PERMIT | on | the enforcement switch the reference lacked |
| Fail open if the engine is unreachable | off | on = allow when the PDP errors |
| Skip TLS verification (dev only) | off | for self-signed test PDPs |
| Request timeout (ms) | 10000 | |

## Test

```bash
mvn -o test    # 23 tests: request building (incl. principal→UserID / agent→actor),
               # decision parsing (permit/deny/obligations), client transport + auth header,
               # statement application, containment
```
