# openid-federation

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly the standalone repo [`dphhyland/openid-federation`](https://github.com/dphhyland/openid-federation) — still live for existing consumers, **backports only**. Absorbed with history 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).


OpenID Federation 1.0 building blocks: trust-chain validation, the federation entity endpoints, a trust
controller gateway, and federation-gated client authorization. Framework-agnostic — depends only on
[`oidf-jose`](https://github.com/dphhyland/oidf-jose); the PingFederate-specific signer and OGNL hooks live
in [`pf-integration`](https://github.com/dphhyland/pf-integration).

## What's here

- **`TrustChainValidator`** — validates an OpenID Federation trust chain from a leaf entity up to a
  configured trust anchor (`authority_hints` walking, subordinate-statement signature checks, freshness),
  with a bounded `SubordinateStatementCache`.
- **`TrustControllerGateway` / `HttpTrustControllerGateway`** — resolves an entity through a trust
  controller's `/resolve` endpoint and verifies the anchor-signed resolve response.
- **`ClientEntityAuthorizer`** — the federation *authorization* decision for a client: is the entity a
  member (chain resolves), within policy (registration types), active (status), and are the requested
  scopes within what the entity is registered for. A pure decision object.
- **`FederationService` / `OpenIdFederationServlet`** — serves the entity configuration
  (`/.well-known/openid-federation`), entity statements, and `fetch` / `list` / `resolve`. The signing key
  is injected (`SigningKeyProvider`) so the transport stays host-agnostic.

## Install

```xml
<dependency>
  <groupId>com.pingidentity.ps.oidf</groupId>
  <artifactId>openid-federation</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Build

```bash
mvn -o clean install     # offline; requires oidf-jose 0.1.0 in ~/.m2
```

Tests cover chain validation (including live federation fixtures) and the client-authorization decision.
