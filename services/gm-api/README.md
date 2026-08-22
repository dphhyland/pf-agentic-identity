# gm-api — Grant Management & Evaluation API for PingFederate

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from the local `idp-gm-api` repo; the AS-agnostic Go service was extracted from it to **grant-evaluation-api** (sibling checkout, not yet published). See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

The proposed **Grant Evaluation API** (an extension to the OpenID Grant Management API) running
**inside PingFederate** as a servlet war (`gm-api.war`), plus an `/mcp` add-on so an AI agent can ask
before it acts.

A client asks whether an existing grant still permits an action — right now, without a new
authorization flow. The answer is an intersection: *what the client was granted* ∩ *what the subject
actually holds* ∩ *the agent's authority* (when an agent is acting). A grant can be valid, unexpired
and correctly scoped and still worthless, because the subject closed the account it names. That is
what a token introspection cannot see.

## What's here

| Path | What |
|---|---|
| [`servlet/`](servlet) | The API as a PF war: query / revoke / evaluate / metadata + the `/mcp` JSON-RPC add-on. Reads grants in-process via the PF SDK (`AccessGrantManagerAccessor`), verifies tokens against PF's own keys (`JwksEndpointKeyAccessor`). **Start at [`servlet/README.md`](servlet/README.md).** |
| PF + PingDirectory config | Not here — this repo configures no PingFederate. The Terraform (token manager, scopes, clients, PCV) and the grant-store LDIFs moved to [`idp-agentic-demo/gm-api/`](https://github.com/dphhyland/idp-agentic-demo/blob/main/gm-api) on 2026-08-21, beside `gm-pdp` and the agents that exercise them. |
| [`docs/`](docs) | see below |
| [`examples/`](examples) | `java/GrantManagementClient.java`, a single-file JDK-only client; curl and Go examples live with the Go reference |

## Docs

- [`docs/INTEGRATING.md`](docs/INTEGRATING.md) — how another project calls this: the question it answers, which endpoint, getting a token (user present / client credentials / agent delegation), the four operations, reading the answer, gotchas.
- [`docs/GMAPI-Extension.md`](docs/GMAPI-Extension.md) — the proposed spec text: §3.8 use case, §6.7 Grant Evaluation endpoint and its scopes, §7.1 metadata, §8.4 implementation considerations, privacy and security.
- [`docs/authzen-oauth-profile.md`](docs/authzen-oauth-profile.md) — AuthZEN profile for OAuth 2.0 / OIDC: how scopes, claims and RAR map onto the AuthZEN information model.
- [`docs/pingfederate-gm-api-gaps.md`](docs/pingfederate-gm-api-gaps.md) — the implementer's report against PF 13.0.3: §6 and §7.1 can be added from outside the product, §5 cannot; what PF supports natively (nothing, verified).
- [`docs/MCP.md`](docs/MCP.md) — the MCP server: tools (`evaluate_grant`, `list_entitlements`, `describe_grant`), transport, why it holds no credential of its own.

## Build — this module is different

`services/gm-api/servlet` is a **vendored tree** and deliberately not a consumer of the repo BOM: groupId
`au.com.idpartners`, artifact `gm-api` 1.0.0, and every dependency `provided` under the
`local.pingfederate:*` coordinate convention (`pingfederate-sdk` 13.0.3, `servlet-api` 4.0.9, `jose4j`
1.x, `jackson-*` 2.x, `commons-lang3` 3.x, `commons-logging` 1.x). Those coordinates exist in `~/.m2`
only after the `install:install-file` lines in `.github/workflows/build.yml` have run — CI extracts the
jars from the public `pingidentity/pingfederate` image; locally, run those lines once (or copy the jars
out of a running PF as [`servlet/README.md`](servlet/README.md) shows). Without them the root
`mvn package` fails on this module. Bundling any of them into the war would break linkage: PF isolates
each deploy-dir artifact on its own classloader.

## Related

- **AS-agnostic Go reference:** **grant-evaluation-api** - a sibling checkout under `~/Source/`, not yet published to GitHub
  — the same API over a pluggable grant source (PF, or any RFC 7662 introspection endpoint), plus the
  demo AuthZEN PDP (`cmd/pdp`) and the grant-creation script (`scripts/authcode.py`) the servlet's
  verification steps use.
- **RAR consent processor:** [`plugins/rar-paz-plugin`](../../plugins/rar-paz-plugin) governs
  `authorization_details` at consent time via PingAuthorize — the native consent the evaluator prefers
  over the interim grant-attribute fallback.

## The PDP

The servlet is the enforcement point; the decision is an **AuthZEN 1.0 PDP** it calls
(`/access/v1/evaluation`, resource search at `/access/v1/search/resource`). For a demo PDP, run
`cmd/pdp` from `grant-evaluation-api`, or point `pdpUrl` at PingAuthorize behind its AuthZEN facade.
The servlet needs no PDP code of its own.
