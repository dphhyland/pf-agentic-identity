# gm-api — Grant Management & Evaluation API for PingFederate

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Absorbed with history from the local `idp-gm-api` repo; the AS-agnostic Go service was extracted from it to **grant-evaluation-api** (a private repo, checked out as a sibling). See [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

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
- [`docs/pingfederate-gm-api-gaps.md`](docs/pingfederate-gm-api-gaps.md) — the implementer's report, written against PF 13.0.3 and not re-run on 13.1.3: §6 and §7.1 can be added from outside the product, §5 cannot; what PF supports natively (nothing, verified then).
- [`docs/MCP.md`](docs/MCP.md) — the MCP server: tools (`evaluate_grant`, `list_entitlements`, `describe_grant`), transport, why it holds no credential of its own.

## Build

`services/gm-api/servlet` builds like every other module in the reactor: it imports the repo BOM, and
its dependencies carry no versions of their own. Only its groupId differs - it keeps the coordinates
`au.com.idpartners:gm-api`, on the reactor's version (`tools/set-version.py` keeps it in step). Every
PingFederate dependency is `provided` and comes from PingFederate at run time; from 0.5.0 the war bundles only
this repository's own `platform-pf` and `platform`, for its lifecycle listener, health and start-up audit
([libs/platform-pf](../../libs/platform-pf/README.md#lifecycle)). At build time
`pingfederate-sdk` is one of the two jars `.github/actions/pf-provided-jars/action.yml` installs from the
public `pingidentity/pingfederate` image, and the rest come from Maven Central: `jose4j`,
`jackson-databind` and `jackson-core` at the versions the BOM holds to the image, and `jakarta.servlet-api`
5.0.0, the API line the image's Jetty ships as 5.0.2 (`tools/pf-linkcheck.py` checks the servlet members
the war uses). Bundling any of them into the war would break linkage: PF isolates each deploy-dir
artifact on its own classloader.

## Related

- **AS-agnostic Go reference:** **grant-evaluation-api** - a private repo, checked out as a sibling under `~/Source/`
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

From 0.6.0 (plan item S5d) the call goes through libs/platform's `OutboundHttp`, and `pdpTimeoutMs` (10 s by
default) bounds the whole exchange, the answer's body included, and a value above 10 s holds; before, it bounded the
connect and each read apart, so a PDP sending a byte at a time held a grant request without end. Connecting, TLS
included, takes at most platform's default 5 s within it (before, it could take the whole `pdpTimeoutMs`), and at most platform's default 256 KiB of the answer is read. A `pdpTimeoutMs` of zero or below,
which meant no timeout, is now the 10 s default. The PDP is internal by design (the demo reaches PingAuthorize at
`http://pingauthorize.railway.internal:1080`), so the URL `pdpUrl` names is exempt from the scheme and address rules -
pinned to its scheme, host, port and path - and nothing else is; production already refuses an http `pdpUrl`. The JVM's
trust store decides the PDP's certificate, which must name its host. Every failure - no answer by the deadline, a body
over the cap, a TLS failure, a status other than 200 - is a PDP that could not be asked, a 503, with the reason in the
log; never a denial.
