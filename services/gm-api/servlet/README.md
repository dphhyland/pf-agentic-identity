# The Grant Management API as a PingFederate servlet

The same API as the Go reference's `cmd/gm-api`
(**grant-evaluation-api**, sibling checkout), deployed **inside**
PingFederate instead of beside it. Package `au.com.idpartners.gm.servlet`, artifact `gm-api.war`.

```
GET    https://localhost:9131/gm-api/grants/{grantId}            query    (spec 6.2)
DELETE https://localhost:9131/gm-api/grants/{grantId}            revoke   (spec 6.3)
POST   https://localhost:9131/gm-api/grants/{grantId}/evaluate   evaluate (spec 6.7, proposed)
GET    https://localhost:9131/gm-api/.well-known/grant-management-configuration
POST   https://localhost:9131/gm-api/mcp                          MCP tools for AI agents
```

The MCP add-on lets an AI agent ask "may I do this?" before acting, authenticated with the agent's own
delegated token; read-only (`evaluate_grant`, `describe_grant` — revoke is deliberately not exposed).
See [`../docs/MCP.md`](../docs/MCP.md).

**PingFederate implements none of the Grant Management API itself** — no §7.1 metadata, no §6
endpoints, and it ignores the §5 `grant_management_action` parameter outright. This servlet puts the
spec's shape on PF's own grant store. What it cannot do is §5, which is AS behaviour rather than an
endpoint. Full report: [`../docs/pingfederate-gm-api-gaps.md`](../docs/pingfederate-gm-api-gaps.md);
what to send: [`../docs/INTEGRATING.md`](../docs/INTEGRATING.md).

Each operation requires exactly its own scope, so a client registered only to evaluate cannot thereby
read or revoke: `grant_management_query` / `grant_management_revoke` / `grant_management_evaluate`.

## How it loads, and why in-process

PF's plugin SDK has no extension point for a REST endpoint — which is why this started as a Go sidecar.
But PF runs on Jetty and its `PFWebAppProvider` deploys wars out of `server/default/deploy`, making the
war name the context path (`gm-api.war` → `/gm-api`), exactly how PF's own `pf-ws.war` serves
`/pf-ws/rest/oauth/...`. `web.xml` declares Servlet 3.1 and carries no container security — the
servlet verifies the bearer itself. Being in-process removes every seam the sidecar had, each of which
produced a real bug:

| Sidecar | Servlet |
|---|---|
| service-account PCV + Basic auth to `/pf-ws/rest/oauth/...` | `AccessGrantManagerAccessor.getAccessGrantManager().getByGuid(id)` |
| `-insecure-skip-verify` for PF's self-signed cert | no network hop |
| unpicking consent from a JSON string in a grant attribute | `AccessGrant.getAuthorizationDetails()`, typed (the attribute stays as fallback for a PF with no Authorization Detail Processor) |
| `JWKS_URL` + `TOKEN_ISSUER`, which can disagree | `JwksEndpointKeyAccessor` — the server's own keys |

The issuer is not checked, deliberately: a token verified against this server's own signing keys was
necessarily issued by this server. The **audience** is checked, because this server mints tokens for many
audiences and one meant for a different API must not be accepted here.

## Layout

| Class | Responsibility |
|---|---|
| `GrantsServlet` | HTTP: routing, the bearer header, JSON, status codes for the three REST operations |
| `McpServlet` | JSON-RPC 2.0 over MCP Streamable HTTP; same rules, no authorisation logic of its own |
| `MetadataServlet` | §7.1 metadata at a non-conformant path (PF's own AS metadata cannot be extended) — see the gaps report |
| `GrantOperations` | the operations, transport-independent — REST and MCP both go through here so they cannot drift |
| `GrantEvaluator` | `authorise()` — the (client, AS, subject) rule every operation shares — plus the §8.4.2 gates and the AuthZEN request. **No PF types**; unit tested |
| `GrantView` | reads a PF `AccessGrant` into plain data; every PF-specific assumption lives here |
| `TokenClaims` | the token's three identities: principal `sub`, actor `act.sub`, operator `client_id` |
| `PfTokenVerifier` | verifies the token against PF's own signing keys |
| `PdpClient` | AuthZEN 1.0 over HTTP (`/access/v1/evaluation`, `/access/v1/search/resource`) — the one thing that stays remote, on purpose |

`GrantView` exists because PF's `AccessGrant` is **not** a value object: constructing one reaches into the
server's service locator and throws `No Impl found for AccessGrantService` outside a running PF.
Isolating it keeps the decision logic ordinary and testable (53 tests; jacoco gates
`GrantEvaluator.build*` / `authorise` at 100% line + branch).

## Build

Not a BOM consumer: every dependency is `provided` under `local.pingfederate:*` coordinates
(`pingfederate-sdk` 13.0.3, `servlet-api` 4.0.9, `jose4j`, `jackson-*`, `commons-lang3`,
`commons-logging`). The PF SDK is Ping-licensed and not on Maven Central, so those coordinates must be
installed into `~/.m2` first — the `install:install-file` lines in `.github/workflows/build.yml` do it
from the public `pingidentity/pingfederate` image; or copy the jars out of a running PF:

```bash
PF=gm-pingfederate
for j in pingfederate-sdk jose4j commons-logging commons-lang3 jackson-core jackson-databind jackson-annotations; do
  src=$(docker exec $PF sh -c "find /opt/out/instance/server/default/lib /opt/out/instance/lib -iname '${j}*.jar' | head -1")
  docker cp "$PF:$src" lib/
done
docker cp $PF:/opt/out/instance/lib/jetty-servlet-api-4.0.9.jar lib/
mvn install:install-file -Dfile=lib/pingfederate-sdk.jar -DgroupId=local.pingfederate \
  -DartifactId=pingfederate-sdk -Dversion=13.0.3 -Dpackaging=jar -DgeneratePom=true
# likewise servlet-api (4.0.9), jose4j (1.x), commons-logging (1.x), commons-lang3 (3.x), jackson-{core,databind,annotations} (2.x)

mvn -pl services/gm-api/servlet package     # from the repo root → target/gm-api.war
```

`lib/*.jar` is gitignored. **Bundle nothing**: PF isolates each deploy-dir artifact on its own
classloader, so a second copy of a PF class would not be the same class (`rar-paz-plugin` shades jackson
for the same reason — it needs jackson but must not collide with PF's).

## Deploy and configure

```bash
docker cp target/gm-api.war gm-pingfederate:/opt/out/instance/server/default/deploy/
docker restart gm-pingfederate
```

`web.xml` init-params, with env fallbacks (`McpServlet.ServletConfigs`, shared by both servlets):

| Param | Env | Meaning |
|---|---|---|
| `pdpUrl` | `AUTHZEN_BASE_URL` | AuthZEN PDP base URL; `/access/v1/evaluation` is appended. **Required** |
| `audience` | `GM_AUDIENCE` | the `aud` this API answers to (the token manager's audience claim). **Unset accepts any token this server signed** |
| `pdpToken` | `AUTHZEN_BEARER_TOKEN` | credential for a protected PDP |
| `pdpTimeoutMs` | — | default 10000 |
| `issuer`, `grantManagementEndpoint` (metadata servlet) | — | what `/.well-known/grant-management-configuration` advertises; endpoint defaults to `<base>/gm-api/grants` |

Confirm it started: `Started ContextHandler{Grant Evaluation API,/gm-api,...,a=AVAILABLE}` —
`a=UNAVAILABLE` means the context failed; check `web.xml` parsed.

## Three things that will cost you an hour each

- **`--` is illegal inside an XML comment.** A `web.xml` with one fails to parse, Jetty marks the context
  `UNAVAILABLE`, and the endpoint 404s. It looks exactly like a deployment problem.
- **`getPathInfo()` has the servlet path already stripped.** Mapped at `/grants/*`, a request to
  `/gm-api/grants/{id}/evaluate` yields pathInfo `/{id}/evaluate`. Pinned by `PathTest`.
- **PingFederate regenerates its signing keys on restart** when the container has no persistent
  keystore, so every restart invalidates every previously issued token — `Unable to find a suitable
  verification key` reads like a code bug and is not. Re-run the grant-creation flow.

## Verify

The demo PDP and the grant-creation script ship with the Go reference; run them from a checkout of
**grant-evaluation-api** (sibling checkout) against the PF in
[`../deploy/pingfederate/`](../deploy/pingfederate/README.md).

```bash
go run ./cmd/pdp -addr :9099 -expose-entitlements &   # AuthZEN PDP the servlet calls
python3 scripts/authcode.py <tpp-secret>              # fresh PF grant + token; prints TOKEN and its agid
curl -sk -X POST "https://localhost:9131/gm-api/grants/$AGID/evaluate" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
# {"decision":false,"context":{"reasons":[{"id":"subject_not_entitled","message":"You no longer have access to this account."}]}}
```

Against Alice's grant (consents to 111, 222, 444): `111` read_balance **Permit**; `222` read_balance
**Deny** (consent holds, subject no longer holds the account); `444` read_balance **Permit**; `444`
read_transactions **Deny** (right missing); `999` read_balance **Deny** (no consent).

## Agents: delegation, not impersonation

An agent presents a token minted by RFC 8693 token exchange: `sub` is the principal (Alice), `act.sub` is
the agent actually calling, `client_id` is the agent **operator** — the legal entity responsible for the
agent, not the agent. `TokenClaims` reads all three and `GrantEvaluator` passes the actor to the PDP as
`context.actor = {delegated, id, chain (current actor first, RFC 8693 §4.1), operator}`. Effective access
becomes `grant ∩ subject entitlement ∩ agent authority`: an agent can only ever be *narrowed* against
Alice's grant, never widened past it.

A token with `sub: alice` and no `act` is impersonation — indistinguishable from Alice acting herself.
The servlet marks it `delegated: false` rather than guessing and does not refuse it: only policy knows
whether an agent flow was expected. The actor is taken **only** from the signed token; a caller-supplied
`context.actor` is overwritten (`DelegationTest`).

**Not wired here:** PingFederate must actually *mint* the delegated token — a token-exchange processor
policy that nests `act`. The PF in `../deploy/pingfederate/` is not configured for it, so the live path
there only exercises `delegated: false`; act-chain reading, nesting, cycle-safety and propagation are
covered by `DelegationTest`. `may_act` — who may delegate — is enforced at token exchange, upstream of
this API.

## Relationship to the Go service

Both exist on purpose. This is the PingFederate artifact; `cmd/gm-api` is the AS-agnostic reference for
the spec proposal, and the only one that demonstrates the extension is not Ping-specific. They agree on
the AuthZEN request shape and on the §8.4.2 gates, which is what makes them the same API rather than
two. The consent path mirrors too: native `getAuthorizationDetails()` wins, and the
`authorization_details` grant attribute is the fallback (see `../deploy/pingfederate/README.md`).
