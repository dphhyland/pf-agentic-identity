# The Grant Management API as a PingFederate servlet

The same API as `cmd/gm-api`, deployed **inside** PingFederate instead of beside it.

```
GET    https://localhost:9131/gm-api/grants/{grantId}            query    (spec 6.2)
DELETE https://localhost:9131/gm-api/grants/{grantId}            revoke   (spec 6.3)
POST   https://localhost:9131/gm-api/grants/{grantId}/evaluate   evaluate (spec 6.7, proposed)
GET    https://localhost:9131/gm-api/.well-known/grant-management-configuration
POST   https://localhost:9131/gm-api/mcp                          MCP tools for AI agents
```

The MCP add-on lets an AI agent ask "may I do this?" before acting, authenticated with
the agent's own delegated token. See [`docs/MCP.md`](../docs/MCP.md).

**PingFederate implements none of the Grant Management API itself** — no §7.1 metadata,
no §6 endpoints, and it ignores the §5 `grant_management_action` parameter outright
(even an invalid value returns 200). This servlet puts the spec's shape on PF's own grant
store. What it cannot do is §5, which is AS behaviour rather than an endpoint. The full
implementer's report is in [`docs/pingfederate-gm-api-gaps.md`](../docs/pingfederate-gm-api-gaps.md).

Each operation requires exactly its own scope, so a client registered only to evaluate
cannot thereby read or revoke:

| Operation | Scope |
|---|---|
| query | `grant_management_query` |
| revoke | `grant_management_revoke` |
| evaluate | `grant_management_evaluate` |

## Why this exists

PingFederate's plugin SDK has no extension point for adding a REST endpoint — that was
true, and it is why this started as a Go sidecar. But PF runs on Jetty and its
`PFWebAppProvider` deploys WARs out of `server/default/deploy`, making the WAR name the
context path. That is exactly how PF's own `pf-ws.war` serves `/pf-ws/rest/oauth/...`.

Being in-process removes every seam the sidecar has, and each of those seams produced a
real bug:

| Sidecar | Servlet |
|---|---|
| `gm-api-service` PCV + Basic auth to `/pf-ws/rest/oauth/...` | `AccessGrantManagerAccessor.getAccessGrantManager().getByGuid(id)` |
| `-insecure-skip-verify` for PF's self-signed cert | no network hop |
| unpicking consent from a JSON string in a grant attribute | `AccessGrant.getAuthorizationDetails()`, typed |
| `JWKS_URL` + `TOKEN_ISSUER`, which can disagree | `JwksEndpointKeyAccessor` — the server's own keys |

The issuer is not checked, deliberately: a token verified against this server's own
signing keys was necessarily issued by this server. The **audience** is checked, because
this server mints tokens for many audiences and one meant for a different API must not
be accepted here.

## Layout

| Class | Responsibility |
|---|---|
| `GrantsServlet` | HTTP. Routing, the bearer header, JSON, status codes, for all three operations. |
| `MetadataServlet` | §7.1 metadata, at a non-conformant path — see the gaps report. |
| `GrantEvaluator` | `authorise()` — the (client, AS, subject) rule every operation shares. Plus the §8.4.2 gates and the AuthZEN request. **No PF types** — plain code, unit tested. |
| `GrantView` | Reads a PF `AccessGrant` into plain data. Every PF-specific assumption lives here. |
| `PfTokenVerifier` | Verifies the token against PF's own signing keys. |
| `PdpClient` | AuthZEN 1.0 over HTTP. The one thing that stays remote, on purpose. |

`GrantView` exists for a specific reason: PF's `AccessGrant` is **not** a value object.
Constructing one reaches into the server's service locator and throws
`No Impl found for AccessGrantService` outside a running PF, so anything touching it
directly can only be tested inside the server. Isolating it keeps the decision logic
ordinary, and names the shape the sidecar and the servlet agree on.

## Build

The PF SDK is Ping-licensed and not on Maven Central, so it is copied out of a running
server. `lib/*.jar` is gitignored.

```bash
PF=gm-pingfederate
for j in pingfederate-sdk jose4j commons-logging commons-lang3 \
         jackson-core jackson-databind jackson-annotations; do
  src=$(docker exec $PF sh -c "find /opt/out/instance/server/default/lib /opt/out/instance/lib -iname '${j}*.jar' | head -1")
  docker cp "$PF:$src" lib/
done
docker cp $PF:/opt/out/instance/lib/jetty-servlet-api-4.0.9.jar lib/
chmod u+w lib/*.jar

# Install under local coordinates: the real jars carry POMs referencing parents that
# do not resolve offline.
mvn install:install-file -Dfile=lib/pingfederate-sdk.jar -DgroupId=local.pingfederate \
  -DartifactId=pingfederate-sdk -Dversion=13.0.3 -Dpackaging=jar -DgeneratePom=true
# ...likewise servlet-api (4.0.9), jose4j (1.x), commons-logging (1.x),
#    commons-lang3 (3.x), jackson-{core,databind,annotations} (2.x)

mvn test && mvn package     # -> target/gm-api.war
```

Every dependency is `provided`. **Bundle nothing**: PF isolates each deploy-dir artifact
on its own classloader, so a second copy of a PF class would not be the same class.
(`pf-rar-paz-plugin` shades Jackson for this reason — it needs Jackson but must not
collide with PF's.)

## Deploy

```bash
docker cp target/gm-api.war gm-pingfederate:/opt/out/instance/server/default/deploy/
docker restart gm-pingfederate
```

Configure via `web.xml` init-params (or env):

| Param | Env | Meaning |
|---|---|---|
| `pdpUrl` | `AUTHZEN_BASE_URL` | AuthZEN PDP base URL; `/access/v1/evaluation` is appended |
| `audience` | `GM_AUDIENCE` | The `aud` this API answers to. **Unset accepts any token this server signed** |
| `pdpToken` | `AUTHZEN_BEARER_TOKEN` | Credential for a protected PDP |
| `pdpTimeoutMs` | — | Default 10000 |

Confirm it started:

```
INFO: Grant Evaluation API ready; PDP at http://host.docker.internal:9099/access/v1/evaluation
Started ContextHandler{Grant Evaluation API,/gm-api,...,a=AVAILABLE}
```

`a=AVAILABLE` is the bit that matters. `a=UNAVAILABLE` means the context failed — check
`web.xml` parsed.

## Three things that will cost you an hour each

**`--` is illegal inside an XML comment.** A `web.xml` with one fails to parse, Jetty
logs `Unable to parse .../web.xml` and marks the context `UNAVAILABLE`, and the endpoint
404s. It looks exactly like a deployment problem.

**`getPathInfo()` has the servlet path already stripped.** Mapped at `/grants/*`, a
request to `/gm-api/grants/{id}/evaluate` yields pathInfo `/{id}/evaluate` — not
`/grants/{id}/evaluate`. Getting this wrong 404s every well-formed request. Pinned by
`PathTest`.

**PingFederate regenerates its signing keys on restart.** This container has no
persistent keystore, so every restart invalidates every previously issued token. A token
minted before a restart fails with `Unable to find a suitable verification key`, which
reads like a code bug and is not. Re-run the grant-creation flow (`scripts/authcode.py`,
in [`grant-evaluation-api`](https://github.com/dphhyland/grant-evaluation-api)) after restarting.

## Verify

The demo PDP and the grant-creation script are not in this repo — they ship with the Go
reference, [`grant-evaluation-api`](https://github.com/dphhyland/grant-evaluation-api).
Run the first two from a checkout of it; the API under test is the deployed servlet.

```bash
go run ./cmd/pdp -addr :9099 -expose-entitlements &   # AuthZEN PDP the servlet calls
python3 scripts/authcode.py <tpp-secret>              # fresh PF grant + token; prints the access token and its agid

# TOKEN and AGID come from authcode.py's output above:
curl -sk -X POST "https://localhost:9131/gm-api/grants/$AGID/evaluate" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
# {"decision":false,"context":{"reasons":[{"id":"subject_not_entitled",
#   "message":"You no longer have access to this account."}]}}
```

Against Alice's grant (consents to 111, 222, 444):

| Request | Result | |
|---|---|---|
| `111` read_balance | **Permit** | consent ✓ holds ✓ |
| `222` read_balance | **Deny** | consent ✓ **holds ✗** |
| `444` read_balance | **Permit** | consent ✓ view rights suffice |
| `444` read_transactions | **Deny** | consent ✓ **right ✗** |
| `999` read_balance | **Deny** | consent ✗ |

## Agents: delegation, not impersonation

An agent asking "may I touch Alice's account?" presents a token minted by RFC 8693
**token exchange**, carrying:

```json
{ "sub": "alice",                          // the principal, whose authority this is
  "act": { "sub": "urn:agent:concierge:v2" },  // the agent actually calling
  "client_id": "acme-budgeting",           // the agent OPERATOR, not the agent
  "agid": "..." }
```

Three identities, and conflating them is the whole failure mode. `sub` is the principal.
`act.sub` is the agent. `client_id` is the legal entity responsible for the agent. The
servlet reads all three and passes the actor to the PDP:

```json
"context": {
  "actor": { "delegated": true,
             "id": "urn:agent:concierge:v2",
             "chain": ["urn:agent:concierge:v2"],   // current actor first (RFC 8693 §4.1)
             "operator": "acme-budgeting" },
  "scopes": [...], "authorization_details": [...], "oauth": {...}
}
```

Effective access becomes a **three-way** intersection:

```
grant  ∩  subject entitlement  ∩  agent authority
```

The first two the PDP already decides. The third is what `actor` makes possible: policy
can now bound the agent by its registration and attestation — and an agent can only ever
be *narrowed* against Alice's grant, never widened past it.

**A token with `sub: alice` and no `act` is impersonation** — indistinguishable from
Alice acting herself, with the agent invisible. The servlet marks that
`delegated: false` rather than guessing, so policy can refuse it for an agent flow if it
chooses. It does not refuse it here: a real user acting directly looks exactly the same,
and only policy knows which is expected.

The actor is taken **only** from the signed token. A caller-supplied `context.actor` is
overwritten, or any client could claim to be any agent (`DelegationTest`).

### What is not wired yet

PingFederate must actually *mint* the delegated token — a token exchange processor policy
that nests `act`. That exists in `agentic-token-exchange-flatten` and
`idp-paz-authzen-adapter` but is not configured on this PF, so the live path here only
exercises `delegated: false`. The act-chain reading, nesting, cycle-safety and
propagation are covered by `DelegationTest`.

`may_act` — which controls *who may delegate* — is enforced at token exchange, upstream
of this API, not here.

## Relationship to the Go service

Both exist on purpose. This is the PingFederate artifact; `cmd/gm-api` is the
AS-agnostic reference implementation for the spec proposal, and is the only one that
demonstrates the extension is not Ping-specific. They agree on the AuthZEN request shape
and on the §8.4.2 gates, which is what makes them the same API rather than two APIs.

The consent path also mirrors the Go client: native `getAuthorizationDetails()` wins, and
the `authorization_details` grant attribute is the fallback for a PF with no
Authorization Detail Processor deployed. See `../deploy/pingfederate/README.md`.
