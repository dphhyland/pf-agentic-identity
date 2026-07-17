# The Grant Management MCP server

An add-on to the PingFederate servlet: the same Grant Management operations, exposed as
[MCP](https://modelcontextprotocol.io) tools so an **AI agent can ask before it acts**.

```
POST https://<pf-runtime>/gm-api/mcp        JSON-RPC 2.0 over MCP Streamable HTTP
```

It ships in the same `gm-api.war` as the REST surface and is registered in the same
`web.xml`. No separate process, no separate deploy.

## Why an agent wants this

An agent acting on a user's behalf holds a token. The token being valid does not mean the
user's consent still covers what the agent is about to do — the user may have closed the
account, or never held the access they consented to share. The agent should **ask first**:

```
evaluate_grant(grant_id, resource_type="account", resource_id="222", action="read_balance")

→ { "permitted": false,
    "reason": "subject_not_entitled",
    "explanation": "You no longer have access to this account.",
    "guidance": "DENIED, and asking the user to consent again will NOT help: they do not
                 hold this access themselves, or the grant is gone. Do not retry and do
                 not start a consent flow. Tell the user what happened and stop.",
    "consent_would_help": false }
```

`guidance` and `consent_would_help` are the point. A model reads them and knows the
difference between *"ask the user to re-consent"* and *"stop, this cannot be fixed"* —
the retryable split, turned into an instruction. Without it, a model faced with a denial
either gives up on a problem the user could fix, or loops the user through pointless
consent flows for one they cannot.

## The tools

| Tool | Does | Scope on the agent's token |
|---|---|---|
| `evaluate_grant` | may I do this, on this resource, right now? | `grant_management_evaluate` |
| `describe_grant` | what did the user consent to? | `grant_management_query` |

**Revoke is deliberately not exposed.** Ending a user's consent is irreversible, and is
not a decision an agent should reach through a tool call. The REST surface has it, for
software with a human behind it.

## The one thing that makes this safe: whose token

**The MCP server holds no credential of its own.** Every call is authenticated with the
bearer token on the MCP request — the agent's own.

This is not a detail; it is the whole design. The tempting alternative — give the MCP
server a client credential, let the agent pass a `grant_id` — is a **confused deputy**:

- the agent could interrogate any grant the server can reach, not just its own;
- the `act` chain that identifies the agent would never be checked;
- the agent would be invisible to policy, which is exactly the failure the delegation
  model exists to prevent.

So the agent brings a **delegated token** and gets a decision bounded by it, or it brings
no token and gets a 401. Verified live:

```
no Authorization header        → HTTP 401
another client's valid token   → {"permitted": false, "reason": "unauthorized"}
```

The token flows into the same `GrantOperations` the REST surface uses, so every rule holds
identically: the client leg authorises, the subject comes off the grant, and — when the
token carries an `act` chain — the agent is surfaced to the PDP as `context.actor` so
policy can bound it by its registration.

## Connecting an agent

The transport is MCP Streamable HTTP. Any MCP client that supports a bearer token works;
point it at `/gm-api/mcp` and supply the agent's access token.

```jsonc
// initialize
{"jsonrpc":"2.0","id":1,"method":"initialize",
 "params":{"protocolVersion":"2025-06-18","capabilities":{}}}

// tools/list  → evaluate_grant, describe_grant

// tools/call
{"jsonrpc":"2.0","id":3,"method":"tools/call",
 "params":{"name":"evaluate_grant",
           "arguments":{"grant_id":"<agid>","resource_type":"account",
                        "resource_id":"222","action":"read_balance"}}}
```

The `grant_id` is the `agid` claim in the agent's own token — the agent names its own
grant without being told the id out of band.

## Where this is, and is not, finished

**Finished:** the tools, the token model, the guidance, and the shared authorisation. All
verified against a real PingFederate.

**Not yet:** PingFederate is not configured to mint **delegated** tokens (a token exchange
processor policy that nests `act`). So today the tokens reaching this server carry no
`act`, and every call runs the non-delegated path — `context.actor.delegated` is `false`.
The act-chain reading and its propagation to the PDP are covered by unit tests
(`DelegationTest`), and the code is ready; the AS configuration is the missing piece. Until
it lands, this demonstrates the shape of agentic grant evaluation, not a live agent
delegation.

That gap is called out here rather than papered over, for the same reason the pinned
consent in `grant-mapping.tf` is: a demo that looks more finished than it is misleads.

## Try it

```bash
go run ./cmd/pdp -addr :9099 -expose-entitlements &
python3 scripts/authcode.py <tpp-secret>          # a token + grant

TOKEN=$(cat .../alice_token); GRANT=$(cat .../alice_grant_id)
curl -sk -X POST https://localhost:9131/gm-api/mcp \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{
        \"name\":\"evaluate_grant\",
        \"arguments\":{\"grant_id\":\"$GRANT\",\"resource_type\":\"account\",
                       \"resource_id\":\"222\",\"action\":\"read_balance\"}}}"
```
