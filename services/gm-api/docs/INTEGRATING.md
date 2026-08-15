# Integrating the Grant Evaluation API

How another project calls this to ask **"does this consent still permit this, right now?"**

Runnable examples: [`examples/`](../examples). Start with
`examples/curl/walkthrough.sh` (in the **grant-evaluation-api** repo since the Go extraction).

---

## 1. What question this answers

You hold a grant — an OAuth consent a user gave your client. Later, you want to act on
it. A token introspection tells you the token is valid. It does **not** tell you whether
the consent still covers what you are about to do.

```
POST {gm}/grants/{grantId}/evaluate
{"action": {"name": "read_balance"}, "resource": {"type": "account", "id": "222"}}

→ {"decision": false,
   "context": {"reasons": [{"id": "subject_not_entitled",
                            "message": "You no longer have access to this account."}]}}
```

Alice's grant is valid, unexpired, and explicitly names account 222. She closed it last
week. **The grant says yes. The answer is no.**

Effective access is an intersection:

```
what the client was granted  ∩  what the subject holds  ∩  agent authority (if any)
scopes + RFC 9396 RAR           entitlement                act chain
asserted by the AS              looked up by the PDP       from the token
```

The API answers the first two always, the third when an agent is involved.

---

## 2. Which endpoint to call

Two deployments, same contract. Pick by which AS you are in front of.

| | Base URL | Use when |
|---|---|---|
| **PF servlet** | `https://<pf-runtime>/gm-api` | You are on PingFederate. In-process, nothing to run. |
| **Go sidecar** ([`grant-evaluation-api`](https://github.com/dphhyland/grant-evaluation-api)) | `http://<host>:8088/api/v1` | Any AS, or you cannot deploy into the AS. |

> The Go sidecar currently **requires a token subject**, so it cannot serve the
> `client_credentials` shape in §3.2. If you are a TPP with a standing consent and no user
> token, use the servlet. See [`pingfederate-gm-api-gaps.md`](pingfederate-gm-api-gaps.md).

Both need an [AuthZEN 1.0 PDP](#6-the-pdp) behind them.

---

## 3. Getting a token

Three caller shapes. The grant is a relationship between **client, AS and subject** —
your client leg is what authorises the question, so in every shape you authenticate as
the grant's client.

### 3.1 User present (authorization code)

The ordinary case. The token carries `sub` and, on PingFederate, `agid` — the grant's id.

```
sub:       alice
client_id: acme-budgeting
agid:      B8yAsHppNMWQlrUBVwpoZoZo7W0JzHi4     ← the grant to name in the URL
scope:     accounts.read grant_management_evaluate
```

`agid` is how you learn your own grant id without being told out of band. It is
PingFederate's claim name, configured on the access token manager as *Access Grant GUID
Claim Name*. (The spec puts `grant_id` on the token *response*; PF does not — see the gaps
doc.)

### 3.2 No user present (client credentials) — Open Data / Open Banking

You are a TPP holding a long-lived consent. You want to know whether it still covers an
account **before** spending a refresh token. There is no user and no user token.

```bash
curl -sk -X POST https://pf:9031/as/token.oauth2 \
  -d grant_type=client_credentials \
  --data-urlencode 'scope=grant_management_evaluate' \
  -u "$CLIENT_ID:$CLIENT_SECRET"
```

This token has **no `sub` at all**. That is fine: the subject comes off the grant
(spec §8.4.1). You supply the grant id yourself — persist it from the original
authorization.

**Servlet only.** See the note in §2.

### 3.3 An agent acting for a user (delegation)

The agent presents a token from RFC 8693 token exchange:

```json
{ "sub": "alice",
  "act": { "sub": "urn:agent:concierge:v2" },
  "client_id": "acme-budgeting" }
```

Three identities, and conflating them is the whole failure mode:

| Claim | Who |
|---|---|
| `sub` | the **principal** — whose authority is being exercised |
| `act.sub` | the **agent** — what is actually calling |
| `client_id` | the **agent operator** — the registered client, accountable for the agent |

`sub: alice` with **no** `act` is *impersonation*: indistinguishable from Alice herself,
agent invisible. Use delegation. The API surfaces the actor to the PDP so policy can bound
the agent by its registration; it never lets an agent widen what Alice granted.

> PF must be configured to mint these (a token exchange processor policy that nests
> `act`). Not configured on the demo PF.

---

## 4. The API

All three operations need the grant's client to be **your** client. Each needs exactly its
own scope — a client registered only to evaluate cannot thereby read or revoke.

### Evaluate — `POST {gm}/grants/{grantId}/evaluate`

Scope: `grant_management_evaluate`

```json
{
  "action":   { "name": "read_balance", "properties": { "amount": 500 } },
  "resource": { "type": "account", "id": "111" },
  "context":  { "anything": "you like" }
}
```

`action.properties` and `context` are optional and passed to the PDP. **The subject is
never in the body** — it comes from the grant. Anything you put in `context` that collides
with the grant's own constraints (`scopes`, `authorization_details`, `oauth`, `actor`) is
overwritten; you cannot widen your own consent by asking nicely.

```json
{
  "decision": false,
  "context": { "reasons": [ { "id": "resource_not_consented",
                              "message": "You have not shared this account." } ] },
  "trace":   { "step": "Denied by the authorization server. The PDP was not consulted." }
}
```

`trace` appears only when the AS refused before reaching the PDP. Treat it as
diagnostic — do not depend on it.

### Query — `GET {gm}/grants/{grantId}`

Scope: `grant_management_query`

```json
{ "scopes": [ { "scope": "accounts.read" } ],
  "authorization_details": [ { "type": "account_information",
                               "actions": ["read_balance", "read_transactions"],
                               "locations": ["111", "222", "444"] } ] }
```

The spec's `claims` array is omitted: PingFederate's grant model has no claims, so there
is nothing to populate it from.

### Revoke — `DELETE {gm}/grants/{grantId}`

Scope: `grant_management_revoke` → `204 No Content`.

Revocation bites on the **next evaluation** — no token needs to expire first:

```
DELETE /grants/{id}          → 204
POST   /grants/{id}/evaluate → {"decision": false, "reasons": [{"id": "grant_not_found"}]}
```

### Metadata — `GET {gm}/.well-known/grant-management-configuration`

⚠️ **Non-standard location.** §7.1 puts these fields in the AS's own metadata, which
PingFederate generates and no plugin can extend. Do not build discovery on this. It is
inspectable, not conformant.

---

## 5. Reading the answer

Branch on `reasons[0].id`, never on the message text — messages are for humans and will
change.

| `id` | Meaning | Your move |
|---|---|---|
| `consent_covers_request` | permitted | proceed |
| `resource_not_consented` | this resource is not in the consent | re-consent for it |
| `action_not_consented` | consent does not cover this action | re-consent |
| `missing_scope` | the grant lacks the scope | re-consent |
| `no_consent_for_resource_type` | no consent of the governing type | re-consent |
| `subject_not_entitled` | **the user no longer holds this resource** | do not retry; consent cannot fix this |
| `entitlement_lacks_right` | the user holds it, but not this far | do not retry |
| `amount_exceeds_consented_limit` | over a contextual cap | retry smaller |
| `grant_expired` / `grant_not_found` | the grant is gone | re-authorize |
| `unauthorized` | not your grant | you have the wrong grant id |
| `insufficient_scope` | your token lacks the operation's scope | fix your token |

The two that matter are `subject_not_entitled` and `entitlement_lacks_right`. **Re-consent
will not help** — the user cannot consent to what they do not have. Anything else is a
consent problem you can ask the user to fix.

### HTTP status vs decision

A **refusal is a 200 carrying `"decision": false`** — including `insufficient_scope` on
evaluate. Non-200s are transport-level:

| Status | Meaning |
|---|---|
| `400` | malformed body |
| `401` | token invalid, expired, or not signed by this AS |
| `403` | on **query/revoke** only: scope or ownership |
| `404` | bad path |
| `503` | **the PDP or grant store could not be reached** |

**A 503 is not a denial.** It means the question could not be asked. Do not treat it as
"no" — retry, or fail closed in your own code, deliberately.

---

## 6. The PDP

The API decides nothing about policy. It checks the grant is real, yours and unexpired,
then asks an **AuthZEN 1.0** PDP:

```
POST {pdp}/access/v1/evaluation
{ "subject":  {"type": "user", "id": "alice"},
  "action":   {"name": "read_balance"},
  "resource": {"type": "account", "id": "111"},
  "context":  { "oauth": {"client_id": "...", "grant_id": "..."},
                "scopes": ["accounts.read"],
                "authorization_details": [...],
                "actor": {"delegated": false, "operator": "acme-budgeting"} } }
```

The grant's constraints ride in `context`. That is what lets a general-purpose PDP decide
against one specific consent.

Any conformant PDP works — point `AUTHZEN_BASE_URL` (Go) or the `pdpUrl` init-param
(servlet) at it:

| PDP | Notes |
|---|---|
| `cmd/pdp` (in [`grant-evaluation-api`](https://github.com/dphhyland/grant-evaluation-api)) | zero dependencies, YAML policy. For demos. |
| **PingAuthorize** | via its AuthZEN facade. The real one. Needs `AUTH_TYPE=oauth`. |
| Topaz / OPA | untested here, but the wire format is the standard |

The PDP needs an **entitlement source** — what the subject actually holds, independent of
any grant. `cmd/pdp` reads `policy/entitlements.yaml`; a real one reads PingDirectory or
core banking. A PDP that cannot reach it **denies**; it does not fall back to trusting the
grant.

---

## 7. Try it now

Nothing to install:

```bash
# The hosted demo — two panels, consent vs entitlement, live decisions
open https://demo-production-0792.up.railway.app

curl -X POST https://demo-production-0792.up.railway.app/api/grants/grant-alice-accounts/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
# → "You no longer have access to this account."
```

Locally, against a real PingFederate: `examples/curl/walkthrough.sh` (in the **grant-evaluation-api** repo since the Go extraction).

---

## 8. Client libraries

| | |
|---|---|
| `examples/go/` (grant-evaluation-api repo) | A `Client` you can copy into a Go project |
| [`examples/java/`](../examples/java) | The same, no dependencies beyond the JDK |
| `examples/curl/` (grant-evaluation-api repo) | Every operation as a shell script |

Each covers all three token shapes and shows the retry/no-retry split on reason ids.

---

## 9. Gotchas

**PingFederate regenerates its signing keys on restart.** No persistent keystore in the
demo container, so every restart invalidates every issued token. `401 invalid_token` after
a restart is not your bug — get a fresh token.

**Do not request `openid`** against the demo PF: no OIDC policy is configured, and the
authorization request fails with `server_error`.

**`grant_management_*` scopes must be on your client's registration.** Requesting one you
are not registered for gives `invalid_scope` at the token endpoint, not at ours.

**The consent on the demo PF is currently pinned in Terraform**, not chosen by Alice —
`pf-rar-paz-plugin` replaces that once its PDP is configured. Everything downstream is
real; the consent's provenance is not yet.
