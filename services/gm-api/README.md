# idp-gm-api — AuthZEN Grant Evaluation API

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Formerly a standalone local repo, absorbed with history. Absorbed with history 2026-07-21; see [docs/PROVENANCE.md](https://github.com/dphhyland/pf-agentic-identity/blob/main/docs/PROVENANCE.md).


An implementation of the proposed **Grant Evaluation API** extension to the OpenID
Foundation's [Grant Management API](https://openid.net/specs/oauth-v2-grant-management-1_0.html):
a client can ask whether an existing grant still permits an action, right now,
without running a new authorization flow.

The idea in one line: **effective access is what the client was granted intersected
with what the subject actually holds** — and answering that needs a PDP, because
neither half alone is enough.

```
      what the client was granted              what the subject holds
      scopes + RFC 9396 RAR                    entitlement
      ─────────────────────────                ──────────────────────
      asserted by the AS in the                looked up by the PDP from
      AuthZEN request context                  the system of record
                    │                                    │
                    └──────────────┬─────────────────────┘
                                   ▼
                          effective access
```

That asymmetry is deliberate. The GM API asserts the **grant**, because it owns the
grant. It does not assert the **entitlement**, because it is not the authority on
what a subject holds — if it were, a grant could simply claim authority the user
never had. So the PDP looks entitlement up itself, from whoever does own it.

This is what a token introspection cannot tell you. A grant can be valid, unexpired,
correctly scoped, and still worthless: Alice consented to share an account she has
since closed, or consented to move money from a business account she only has view
rights over. The grant says yes. The answer is no.

```
  client                 GM API (this repo)              AuthZEN PDP
    │                          │                              │
    │  POST /grants/{id}/      │                              │
    │       evaluate           │                              │
    ├─────────────────────────►│                              │
    │                          │ 1. validate bearer token     │
    │                          │ 2. fetch grant (PingFederate)│
    │                          │ 3. grant active? unexpired?  │
    │                          │                              │
    │                          │  POST /access/v1/evaluation  │
    │                          │  subject + action + resource │
    │                          │  context = the grant's       │
    │                          │            scopes + RAR      │
    │                          ├─────────────────────────────►│
    │                          │                              │ decide against
    │                          │◄─────────────────────────────┤ the consent
    │  {decision, reasons}     │  {decision, reason_user,     │
    │◄─────────────────────────┤             reason_admin}    │
```

The subject is never taken from the request body — it comes from the grant and the
bearer token. That is what makes the answer trustworthy.

## Using it from another project

**Start here:** [`docs/INTEGRATING.md`](docs/INTEGRATING.md) — the integration guide.
Working, tested clients in [`examples/`](examples): curl, Go, Java.

```bash
CLIENT_SECRET=… ./examples/curl/walkthrough.sh    # every operation, end to end
```

Or with nothing installed at all:

```bash
curl -X POST https://demo-production-0792.up.railway.app/api/grants/grant-alice-accounts/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
# → "You no longer have access to this account."
```

## What's here

| Path | What it is |
|---|---|
| `docs/INTEGRATING.md` | **How to call this from your project** |
| `docs/pingfederate-gm-api-gaps.md` | What PingFederate does and does not support, and why |
| `examples/` | Runnable clients: curl, Go, Java |
| `servlet/` | The API as a PingFederate servlet (query, revoke, evaluate, metadata) + MCP tools for agents |
| `docs/MCP.md` | The MCP add-on: an AI agent asking before it acts |
| `api/` | The Grant Evaluation API: `POST /grants/{id}/evaluate`, plus grant CRUD |
| `authzen/` | AuthZEN 1.0 PDP client (discovery, evaluation, search) |
| `middleware/` | Bearer token validation (JWKS), scopes, rate limiting, CSRF |
| `pingfederate/grant/` | Client for PingFederate's Persistent Grant Management API |
| `pdp/` | A small AuthZEN 1.0 PDP: decides grant ∩ entitlement |
| `policy/openbanking.yaml` | The demo policy |
| `policy/entitlements.yaml` | Demo stand-in for the system of record |
| `cmd/gm-api/` | The real service — needs PingFederate + a PDP |
| `cmd/pdp/` | The demo PDP — standalone |
| `cmd/demo/` | Self-contained walkthrough UI — needs only the PDP |
| `docs/` | The draft spec extension |

## Which parts talk to PingFederate

Worth being blunt about, because the two commands differ:

| | Grants come from | Entitlements come from | Needs PingFederate |
|---|---|---|---|
| `cmd/gm-api` | PingFederate's Persistent Grant Management API | the PDP's `EntitlementSource` | **yes** |
| `cmd/demo` | in-memory fixtures | the PDP's `EntitlementSource` | no |

Both paths work end to end. `cmd/gm-api` has been driven against a real PingFederate
13.0.3 evaluating a real persistent grant that a real user consented to — see
[deploy/pingfederate](deploy/pingfederate/README.md) for the instance, its Terraform,
and the authorization code flow that creates the grant.

`cmd/demo` exists so the protocol stays demonstrable without a PF to hand. Everything
downstream of it — the AuthZEN request shape, the PDP, the policy, the entitlement
lookup — is exactly what `cmd/gm-api` drives.

## Try it in 30 seconds

No PingFederate needed. The demo holds its consents in memory and drives the real
PDP over real AuthZEN.

```bash
go run ./cmd/pdp  -addr :9090 -expose-entitlements &
go run ./cmd/demo -addr :8081 -pdp http://localhost:9090
# open http://localhost:8081
```

The UI shows both halves side by side. Alice's consent names accounts `111`, `222`
and `444` for reading — and it is a perfectly valid grant. What she *holds* is
another matter: she closed `222`, and she is only a view-only signatory on the
business account `444`.

**Where the grant and the entitlement disagree** — the cases a token check misses:

| Try | You get | Because |
|---|---|---|
| `111` · `read_balance` | **Permit** | Consent ✓ and she holds it ✓ |
| `222` · `read_balance` | **Deny** — "You no longer have access" | Consent ✓ but she holds nothing ✗ — she closed it after consenting |
| `444` · `read_balance` | **Permit** | Consent ✓ and view rights are enough ✓ |
| `444` · `read_transactions` | **Deny** — "Your own access does not allow this" | Consent ✓ but her rights stop short ✗ |
| Payment of `5000` | **Deny** — "above your agreed limit" | A contextual limit carried by policy |

**Where the grant alone decides:**

| Try | You get | Because |
|---|---|---|
| `999` · `read_balance` | **Deny** — "You have not shared this account" | Consent is per-resource, not per-scope |
| `333` · `read_balance` | **Deny** — "You have not shared this account" | She *does* hold `333`. The client is told only that it wasn't granted it — see the ordering note below |
| `initiate_payment` on the read-only consent | **Deny** — "You have not consented to this type of access" | Scope gate |
| Bob's expired consent | **Deny** — the PDP is never called | An expired grant carries no authority (§8.4.2) |
| Carol's revoked consent | **Deny** | Revocation bites on the next evaluation; no token need expire |

Expand *Show the AuthZEN exchange* in the UI to see the exact request and response.

### The order of the gates is a privacy decision

The grant is checked **first**, and only inside that envelope is entitlement
consulted. Account `333` above is the case that shows why: Alice holds it, but the
client wasn't granted it, so the client learns only "not shared" and nothing about
her holdings. Checking entitlement first would turn this endpoint into an oracle
for enumerating a subject's accounts, which §9 forbids.

Within the consent envelope the client *does* learn whether the subject still holds
the access. That isn't a leak — it's the question it asked, and the reason the
endpoint exists.

## The PDP

`cmd/pdp` serves AuthZEN 1.0:

```
GET  /.well-known/authzen-configuration
POST /access/v1/evaluation
POST /access/v1/evaluations      # batch
GET  /health
```

```bash
curl -X POST localhost:9090/access/v1/evaluation -H 'Content-Type: application/json' -d '{
  "subject":  {"type":"user","id":"alice"},
  "action":   {"name":"read_balance"},
  "resource": {"type":"account","id":"999"},
  "context": {
    "oauth":  {"client_id":"acme-budgeting","grant_id":"g-1"},
    "scopes": ["accounts.read"],
    "authorization_details": [
      {"type":"account_information","actions":["read_balance"],"locations":["111","222"]}
    ]
  }
}'
```

```json
{
  "decision": false,
  "context": {
    "id": "resource_not_consented",
    "reason_admin": {"en": "resource account/999 is not named by any of [locations data.accounts] in the \"account_information\" consent on grant g-1"},
    "reason_user":  {"en": "You have not shared this account."}
  }
}
```

The two reason halves are load-bearing, not decoration. `reason_admin` may name
internal policy detail and **never** leaves the GM API; `reason_user` is the only
part forwarded to the client. This is §8.4.3 of the draft, enforced in code by
`authzen.EvaluationResponseContext.UserReasons()`.

Because it speaks plain AuthZEN, this PDP is swappable for PingAuthorize, Topaz, or
OPA without touching the GM API.

### Entitlements

`policy/entitlements.yaml` stands in for the bank's system of record — in a real
deployment, PingDirectory or the core banking platform. It is the authority the
grant gets intersected with:

```yaml
subjects:
  alice:
    account:
      "111": [read_balance, read_transactions, initiate_payment]
      # 222 is absent on purpose: Alice consented to share it, then closed it.
      "444": [read_balance]        # view-only signatory on the business account
```

Swap it for a real source by implementing `pdp.EntitlementSource` — two methods,
and only `RightsOn` is load-bearing:

```go
type EntitlementSource interface {
    RightsOn(ctx context.Context, subject, resourceType, resourceID string) (rights []string, held bool, err error)
    Holdings(ctx context.Context, subject string) HoldingsByType  // demo display only
}
```

`held` and `rights` are deliberately distinct: holding nothing is *"you have no
access to this account"*, while holding the resource without the right is *"your
access does not go that far"*. Two different denials, two different reasons.

A PDP that cannot reach its entitlement source **denies** — it does not fall back
to trusting the grant. `NewEngine(policy, nil)` uses `NoEntitlements{}`, which holds
nothing and therefore permits nothing.

> The PDP's `GET /debug/entitlements/{subject}` endpoint exists only so the demo UI
> can show this half. It lets anyone enumerate a subject's holdings, it is not part
> of AuthZEN, and it is off unless `PDP_EXPOSE_ENTITLEMENTS=true`. Never enable it
> in production.

### Policy

`policy/openbanking.yaml` is deliberately small. It does **not** encode who may do
what — the grant and the entitlement already say that between them. It only maps a
resource type onto the `authorization_details` type that governs it, and prices each
action in scope:

```yaml
resources:
  account:
    authorization_details_type: account_information
    id_paths: [locations, data.accounts]   # where consented ids live

actions:
  read_balance:
    requires_scope: accounts.read
  initiate_payment:
    requires_scope: payments.write
    max_amount: 1000
```

The engine is default-deny: every path out of `Evaluate` that isn't an explicit
permit is a denial carrying a reason.

## Running the real GM API

`cmd/gm-api` is the service that belongs in front of PingFederate.

```bash
cp .env.example .env    # fill in PingFederate + PDP details
go run ./cmd/gm-api
```

| Variable | Why it matters |
|---|---|
| `GM_PINGFEDERATE_URL`, `PINGFED_ADMIN_USER/PASS` | Reaching the Persistent Grant Management API |
| `JWKS_URL` | Validating inbound access tokens |
| `TOKEN_ISSUER` | Expected `iss`. **Unset means the `iss` claim is not checked** |
| `AUTHZEN_BASE_URL` | The PDP. Discovery is attempted first, then standard paths |
| `SUBJECT_CLAIM_NAME` | Claim used as the subject (default `sub`) |
| `GRANT_USER_KEY_CLAIM` | Claim matched against the grant's `userKey` to prove ownership |
| `SKIP_JWT_VALIDATION` | Local only. Disables signature checking — never deploy with this on |

Scopes, per §6.7.1:

| Endpoint | Scope |
|---|---|
| `GET /grants`, `GET /grants/{id}` | `grant_management_query` |
| `PUT /grants/{id}` | `grant_management_update` |
| `DELETE /grants/{id}` | `grant_management_revoke` |
| `POST /grants/{id}/evaluate` | `grant_management_evaluate` |

### PingFederate

`deploy/pingfederate/` carries the supporting configuration, and
`deploy/pingdirectory/` the LDIF for the grant store. Change PingFederate config
declaratively with the `pingidentity/pingfederate` Terraform provider rather than
through the admin console, so the deployed state stays reproducible.

## Deploying

Two Railway services build from this repo, selected by `RAILWAY_DOCKERFILE_PATH`:

| Service | Dockerfile | Needs |
|---|---|---|
| `pdp` | `Dockerfile.pdp` | nothing |
| `demo` | `Dockerfile.demo` | `AUTHZEN_BASE_URL` → the PDP |
| (the real API) | `Dockerfile` | PingFederate + a PDP |

The demo reaches the PDP over Railway's private network
(`http://pdp.railway.internal:9090`), so evaluation traffic never crosses the
public internet.

**The demo PDP has no authentication.** That is fine for a demo over invented
consents, and not fine for anything else. Put the PDP behind the GM API's OAuth
client credentials (`AUTH_TYPE=oauth`) before it decides anything real.

## Tests

```bash
go test ./... -race
```

`pdp/engine_test.go` is the useful read: each test is one demo scenario, including
that a denial explains itself to the user without leaking grant internals.

## Status

Implemented: evaluation, search mode, grant state checks, scope + RAR consent
checks, subject entitlement intersection, reason propagation, AuthZEN discovery,
the PDP and its policy.

Not yet:

- The `authorization-evaluation` response header and
  `authorization_enquiry_supported` protected-resource metadata from §5 of the draft.
- Delegation via `act` claims. §8.4.1 is marked TBC upstream, and it is the piece
  that matters most for agentic access: today the PDP intersects the grant with the
  entitlement of *one* subject. Delegation makes that a chain — the actor's own
  authority bounds the principal's, and the same "cannot grant what you do not hold"
  rule has to hold at every hop.
- Pairwise subject identifiers. `SUBJECT_CLAIM_NAME` selects the claim, but a
  pairwise `sub` will not match a system-of-record key without a resolution step.
- Client registration as a third bound. Effective access is really
  `client_allowed ∩ grant ∩ entitlement`; the first term (what the client may ever
  request, per its PF registration) is not checked here, because PF enforces it at
  grant time. It would matter if a client's permitted scopes were narrowed *after*
  grants were issued against them.
