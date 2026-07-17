# Examples

Working code for calling the Grant Evaluation API. Every one of these has been run
against a real PingFederate — the output below is copied from actual runs, not written by
hand.

Start with the guide: [`docs/INTEGRATING.md`](../docs/INTEGRATING.md).

| | What | Run it |
|---|---|---|
| [`curl/`](curl) | Every operation, end to end, in shell | `CLIENT_SECRET=… ./curl/walkthrough.sh` |
| [`go/gmclient/`](go/gmclient) | A Go client to copy into your project | `cd go && go test ./...` |
| [`go/cmd/tpp/`](go/cmd/tpp) | A TPP checking a standing consent (Open Banking) | `cd go && go run ./cmd/tpp -secret … -grant …` |
| [`java/`](java) | Single-file Java client, JDK-only | `java java/GrantManagementClient.java --secret … --grant …` |

## What they all demonstrate

The same five questions against Alice's grant, which consents to accounts **111, 222 and
444** for reading. It is a perfectly valid, unexpired grant.

```
111 read_balance    PERMIT | consent_covers_request     | Access is covered by your consent.
222 read_balance    DENY   | subject_not_entitled       | You no longer have access to this account.
444 read_balance    PERMIT | consent_covers_request     | Access is covered by your consent.
444 read_transact   DENY   | entitlement_lacks_right    | Your own access to this account does not allow this.
999 read_balance    DENY   | resource_not_consented     | You have not shared this account.
```

The middle two are the point. Alice closed 222 and is only a view-only signatory on 444.
**The grant says yes; the answer is no.** A token introspection cannot see either — the
grant is valid and names both accounts.

## The one thing to get right in your integration

Branch on `reasons[0].id`, and split it two ways:

```go
if !decision.Permitted {
    if decision.Retryable() {
        return sendUserThroughConsentAgain()   // a consent problem: they can fix it
    }
    return giveUp(decision.Message())          // an entitlement problem: they cannot
}
```

`subject_not_entitled` and `entitlement_lacks_right` mean the user **does not hold the
access**. Re-consenting cannot conjure it. Sending them through an authorization flow
wastes their time and returns the same denial. Everything else is a consent problem they
can fix.

And separately: **a 503 is not a denial.** It means the PDP or grant store could not be
reached — the question was never asked. Both clients surface that as an error, never as
`decision: false`. Turning "I could not ask" into "no" is indistinguishable to your
caller from a real policy decision.

## Prerequisites

The curl, Go and Java examples need a running PingFederate with the servlet deployed, and
a PDP:

```bash
go run ./cmd/pdp -addr :9099 -expose-entitlements &   # the demo PDP
# PingFederate + the servlet: see deploy/pingfederate/README.md
```

The client secret is in `deploy/pingfederate/terraform/terraform.tfvars` (gitignored).

**No setup at all?** The hosted demo needs nothing:

```bash
curl -X POST https://demo-production-0792.up.railway.app/api/grants/grant-alice-accounts/evaluate \
  -H 'Content-Type: application/json' \
  -d '{"action":{"name":"read_balance"},"resource":{"type":"account","id":"222"}}'
```

## Gotchas that will cost you time

**PingFederate regenerates its signing keys on restart.** The demo container has no
persistent keystore, so every restart invalidates every token ever issued. A `401
invalid_token` right after a restart is not your bug — get a fresh token.

**Do not request the `openid` scope** against the demo PF: no OIDC policy is configured
and the authorization request dies with `server_error`.

**Scopes must be on your client's registration.** Asking for one you are not registered
for fails at PF's token endpoint with `invalid_scope`, before this API is involved.
