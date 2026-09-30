# The details a token carries, held to the attestation ceiling

From 0.6.0 two checks hold what PingFederate issues to an attested client to the `authorization_details` its client
attestation carries (plan item S4d, [F-0032](../findings/F-0032.yaml)): an issuance criterion on your access-token
mappings, which sees the details before the token is made, and a response belt on the token endpoint, which reads them
in the token response. The criterion also sends a bare refresh of a payment or account grant back to be decided again
([F-0105](../findings/F-0105.yaml)).

Why both. The ceiling used to be checked only against the token request's own `authorization_details` parameter, but
the code, CIBA and device grants issue the details stored earlier - at PAR, at `/as/bc-auth.ciba`, at the device
endpoint - and a refresh issues the grant's. Since 0.6.0 ClientAttestationAuth holds the details where they are stored
([S4D1's release note](../releases/unreleased/S4D1.md)); these two hold what is actually issued, whatever path it took.
CAS §7.1 asks exactly that of the authorization server: it "MUST, when authenticating a client via an attestation
containing authorization_details, ensure that any authority granted in issued tokens is a subset of the attestation's
authorization_details".

## The issuance criterion

Add this expression to the issuance criteria of **every access-token mapping an attested client can get a token
through** - in PingFederate's admin console, *Applications > OAuth > Access Token Mappings*, the mapping, *Issuance
Criteria*, an expression; in the admin API or Terraform, an `expressionCriteria` entry with an error result of your
choosing:

```
@com.pingidentity.ps.oidf.servlet.clientregistration.utils.IssuedDetailsCriterion@withinCeiling(#this)
```

The `@class@method` form is OGNL's static call. Written `IssuedDetailsCriterion.withinCeiling(#this)` it fails in
PingFederate 13.1.3 with "source is null for getProperty(null, "pingidentity")" and the criterion refuses every token
(seen on the rig, 2026-09-30). That usually means the `Default` mapping (code, CIBA, device and refresh grants) and the
`Client Credentials` mapping, and any mapping for a token-exchange processor. PingFederate expressions must be
enabled, as they already are for `ClientAttestationUtils.validateClientAttestation`.

PingFederate hands the criterion `context.OAuthAuthorizationDetails`: one map per detail the token will carry - the
request's on the client-credentials grant, what was stored on the code, CIBA and device grants, the grant's on a refresh
without the parameter and the narrower ones on a refresh with it (driven on the rig with PingFederate 13.1.3,
2026-09-30, [U-0018](../findings/U-0018.yaml)). It also asks the mapping's criteria when the authorization endpoint
resumes a code flow, where no attestation is ever sent.

| The request | The criterion answers |
|---|---|
| Its attestation was verified - by ClientAttestationAuth, or by the criterion itself when no filter did - and every detail about to be issued is within a ceiling entry of its type, each constrained field present and within (the model's strict `contains`) | `true` |
| The same, and a detail is not within, a field the ceiling constrains is missing, or the model cannot read a detail | `false` |
| An attestation with no `authorization_details`, and details about to be issued | `false`: nothing is within an empty ceiling, as at the token gate |
| No attestation, at the token endpoint, for a client that may authenticate without one | `true`: the criterion does not invent a ceiling |
| No attestation, at the token endpoint, for a client with `attestation_required=true` (or one whose property cannot be read, or whose policy PingFederate cannot give now) | `false` |
| No attestation, where the authorization endpoint resumes | `true`: the token request that follows is decided at the token endpoint |
| A refresh that sends no `authorization_details`, of a grant holding a detail whose type is in `OIDF_ATTESTATION_REDECIDE_ON_REFRESH_TYPES` | `false`, for every client, attested or not (below) |
| `ATTESTATION_AUTH` failed or refused by the production profile | `false` for every token |
| `ATTESTATION_AUTH` switched off (`OIDF_ATTESTATION_AUTH_ENABLED=false`) | `false` for a request carrying an attestation, which nothing then verifies; `true` otherwise |

A `false` makes PingFederate refuse the token with the criterion's error result: at the token endpoint, 400
`invalid_grant` with the error result as its description; at the authorization endpoint, a redirect with
`error=access_denied`. The criterion cannot choose the error code - RFC 9396 §6's `invalid_authorization_details` is
the belt's. It never throws: anything unexpected is logged and answered `false`.

It runs on PingFederate's engine classloader, whose statics are its own. It learns whether `ATTESTATION_AUTH` is serving
from the component's switch and the production profile's refusals, which it reads from the process's environment once,
and it loads the containment models on its first call ([docs/development/classloaders.md](../development/classloaders.md)).

## A refresh that must repeat its `authorization_details`

PingFederate reissues a bare refresh's stored details without calling the RAR processor's `enrich`, so the PDP is not
asked again: a policy change after issuance is not seen until the grant ends (F-0105; the stub PDP on the rig received
nothing for a bare refresh and one request for a refresh that repeated its details, 2026-09-30). RFC 9396 §7 leaves the
bare refresh to the authorization server: "If the client does not specify the authorization_details token request
parameters, the AS determines the resulting authorization_details at its discretion."

`OIDF_ATTESTATION_REDECIDE_ON_REFRESH_TYPES` (words, default `payment_initiation,account_information`,
[its catalogue entry](../configuration/attestation-token-endpoint.md)) names the types whose refresh is sent back: a
refresh without `authorization_details` of a grant holding one of them is refused by the criterion, so the client asks
again with its details and PingFederate calls `enrich`, and the PDP, again. The refresh token is not revoked - a
refresh that repeats the details is served. Set it blank to send no refresh back. Only mappings that carry the
criterion apply it.

## The response belt

`IssuedDetailsBelt` is mapped over `/as/token.oauth2` just before ClientAttestationAuth
([build/pingfederate/filters.xml](../../build/pingfederate/filters.xml)); nothing needs configuring. For a request whose
attestation ClientAttestationAuth verified, it holds the token response until the `authorization_details` in it -
RFC 9396 §7: "the AS MUST also return the authorization_details as granted by the resource owner and assigned to the
respective access token" - are known to be within the attestation's, by the same check as the criterion.

- Within, or no details in the response: the response leaves byte for byte.
- Not within, or not readable: the client gets 400 `invalid_authorization_details` with "the issued
  authorization_details exceed what the client attestation allows", RFC 9396 §6's code ("the AS refuses the request
  with the error code invalid_authorization_details (similar to invalid_scope)"). The grant behind the response's
  refresh token is revoked through the SDK's `AccessGrantManager` (`getByRefreshToken`, then `revokeGrant`; the rig
  logged "the refused token's grant ... was revoked", 2026-09-30).
- A success body over 64 KiB cannot be checked: the client gets 500 `server_error`, and the event is counted with
  reason `too_large`.
- An error, a body that is not JSON, and one with a `Content-Encoding` go out as they came. PingFederate 13.1.3
  compresses no token response: `Accept-Encoding` gzip, br, deflate or `*` over HTTP/2 and HTTP/1.1 got plain JSON with
  its plain length on the rig ([U-0029](../findings/U-0029.yaml), 2026-09-30).
- A request without `OAuth-Client-Attestation` or its PoP passes untouched and unbuffered. One whose attestation the
  filter did not verify writes straight through.

**Residual risk.** PingFederate has made the access token by the time the belt reads the response, and has no seam to
revoke a JWT access token; `PfInternals` has none, and the SDK's `AccessTokenRevocable` is for token managers that
store their tokens. A refused JWT access token stays valid until it expires, but the client never receives it, and its
grant is revoked. And RFC 9396 §7 lets an authorization server leave values out of the response ("The AS MAY omit
values in the authorization_details to the client"), which the belt cannot see past; PingFederate 13.1.3 did not on the
rig. Both are why the criterion is the control and the belt its fallback for a mapping without it.

## Events

Each refusal is `attestation.issued.refused` in pf-integration's `attestation` catalogue, audited, with the client as
its subject, the reason as its failure (`exceeds_ceiling`, `uncheckable`, `too_large`, `redecide_on_refresh` or
`attestation_required`), `enforcer` (`response_belt` or `issuance_criterion`) and `detail_types` - at most eight types,
never a value. For example, from the rig on 2026-09-30:

```
event=attestation.issued.refused outcome=failure reason=exceeds_ceiling subject=s4d3-attested enforcer=response_belt detail_types=sales_agent
event=attestation.issued.refused outcome=failure reason=redecide_on_refresh subject=s4d3-attested enforcer=issuance_criterion detail_types=payment_initiation
```

## On the rig

Slot 2 (pfai-p3-s4d3, PingFederate 13.1.3), 2026-09-30, a client whose attestation ceiling was `sales_agent` [EMEA,
AMER] up to 500 and `payment_initiation` EUR 100.00: a code grant pushed under that ceiling and redeemed, with no
details, under a narrower one ([EMEA] up to 100) was 400 `invalid_authorization_details` from the belt with the
criterion off, and 400 `invalid_grant` from the criterion with it on; the same within the ceiling was issued; CIBA the
same, redeemed under the narrower ceiling, was 400 from the belt; the device and client-credentials grants within the
ceiling were issued; a client-credentials request with no attestation was issued what it asked for; a CIBA payment
grant for EUR 42.00 refreshed without `authorization_details` was refused, and refreshed with them was issued after the
PDP was asked again.
