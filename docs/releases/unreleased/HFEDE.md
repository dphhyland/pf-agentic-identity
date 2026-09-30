# Refusals to callers that have not authenticated are generic with a reference, the FAPI resource-server rules are per client, and our audit writes no longer blank PingFederate's own audit line

## Changelog

- Every refusal written to a caller that has not authenticated - the attestation, registration and FAPI filters in
  front of the token, PAR, CIBA, device, introspection and revocation endpoints, the authorization endpoint's error
  page, `/federation/register`, the federation endpoints (`/federation/fetch`, `/list`, `/resolve` and the rest) and a
  hosted entity's published configuration - now carries the error code's fixed description and a correlation id,
  `"error_description": "Client authentication failed (reference oidf-1a2b3c4d)"`, and nothing the request or a peer
  chose (plan item H-FED-4, F-0046). The detail - a trust chain's messages, a claim the attestation carried, the URL the
  request named, what to configure - is on one `server.log` line with the same reference. An operator authenticated
  by `OperatorAuthenticator` still gets the detail.
- `FapiResourceServerFilter` (UserInfo) holds only the clients `OIDF_FAPI2_CLIENTS` names, as `Fapi2ProfileFilter`
  does, and those a new setting, `OIDF_FAPI_RESOURCE_CLIENTS`, adds - FAPI 1.0 clients such as FAPI-CIBA's, which the
  FAPI 2.0 token-endpoint rules would refuse - and finds an access token in the query whatever the spelling of the parameter's name - `access%5Ftoken`,
  `Access_Token`, repeated (H-FED-6, F-0048). Until now it refused a query token and set `x-fapi-interaction-id` for
  every client, and read the query as written.
- `OAuthErrorDescriptionFilter` holds a response only when its status is an error when the body starts; a token
  response goes straight through, unbuffered. A `sendError` or `reset` after it started holding an error is followed:
  what was held is dropped (H-FED-6, F-0048).
- Our audit records no longer empty PingFederate's own audit line (H-FED-7, F-0049). On PingFederate 13.1.3
  `LoggingUtil.cleanup()` removes every audit column on the thread, so an event we wrote from inside PingFederate's
  own request - an OGNL issuance criterion at the token endpoint - left PingFederate's line for that request with no
  event, subject, IP address, client, protocol or host. The writer now copies the thread's audit context, writes, and
  puts it back exactly. Our record no longer picks up PingFederate's client and role as its own either.
- A new event, `fapi.request.refused`, in a new `fapi` catalogue: each refusal of either FAPI filter, with the filter,
  the rule, the client as its subject and the endpoint, written to `server.log` and PingFederate's audit log (protocol
  `FAPI`) and counted in `oidf_events_total` (plan item O-2).

## Before you deploy

1. **Error responses to unauthenticated callers are generic now.** What a client sees: the same HTTP status, `error`
   code and headers as before, and an `error_description` that is the code's fixed text followed by
   `(reference <id>)`; the authorization endpoint's error page shows the fixed text and the reference where it showed
   the reason. The reference is `oidf-` and eight hex digits: on PingFederate 13.1.3 its tracking id is not yet on the
   thread when our filters and servlets run, so it is never PingFederate's own tracking id (F-0395). Why: the old
   descriptions carried peer-controlled text - trust chain messages, claims, URLs - and configuration advice to anyone
   who asked. How to tell: a client or test that matched on our `error_description` text now fails; one that matches on
   `error` and the status does not. What to change: match on `error`; to find why a request was refused, search
   `server.log` for `ref=<id>` - the line is from `com.pingidentity.ps.oidf.servlet.oauth.PublicErrors` (the OAuth
   filters and the error page) or `com.pingidentity.ps.oidf.servlet.trustanchor.FederationErrors` (the federation
   endpoints and registration), at INFO for a refusal and WARN or ERROR for a failure of ours, so keep those loggers
   at INFO. An operator page named by `OIDF_FEDERATION_ERROR_PAGE` gets the fixed text in `${errorDescription}` and
   the reference in `${trackingId}`. There is no development escape: the detail is in the log in every profile.
2. **The FAPI resource-server rules apply only to FAPI clients.** What to do: nothing, if `OIDF_FAPI2_CLIENTS` already
   lists your FAPI clients or is `*` and you have no FAPI 1.0 clients; list any FAPI 1.0 clients (FAPI-CIBA's, for
   example) in the new `OIDF_FAPI_RESOURCE_CLIENTS`, space- or comma-separated. Why: FAPI 1.0 Baseline section 6.2.1 and FAPI 2.0 section 5.3.4 are rules for FAPI
   endpoints, and PingFederate's UserInfo serves every client. How to tell: with both lists unset, UserInfo
   no longer sets `x-fapi-interaction-id` and no longer refuses `?access_token=` - PingFederate answers as it does on
   its own - and the start-up line from `FapiResourceServerFilter` says the rules are off; with a list, a listed
   client's query token is refused 400 `invalid_request` and recorded as `fapi.request.refused`. The client is the
   `client_id` of a JWT access token; a reference (opaque) access token names no client, so its query token is refused
   only under `*`. What to change: to keep the old behaviour for every client, set `OIDF_FAPI_RESOURCE_CLIENTS=*`,
   which touches UserInfo only (`OIDF_FAPI2_CLIENTS=*` would also hold every client to the FAPI 2.0 assertion-audience
   and DPoP-algorithm rules at the token endpoint). A list of nothing (a comma alone) in either holds every client at
   UserInfo, with a warning. The conformance rig's `vars.env` now lists its FAPI-CIBA clients there. No development
   escape: this is not a profile rule.

## Notes

- F-0049, checked on the rig on 2026-10-01 (PingFederate 13.1.3, a client-credentials token request with an OGNL
  issuance criterion that wrote one of our events mid-request): at 6815222e PingFederate's `success` audit line for
  the request had empty event, subject, ip, connectionid, protocol and host columns and a response time of 0; with
  this change it had all of them. `javap` on pf-protocolengine 13.1.3.0: `AuditLogger.cleanup` removes every key of
  `AuditLogger.MDC_KEY`. `LoggingUtilAuditWriterTest` pins the save and restore through the SDK's `LoggingUtil`.
- H-FED-4 on the same rig with the federation profile (2026-10-01): nine requests carrying a random marker - in a
  subject, an issuer, a trust anchor, a content type, a `client_id`, a redirect URI and a request object - to
  `/federation/fetch`, `/resolve`, `/list`, `/register`, PAR, the token and the authorization endpoints; no response
  carried it, and each of the seven this module answered had a reference whose `server.log` line held the detail. No
  `server.log` line from our filters or servlets carried PingFederate's `tid:` (F-0395).
- H-FED-6 on the rig: `?access%5Ftoken=` with a token naming `conformance-fapi2-client1` was 400 with
  `x-fapi-interaction-id` and a `fapi.request.refused` audit line; the SSF emitter's real token in `?access_token=`
  went on to PingFederate (its own 403) with no `x-fapi-interaction-id`; an RS256 DPoP proof from a FAPI client at
  the token endpoint was 400 `invalid_dpop_proof` and a second audit line. No conformance plan was re-run for this
  change.
- The authorization endpoint's error page for an attestation-required client's details sent without PAR now shows
  the fixed text of `invalid_request`, not "use a pushed authorization request"; the log line keeps the instruction.
