# Explicit registration bounded like automatic registration

## Changelog

- `POST /federation/register` (OpenID Federation 1.0 §12.2) runs through the same `RegistrationCoordinator` as
  automatic registration: one registration of a client at a time, waiting up to `OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS`
  for another to finish, and at most `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS` resolved at once. A request
  that gets neither is answered 503 `temporarily_unavailable` with `Retry-After: 2`. The servlet has its own pool, as
  each automatic-registration filter has (plan item S5c; F-0010 stays open for S5d).
- Every registration - explicit, and automatic at the token, authorization and PAR endpoints - spends one
  `ResolutionBudget` of its own, handed to the validator on `ValidationRequest.budget` and to
  `TrustMarkValidator.validate(chain, budget)`, so its chain, peer chain and Trust Marks share it. The budget has the
  `federation-resolution` settings' requests (`OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS`) and their wall clock
  (`OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS`) or what is left of the registration's deadline, a new setting
  `OIDF_REGISTRATION_DEADLINE_SECONDS` (25 s, 2 to 300), whichever is shorter. The deadline runs from when the
  request asks to register, so the wait for the client's lock comes off it. This closes the registration half of
  F-0280: the resolve endpoint's `FederationService` and `ClientAttestationUtils` still validate the chain and its
  marks on two budgets.
- A budget that runs out is a federation that could not be answered in time: `Kind.TRANSPORT`, 503
  `temporarily_unavailable`, remembered for the 15 s transport backoff. Before this, S5B's `invalid_trust_chain` made
  it a trust failure: 401 `invalid_client` at the token endpoint, remembered for 60 s. A required Trust Mark the
  budget left unchecked is refused the same way, not as a mark the entity lacks (400 `invalid_client_metadata`).
- The failure memory is keyed on the SHA-256 of the whole chain an attempt started from - every statement in order,
  each with its length, and for an explicit registration the posted Entity Configuration, the statements of its
  `trust_chain` header and its `peer_trust_chain` - with the client id. It was keyed on the first statement alone,
  so a caller who varied the rest of a chain got a fresh resolution each time. Explicit registration now consults
  and fills it: the same failed chain posted again within its backoff is answered with the same refusal and resolves
  nothing. A success clears the client's remembered failures. At most 32 are kept per client.
- `POST /federation/register` reads at most `OIDF_REGISTRATION_MAX_BODY_BYTES` of a body (65536, 4096 to 524288). A
  body whose `Content-Length` is larger is refused before any of it is read, and one found larger at the cap -
  chunked, or understated - is refused with no more of it read: 413 `invalid_request`. It used to read the whole body,
  however large.
- A `trust-chain+json` body whose statement is not a JWT is answered 400 `invalid_request`; it was a 500 with a stack
  trace at ERROR (F-0317, found on the rig).
- A lock wait that is not shorter than the deadline stops `/federation/register` and both automatic-registration
  filters starting, naming both settings.

## Before you deploy

1. **Explicit registration is now rate-limited like automatic registration.** `POST /federation/register` used to
   validate every posted chain at once, however many arrived for one client or in all. It is now held to
   `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS` (8) registrations resolved at once and one registration of a
   client at a time, a second waiting up to `OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS` (2000 ms) - the settings that bound
   automatic registration, applied to the servlet's own pool. An RP that registers while the pool is full, or while
   another registration of it is still running past the lock wait, now gets HTTP 503 with
   `{"error": "temporarily_unavailable"}` and `Retry-After: 2`, where it used to be served. The answer is 503 rather
   than 429 because OpenID Federation 1.0 §12.2.4 says "For a client registration error, the response is as defined
   in Section 8.9", and §8.9 defines `temporarily_unavailable` as "currently unable to handle the request due to
   temporary overloading or maintenance. The HTTP response status code SHOULD be 503 (Service Unavailable)"; 429 is
   not among its codes. To tell, look for 503s from `/federation/register` in the access log, or the WARN
   "Federation endpoint temporarily unavailable: status=503 error=temporarily_unavailable" with "too many federation
   registrations" or "still in progress" in it. If RPs register in bursts, raise
   `OIDF_AUTO_REGISTRATION_MAX_CONCURRENT_RESOLUTIONS`; RPs should retry after the `Retry-After`. There is no
   development-profile escape: the bound is what stops a stranger's posted chains taking every request thread
   (§18.1), and the setting is the way to widen it.
2. **A registration request body is capped.** `POST /federation/register` now reads at most
   `OIDF_REGISTRATION_MAX_BODY_BYTES` bytes, 65536 (64 KiB) by default, 4096 to 524288, and answers a larger body 413
   `invalid_request` - "the registration request is larger than 65536 bytes, the most this endpoint reads" - without
   reading the rest. PingFederate's own `pf.runtime.http.maxRequestBodySize` (200000 bytes) did not bound this body:
   its jetty-runtime.xml gives it to the web app as `maxFormContentSize`, a limit on form parameters, and this body
   is read as a stream. A posted Entity Configuration is a few kilobytes; one whose `trust_chain` or
   `peer_trust_chain` header carries many statements, or a large `trust-chain+json` body, can be larger. To tell,
   look for 413s from `/federation/register`, or measure the requests your RPs post. Raise the setting if they need
   more. A value outside the range is refused on the first registration request, which is answered 500 until it is
   fixed. There is no development-profile escape: the cap is a bound on what an unauthenticated request can make
   the server hold, and the setting is the way to change it.
3. **Every registration now ends by a 25-second deadline.** A registration's chain resolution used to have the
   `OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS` budget, 45 s by default, after however long it waited for the
   client's lock. It now has that or what is left of `OIDF_REGISTRATION_DEADLINE_SECONDS` (25 s by default, 2 to 300)
   after the wait, whichever is shorter, so a registration answers within the deadline plus its PDP decision and
   store writes. The default sits under PingFederate's `pf.runtime.http.idleTimeout`, 30000 ms in run.properties;
   PingFederate has no other request deadline we could find. A federation that needs longer than 25 s to resolve is
   now refused where it used to register. To tell, look for "ran out of time: its wall-clock budget of ... ms" with a
   figure under 25000 in the WARN from `com.pingidentity.ps.oidf.federation.TrustChainValidator`. Raise the deadline,
   and `pf.runtime.http.idleTimeout` and any proxy's timeout above it, if your federations need it. The deadline must
   be longer than `OIDF_AUTO_REGISTRATION_LOCK_WAIT_MS`; if it is not, `/federation/register` and both automatic
   registration filters do not start, and the reason names both. There is no development-profile escape: it is a
   range, and the setting is the way out.
4. **A registration whose budget runs out is now a 503, not a refusal of the client.** With S5B's budget alone, a
   registration that ran out of time or requests was refused `invalid_trust_chain`: 400 at `/federation/register`,
   401 `invalid_client` at the token endpoint, and remembered for 60 s. It is now 503 `temporarily_unavailable` with
   `Retry-After: 15` at `/federation/register`, the PAR endpoint and the token endpoint, the authorization endpoint's
   error page says so, a due renewal is deferred while the registration still stands, and the failure is remembered
   for 15 s. So is a registration refused because a required Trust Mark could not be checked before the budget ran
   out, which used to be a 400 `invalid_client_metadata` naming the mark. Anything that treats a 503 from these
   endpoints as fatal, or alerts on it, should treat it as a slow federation. To tell, look for the audit event
   `federation.registration.refused` with reason `temporarily_unavailable`. There is no development-profile escape:
   this is the outcome a slow federation has always been meant to get.
5. **A failed explicit registration is answered from memory for up to 60 seconds.** The same chain posted again for
   the same client within 60 s of a refusal (15 s after an unreachable federation or a budget that ran out) now gets
   the same refusal without being resolved again. An RP whose registration failed because of something outside its
   request - a superior's statement not yet published, say - and that posts the same request again at once gets the
   old answer until the backoff passes; any change to the posted statement or its headers is a new attempt. A
   successful registration of the client clears its remembered failures. To tell, the audit event
   `federation.registration.refused` is recorded for the first refusal and not for the repeats, which are answered at
   once. RPs should retry after the backoff.
   There is no development-profile escape: resolving the same failing chain for every request is the work §18.1
   warns a stranger can cause.

## Notes

**The failure memory's new key** (plan item S5c). A failed registration attempt is remembered under its client id
and the lowercase hex SHA-256 of its chain: the kind of attempt (`explicit`, or `presented` for an automatic one's
chain), then the number of statements and each statement as its UTF-8 length, a colon and its bytes, in order, then
the same for the peer chain. Discovery, with no chain presented, has the key `discovery`. Two attempts share a key
only when they present the same statements in the same order, so a caller who varies any statement - not only the
first - makes a new attempt, and each one is remembered. The chains that validated are kept under the same key for
60 s. Each registration component (the servlet and the two filters) keeps its own memory and pool.

**What the budget does not cover.** A PDP decision (`OIDF_PDP_REQUEST_TIMEOUT_MS`, 3000), an RP's `jwks_uri` or
`signed_jwks_uri` fetch at the front channel (the outbound client's 15 s) and the client store writes run after the
resolution and are not part of its budget, so a registration can outlast its deadline by those.

**Tests.** The pf-integration suite ran on JDK 20.0.2 and 17.0.11 (727 tests, the method coverage gate included), and
the registration test classes (199 tests, among them RegistrationBudgetTest's slow peers over loopback HTTP for the
explicit, token and front-channel paths) on Temurin 21.0.12 in maven:3-eclipse-temurin-21, on 2026-09-30.

**The rig** (2026-09-30, slot 5, `PF_PROFILE=federation`, PingFederate 13.1.3, the image built from this branch at
6dcdf420 and again at 3f97372d). A 300 KB `trust-chain+json` body to `/federation/register` was answered 413 in 25 ms,
with a `Content-Length` and again chunked; a 300 KB form to `/as/token.oauth2` and `/as/par.oauth2` was answered 400
"Unable to parse form content" by PingFederate's own limit, and a 150 KB one reached this module's filters (U-0326).
The same unresolvable chain posted three times was resolved once: one `federation.registration.refused` event, the
repeats answered 503 with `Retry-After: 15` in about 10 ms. A body `["a.b.c"]` was a 500 at 6dcdf420 (F-0317) and a
400 at 3f97372d. No conformance plan was re-run: the suite's federation plans register automatically, which this
package changes only in its failure memory's key and its budget.
