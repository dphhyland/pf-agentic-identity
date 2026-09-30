# The SSF receiver maps every subject it is sent, gets its own token and stream; the poll endpoint caps, records and waits

## Changelog

- The SSF receiver takes RFC 9493's `did`, `uri` and `aliases` subjects and SSF 1.0's complex subject (plan item
  H-SSF-1, finding F-0053, closed), and maps each to the user key or device its handlers act on: an `iss_sub` only when
  its `iss` is the SET's issuer, this PingFederate's `OIDF_SSF_ISSUER` or one in the new
  `OIDF_SSF_RECEIVER_SUBJECT_ISSUERS`; `aliases` by its first identifier in the order `iss_sub`, `email`, `account`,
  `phone_number`, `opaque`, `did`, `uri`; a complex subject by its `user` and `device` members. A subject that maps to
  no one is logged with the reason and counted (`ssf.receiver.subject_unmapped`), and nothing is acted on.
- A received SET carrying `exp` or `sub` is refused as `invalid_request`, the description naming the claim (SSF 1.0
  §4.1.7 and §4.1.2; finding F-0246, closed): a 400 on push, a `setErrs` entry on poll, counted as
  `ssf.receiver.set_refused`. The push endpoint's 400 now carries `Content-Language: en-US` (RFC 8935 §2.3).
- An event whose complex subject carries a member the transmitter declared critical and the receiver does not act on
  is accepted and discarded (SSF 1.0 §3.6), counted as `ssf.receiver.set_discarded`.
- The receiver's poll and stream calls get their token from the transmitter's authorization server by client
  credentials: `OIDF_SSF_RECEIVER_TOKEN_ENDPOINT`, `OIDF_SSF_RECEIVER_CLIENT_ID`, `OIDF_SSF_RECEIVER_CLIENT_SECRET`
  (`client_secret_basic`) or `OIDF_SSF_RECEIVER_CLIENT_KEY` (a private JWK, `private_key_jwt`), and
  `OIDF_SSF_RECEIVER_CLIENT_SCOPE`; the token is kept until shortly before it expires and fetched again after a 401.
  `OIDF_SSF_RECEIVER_POLL_TOKEN` is now development only.
- With `OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL` the receiver creates or finds its own stream at the
  transmitter at start-up and keeps its events (`OIDF_SSF_RECEIVER_EVENTS_REQUESTED`) and, for push
  (`OIDF_SSF_RECEIVER_PUSH_ENDPOINT_URL`), its delivery in step; a transmitter that refuses leaves `SSF_RECEIVER`
  `FAILED_DEPENDENCY`, retried by the supervisor, and a stream it created and cannot accept is deleted again.
- The poll endpoint caps `maxEvents` (`OIDF_SSF_POLL_MAX_EVENTS_CAP`, 100, 1-1000), records `setErrs` (logged,
  counted as `ssf.poll.set_error`, the SET released), returns nothing for a paused or disabled stream, and treats a
  poll whose `returnImmediately` is not `true` as a long poll, held for up to `OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS`
  (10, 0-30) off the request thread (plan item H-SSF-2, finding F-0054, closed). PingFederate's own filters do not
  allow async requests, so inside PingFederate the poll is answered at once (finding F-0360).
- New event catalogues `ssf-receiver` and `ssf-poll` in servlets/ssf.

## Before you deploy

1. **Give the SSF receiver a client for its poll token.** What to do: where the receiver polls a transmitter
   (`OIDF_SSF_RECEIVER_POLL_URL`) or manages its stream, register a client for it at the transmitter's authorization
   server with the client credentials grant and the scope the transmitter asks for, and set
   `OIDF_SSF_RECEIVER_TOKEN_ENDPOINT`, `OIDF_SSF_RECEIVER_CLIENT_ID`, one of `OIDF_SSF_RECEIVER_CLIENT_SECRET` or
   `OIDF_SSF_RECEIVER_CLIENT_KEY` (a private JWK; both may be given as a `_FILE`), and `OIDF_SSF_RECEIVER_CLIENT_SCOPE`;
   then unset `OIDF_SSF_RECEIVER_POLL_TOKEN`. Why: a static token never expires or rotates, and the receiver has no
   way to replace it when the transmitter stops taking it, so it is now classed forbidden in production. What now
   happens: in production, `OIDF_SSF_RECEIVER_POLL_TOKEN` set refuses `SSF_RECEIVER` (its endpoint answers 503 and
   the start-up audit names the setting); the static token and a client set together are refused in every profile, as
   is a client with neither or both of a secret and a key. How to tell: the start-up audit lists "SSF_RECEIVER
   REFUSED" with `OIDF_SSF_RECEIVER_POLL_TOKEN`. Development-profile escape: with `OIDF_DEPLOYMENT_PROFILE=development`
   the static token is still used, with the start-up audit's "not refused (development)" line.
2. **Received SETs with `exp` or `sub` are refused.** What to do: if a transmitter you receive from puts `exp` or the
   JWT `sub` claim in its SETs, have it stop (SSF 1.0 §4.1.7: "The "exp" claim MUST NOT be used in SETs"; §4.1.2:
   "The JWT "sub" claim MUST NOT be present in any SET containing an SSF event") - the subject belongs in `sub_id`.
   Why: both keep a SET from being taken for another kind of JWT (SSF 1.0 §4.1.3), and a SET that breaks them is not
   one a conforming transmitter sends. What now happens: the push is answered 400 `invalid_request` with a
   description naming the claim, a polled SET is reported in `setErrs`, nothing is acted on, and
   `oidf_events_total{code="ssf.receiver.set_refused"}` rises. How to tell: server.log's WARN "inbound SET rejected
   (invalid_request): the SET carries the "exp" claim". There is no development-profile escape: the refusal does not
   depend on the profile, and a transmitter that sends these claims is fixed at the transmitter.
3. **Long polling holds a request up to the wait you set.** What to do: check what your receivers send to
   `/ssf/poll`. A poll that leaves out `returnImmediately` or sends `false` is now a long poll (RFC 8936 §2.2: "The
   default value is "false", which indicates the request is to be treated as an HTTP long poll"): with nothing to
   return it is held for up to `OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS` (10 by default, 0-30) and answered when a SET
   arrives. Set a receiver's HTTP read timeout above the wait, or set the wait to 0 to answer every poll at once. Why:
   before 0.6.0 an absent `returnImmediately` was read as `true`. How to tell: a poll of an empty stream takes about
   the wait. Inside PingFederate 13.1.3 the wait is not reached: PingFederate's runtime filters do not allow async
   requests, so the poll is answered at once and server.log says "SSF long polling is unavailable here" once
   (finding F-0360). Also: `maxEvents` above `OIDF_SSF_POLL_MAX_EVENTS_CAP` (100) now returns the cap and
   `moreAvailable: true`, and a paused or disabled stream answers `{"sets": {}}`. Development-profile escape: none
   needed; `OIDF_SSF_POLL_LONG_POLL_WAIT_SECONDS=0` restores answering at once in any profile.
4. **Name the issuers whose `iss_sub` subjects are your users.** What to do: if a transmitter sends `iss_sub`
   subjects whose `iss` is an identity provider rather than the transmitter itself (a PingOne environment, say), list
   those issuers in `OIDF_SSF_RECEIVER_SUBJECT_ISSUERS`, comma-separated. Why: a `sub` is unique only within its
   issuer (RFC 7519 §4.1.2), and until 0.6.0 the receiver acted on an `iss_sub`'s `sub` whatever its `iss`, so a
   SET about another issuer's user who shared the value revoked this one's grants. What now happens: an `iss_sub`
   from any issuer but the SET's own, this PingFederate's `OIDF_SSF_ISSUER` and the ones listed maps to no one; no
   grant or instance is touched. How to tell: server.log's WARN "revocation signal ... names no user here: the iss_sub
   subject's iss '...' is neither the SET's issuer nor this PingFederate's", and
   `oidf_events_total{code="ssf.receiver.subject_unmapped"}` rises. Development-profile escape: none; the list is the
   escape, in any profile.

## Notes

- Verified 2026-09-30 on the rig (slot 4, `pfai-p3-hssf1`, PingFederate 13.1.3 on Java 21.0.12, development profile,
  the branch at `c2360195`): `openid-ssf-transmitter-test-plan` plan `sZoXwU7pXFdZu` 19 of 19
  PASSED, and `openid-ssf-transmitter-caep-test-plan` plan `U7kyNRApD03H1` 13 of 13 PASSED, against the suite
  release-v5.3.1 of `suite/suite-compose.yml`. The suite's polls never reached an empty long poll.
- The receiver end to end, on the same rig with receiver settings added for the check: its `private_key_jwt`
  assertion for `conformance-ssf-receiver` was accepted by PingFederate's token endpoint; `SSF_RECEIVER` was
  `FAILED_DEPENDENCY` while PingFederate was not yet listening ("HTTP connect timed out") and the supervisor ran it
  again about 4 s later, when it created its poll stream and went `READY`; three events raised by
  `suite/trigger-caep-events.py` were polled, verified against PingFederate's JWKS and acted on ("revoked 0 grant(s)
  for 'example.user@example.com'"). A SET with `exp` pushed to `/ssf/receiver/events` was answered 400 with
  `content-language: en-US` and the claim named. The check ran with
  `-Djdk.internal.httpclient.disableHostnameVerification=true`, because the rig's certificate names only localhost
  and PingFederate takes an assertion only for its own base URL (finding F-0362). The managed push stream and finding
  a stream again after a restart were not run against a live transmitter (U-0370).
- Long polling on PingFederate: `req.isAsyncSupported()` is false for `/ssf/poll` - pf-runtime.war maps nineteen
  filters, none `async-supported` - so a poll of an empty stream was answered in 0.21 s (F-0360). The async path is
  tested in `SsfLongPollTest` (released by a new SET, by the wait, by the container's timeout).
- The `exp`/`sub` refusal is the receiver's (`SsfReceiverService`), not libs/shared-signals' `SetVerifier`, which
  keeps RFC 8417's reading for its other users.
- setErrs releases the SET with no record kept of it (F-0361, S-10). The poll client's acknowledgements and the
  receiver's dedup window stay per node (F-0043, S10e).
- The token and stream clients use `java.net.http` with a 10 s connect and request timeout until S-5d moves them onto
  platform.http (wave 6).
- `mvn verify` of servlets/ssf passed on JDK 20 and 17 (486 tests, the 100% METHOD gate with the new methods in it)
  and the tests on JDK 21.0.12 (`maven:3-eclipse-temurin-21`); `EventsCataloguedTest` passed with the two new
  catalogues.
