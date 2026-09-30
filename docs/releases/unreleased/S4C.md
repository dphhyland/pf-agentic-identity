# One attestation policy for the token-endpoint filter and the OGNL criterion

## Changelog

- `AttestationPolicyResolver` builds each client's attestation policy for both the token-endpoint filter and the
  OGNL criterion: the server's, tightened by the client's `attestation_*` extended properties. The filter used to
  ignore the properties altogether (F-0009); the criterion read them loosely, so a bad value fell back to the
  default and a large one loosened the policy. Each property is now parsed strictly and can only tighten: a proof
  age or clock skew can only shrink, an algorithm list can only narrow, `attestation_challenge_required` can only
  turn the challenge on, `attestation_required_claims` only adds, and `attestation_expected_htu` can only pin one of
  the token endpoint URLs this server answers at. A value that does not parse or would loosen refuses the client
  with 401 `invalid_client`. The policy is kept 30 s per client; a client manager that cannot answer is 503
  `temporarily_unavailable` (plan item S4c).
- The filter resolves the client from the attestation's `sub` before verifying it, and refuses a verified `sub` that
  is another client. It publishes the SHA-256 of the policy it verified under, and the criterion, reusing that
  verification, refuses a context verified under another policy.
- `attestation_required=true` is enforced: a token request for such a client without `OAuth-Client-Attestation` is
  refused by the filter (401 `invalid_client`) instead of going on to PingFederate's own client authentication.
- A start-up scan, then every 10 minutes, reads every client's properties and lists the clients it would refuse, by
  client id and property, as a `DEGRADED` part of `ATTESTATION_AUTH` (`AttestationPolicyScan`) in the health detail.
- A token exchange's `subject_token` that verifies as one PingFederate signed (its signing keys, its issuer, an `exp`
  not passed, a `typ` of none, `JWT` or `at+jwt`) is published as `verified_subject_token_sub` in the attestation
  context, and only then does `delegationActChain` nest its `act`. The RAR plugin takes a token exchange's principal
  from that member alone (F-0074).
- The filter and the criterion emit `attestation.client.verified` and `attestation.client.refused` for every
  decision, and `attestation.policy.invalid` - in pf-integration's new `attestation` event catalogue - for each
  refused property, all counted in `oidf_events_total` (plan item O-2).

## Before you deploy

1. **Per-client attestation properties now apply at the token endpoint.** Until 0.6.0 a client's `attestation_*`
   extended properties were read only by the OGNL criterion, so a client authenticated by the token-endpoint filter
   was held to none of them, and neither was it held to `OIDF_ATTESTATION_REQUIRED_CLAIMS`. From 0.6.0 the filter
   applies both: a client with, say, `attestation_dpop_max_age=30` or `attestation_required_claims=workload` whose
   proofs or attestations do not meet them is refused with 401 `invalid_client`. Why: a property an administrator set
   is the client's policy, and it has to hold on the route that authenticates the client. What to change: read each
   attestation client's properties in the admin console (Applications > OAuth > Clients > the client > Extended
   Properties) and remove any it does not meet; check the attesters send the claims `OIDF_ATTESTATION_REQUIRED_CLAIMS`
   names. Deploy the new pf-integration jar to both `pf-runtime.war` and `server/default/deploy/` together: the
   criterion refuses a verification the filter published without the policy fingerprint, which an older filter jar
   does not publish. How to tell: `attestation.client.refused` events with `endpoint` `token_endpoint_filter`, and
   the filter's log line naming the check that failed. There is no development-profile escape: the properties are the
   client's own configuration, and removing one is the way to stop applying it.
2. **A per-client property can only tighten the server's policy.** Until 0.6.0 a property that did not parse was
   ignored with a warning, `attestation_challenge_required` other than `true` read as `false`, and a value could
   loosen the policy: `attestation_pop_max_age=3600`, `0` (no limit at all) or `attestation_clock_skew=600`. From 0.6.0
   such a value refuses the client with 401 `invalid_client` ("the client's attestation policy is not valid") and an
   `attestation.policy.invalid` event naming the client and the property, never the value. The limits: proof ages
   whole seconds from 1 to 300, clock skew from 0 to 60, algorithm lists that share at least one algorithm with the
   server's, an `attestation_expected_htu` that is the token endpoint's URL as PingFederate advertises it or the
   issuer followed by `/as/token.oauth2`, and `true` or `false` for the two booleans. Why: a client's property is
   there to hold that client tighter, never looser, than every other. How to tell before the first refused request:
   after start-up, the health detail (`/agentic-identity/health`) lists the refused clients as the `ATTESTATION_AUTH` part
   `AttestationPolicyScan`, `DEGRADED`, with each client's id and property, and server.log names each one ("attestation
   policy: attestation_dpop_max_age on client ... would loosen the server's 300 s"). What to change: correct or remove
   the property. A property that holds more than one value is refused too: the old reader took the first value and
   split it on commas, so a client whose `attestation_accepted_algs`, `attestation_pop_algs`, `attestation_dpop_algs`
   or `attestation_required_claims` was stored as several values (pf-oidf-modules declares them multi-valued) is now
   refused until the list is written as one comma-separated value. Development-profile escape: `yes`, `no`, `on`,
   `off`, `1`, `0` and `true` or `false` in another case are read for the booleans, and a value with spaces around it
   is read trimmed, each with a warning naming the strict spelling; production refuses them, and every other rule
   holds in both profiles.
3. **`attestation_required` is enforced.** A federation client whose metadata asks for `attest_jwt_client_auth` is
   written with `attestation_required=true`, and an administrator can set it on any client. Until 0.6.0 nothing read
   it: a token request for such a client with no attestation went on to PingFederate's own client authentication.
   From 0.6.0 the token-endpoint filter refuses it with 401 `invalid_client` ("this client authenticates with a client
   attestation"), whether the client is named by `client_id`, HTTP Basic or a `client_assertion`. Why: a client that
   registered to authenticate by attestation must not authenticate any other way. What to change: a client that
   still needs another method sets `attestation_required=false` or drops the property. How to tell:
   `attestation.client.refused` events for the client with `endpoint` `token_endpoint_filter` and no attestation
   verified. It applies while attestation authentication runs (`ATTESTATION_AUTH` enabled); there is no
   development-profile escape.

## Notes

F-0074: token exchange can carry a person's payment once the subject token is PingFederate-signed. The RAR plugin
has taken a token exchange's principal only from `verified_subject_token_sub` since S2b, and nothing published it, so
every token exchange was decided about nobody and `payment_initiation` was refused before the PDP. It is published
now for a subject token that verifies against `JwksEndpointKeyAccessor.getSigningJsonWebKeySet()` (the SDK accessor,
javap on 13.1.3, 2026-09-30) and the issuer PingFederate resolves for the request. An access token manager that signs
with its own key rather than the centralised signing key signs tokens that key set does not hold, so their exchanges
stay decided about nobody.

On the rig (slot 2, `pfai-p3-s4c`, PingFederate 13.1.3, this branch at 04490401, 2026-09-30), with bridge signing and a
mock attester configured and a client `s4c-attested` created through the admin API with
`attestation_dpop_max_age=30`: a fresh DPoP proof was issued a token; a proof 120 s old (beyond the client's 30 s and
the 60 s skew, within the server's 300 s) was refused at the filter with 401 `invalid_client` "DPoP proof is stale
(iat older than 30s)" and an `attestation.client.refused` event. With `attestation_required=true` added, a request
naming the client by `client_id` with no attestation was refused with 401 `invalid_client` "this client authenticates
with a client attestation" once the 30 s cache had turned over (within it, the kept policy sent it to PingFederate,
which refused it for its own reasons); with an attestation it was issued a token. With
`attestation_dpop_max_age=3600` the filter refused the client with "the client's attestation policy is not valid" and
logged `attestation.policy.invalid` with `reason=loosens property=attestation_dpop_max_age`, no value; after a restart
the start-up scan logged the client and made `AttestationPolicyScan` a `DEGRADED` part of `ATTESTATION_AUTH`. An
access token the rig issued (`typ` `at+jwt`, PS256, `kid` in `/pf/JWKS`, `iss` the issuer) meets every check
`SubjectTokenVerifier` makes; a token exchange was not driven, because the rig has no token exchange policy. The rig
was taken down. No conformance plan was re-run.

Verified 2026-09-30 by unit tests: `AttestationPolicyRoutesTest` runs the filter and the criterion over one table of
19 client-property rows with real attestations and proofs, and both agree on every row (F-0009's acceptance test);
`AttestationPolicyResolverTest` covers each property's rule, the 30 s cache on a moved clock, the bounded cache, the
503, the scan and the events' counts. pf-integration's 736 tests pass on JDK 20 with every jacoco gate, on JDK 17, and on
the image's JDK 21 (21.0.12, in a container).

The spec cited ABCA-10 §5.1 for the attestation's `sub`; draft-ietf-oauth-attestation-based-client-auth-10 has it in
§4 ("sub: REQUIRED.  The sub (subject) claim MUST specify client_id value of the OAuth Client."), and the tests carry
`@Requirement("ABCA-10 §4")`.

The policy cache is not told when a registration path or an administrator changes a client: a change takes effect
within 30 s. The criterion runs on PingFederate's engine classloader with its own copy of the cache, so the two
routes can disagree for up to 30 s after a change, and the criterion then refuses a verification the filter made
under the old policy.
