# Each surface of a disabled or failed component follows its own rule

## Changelog

- Each surface of a component that is disabled or failed now has its own rule, replacing 0.6.0's first, fail-closed
  floor (plan item S-9, second half). OpenID Federation's endpoints, explicit registration, hosting and the operator
  API answer 404 `not_found` when their component is off and 503 `temporarily_unavailable` (OpenID Federation 1.0
  §8.9's body) when it is failed; SSF's, the attester's and the challenge endpoints answer 404 with no body and 503.
  The automatic registration filters refuse only a request that names a federation client - 401 `invalid_client`
  when automatic registration is off, 503 when it is failed - and pass every other request to PingFederate. The
  attestation filter refuses only attestation traffic (401 when off, 503 when failed) and the clients that
  authenticate only with an attestation. A failed FAPI filter answers 503 only to the clients `OIDF_FAPI2_CLIENTS`
  names (F-0270, closed). The logout filter always lets the logout go on; a disabled or failed SSF only stops the
  emission. The table is in [docs/operator/components.md](../../operator/components.md#each-surfaces-rule).
- The OGNL criteria - `validateClientAttestation`, `attestationClaim` (`ATTESTATION_AUTH`), `validateTrustChain`,
  `federationPolicy` (`FEDERATION`) - answer `false` (`attestationClaim`: nothing), never a throw, while their
  component is not serving. On PingFederate's engine classloader, which sees none of the webapp's parts,
  platform-pf's new `CriterionGate` decides from the enable switch and the production profile's refusals.
- Ready (`/agentic-identity/health/ready`) is 503 exactly when an enabled component is neither `READY` nor
  `DEGRADED`, and a component that was serving and failed on a dependency counts as `DEGRADED` for the first 15 s of
  that blip while the supervisor retries it; the health detail marks it `"graced": true`.
- Explicit registration without the trust anchor's keys is `DEGRADED`, not `FAILED_CONFIG`: the rest of `FEDERATION`
  serves and counts as ready, and each registration answers 503 until the keys are configured (F-0192, closed).
- The gate reads each part's state from a published snapshot, without a JVM-wide lock on PingFederate's token and
  authorization path (F-0272, closed).
- The conformance rig switches federation, automatic registration and attestation off
  (`OIDF_FEDERATION_ENABLED=false`, `OIDF_AUTO_REGISTRATION_ENABLED=false`, `OIDF_ATTESTATION_AUTH_ENABLED=false`)
  instead of naming itself trust anchor; its federation profile switches the first two back on. New
  `conformance/fail-soft-matrix.sh` boots the rig once per component with its failure injected and checks the table
  and ready.

## Before you deploy

1. **Route by readiness, and know what it now means.** Ready is 503 exactly when an enabled component is not `READY`
   or `DEGRADED`. `DEGRADED` is ready; so is a component in the first 15 s of a dependency blip (it was serving,
   failed on a dependency, and the supervisor is retrying it); a component that is switched off never counts; a
   component that fails at boot is not ready until it starts. Why: a failed feature closes only its own surfaces, and
   a database that drops for a few seconds must not take every node out of rotation at once. What to change: route
   the load balancer on `/agentic-identity/health/ready` if a node with a failed component should leave rotation, and
   switch off (`OIDF_<NAME>_ENABLED=false`) every component you do not run, so that it cannot hold ready down. How to
   tell: the health detail (`/agentic-identity/health`, `oidf.health.read`) lists each component's state and reason,
   and `"graced": true` beside a component that ready is counting as degraded. No development-profile escape is
   needed: the rule is the same in both profiles.
2. **A disabled federation endpoint answers 404; a failed one 503.** With `OIDF_FEDERATION_ENABLED=false`,
   `/.well-known/openid-federation` and the other federation endpoints answer 404 `{"error":"not_found",...}`; with
   the component failed, 503 `{"error":"temporarily_unavailable","error_description":"FEDERATION is not available"}`.
   Hosting (`/federation/agents/*`, `/federation/resources/*`) and the operator API (`/federation/admin/*`) do the
   same under their own components; SSF's and the attester's endpoints answer 404 with no body and 503. Why: a server
   without the feature says so the way a server without the endpoint would, and a failed one asks the caller to come
   back (OpenID Federation 1.0 §8.9). What to change: a monitor that probed `/.well-known/openid-federation` to see
   whether the node is up should probe ready instead, and expect 404 on a node that does not run federation. How to
   tell: the body's `error` is `not_found` for off and `temporarily_unavailable` for failed. No development-profile
   escape is needed: the answers are the same in both profiles.
3. **Stop naming yourself as trust anchor to keep federation inert.** A deployment that kept OpenID Federation out of
   the way by naming PingFederate itself as `OIDF_FEDERATION_TRUST_ANCHORS` and `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`
   with no pinned keys - as the conformance rig did - should set `OIDF_FEDERATION_ENABLED=false` and
   `OIDF_AUTO_REGISTRATION_ENABLED=false` instead and drop those two lines. Why: from 0.6.0 that workaround leaves
   `AUTO_REGISTRATION` enabled and `FAILED_CONFIG` (the trust controller names no pinned keys), so ready is 503 on a
   node that serves no federation at all. How to tell: the start-up audit in server.log lists `AUTO_REGISTRATION
   FAILED_CONFIG` with "OIDF_FEDERATION_TRUST_ANCHOR_JWKS is unset". A node that is its own trust anchor and is
   bootstrapping - serving its Entity Configuration so that others can pin its keys - sets
   `OIDF_AUTO_REGISTRATION_ENABLED=false` until the keys are pinned: it is ready, and explicit registration answers
   503 until then. No development-profile escape is needed: switching a component off is allowed in both profiles.
4. **An OGNL criterion answers false while its component is off or failed.** `validateClientAttestation` and
   `attestationClaim` need `ATTESTATION_AUTH` serving, and `validateTrustChain` and `federationPolicy` need
   `FEDERATION`; otherwise the criterion answers `false` and PingFederate denies the token with 400 `invalid_grant`
   and the criterion's Error Result. Why: a criterion whose feature is not running cannot vouch for anything, and a
   criterion that throws already denied the token, with nothing in server.log to say why. What to change: a
   deployment that runs the attestation criterion without the filter - `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false`,
   the criterion verifying the attestation itself - must switch `ATTESTATION_AUTH` on (`OIDF_ATTESTATION_AUTH_ENABLED=true`
   with a bridge key) or every token its mapping issues is refused; a mapping that asks `validateTrustChain` needs
   `OIDF_FEDERATION_ENABLED=true` (or, in development, federation settings to infer it from). How to tell: server.log
   says "OGNL criterion validateClientAttestation answers false: ATTESTATION_AUTH is DISABLED" once per component at
   WARN. No development-profile escape: a criterion of a component that is off answers `false` in both profiles.
5. **A client that sends an attestation, or a federation client, is refused while that feature is off.** With
   attestation authentication switched off, a token or PAR request carrying `OAuth-Client-Attestation` answers 401
   `invalid_client` ("this server does not accept client attestations"); with automatic registration switched off, a
   request from a client registered through the federation, or naming an unknown Entity Identifier, answers 401
   `invalid_client`; and a client whose `attestation_required` is `true` is refused 401 without an attestation, as it
   is while the feature is on. Until 0.6.0 all three passed to PingFederate, which authenticated the client by
   whatever else it sent. Why: nothing verifies the attestation, or keeps the federation client's registration current and enforces
   its expiry, while the feature is off. What to change: switch the feature on for the clients that use it, or move
   those clients to another authentication method; clients made through explicit registration count as federation
   clients, so a deployment that registers explicitly also needs `OIDF_AUTO_REGISTRATION_ENABLED=true`. With
   attestation authentication off, every request that names a client still asks the client store for its
   `attestation_required`, and answers 503 when the store cannot say. How to tell: the 401 body names the feature. No
   development-profile escape is needed: the rule is the same in both profiles.

## Notes

**Verified first, on the rig** (2026-09-30, slot 1, PingFederate 13.1.3.0, origin/main cf5b8bce before this change,
development profile, a probe client and the criteria set on the client-credentials access token mapping through the
admin API). A criterion that returns `false` (`1 == 2`) and one that throws (`@java.lang.Integer@parseInt("x")`) both
denied the token: 400 `{"error":"invalid_grant","error_description":"<the Error Result>"}`. PingFederate's code is
`invalid_grant`, not `access_denied`; a criterion can refuse a token but not choose the refusal's code. U-0110 (the
issuance criterion's containment check on the engine classloader) held and is closed: with the filter off and
`validateClientAttestation(#this)` on the mapping, an attested request within the attestation's ceiling got a DPoP
token, one over it got 400 with "authorization_details exceeds what the client attestation allows" in server.log, the
engine's models loaded once on the first criterion call, and with a truncated `OIDF_RAR_MODELS` every attested token
was refused with "the RAR containment models could not be loaded".

**Verified after, on the rig** (2026-09-30, the branch at 428acf93, PingFederate 13.1.3.0 on java 21.0.12.1):
`conformance/fail-soft-matrix.sh`, one boot per component with its failure injected, a bootstrap trust anchor and a
`FAILED_DEPENDENCY` retried to `READY` without a restart - 44 rows, none failed; its output is in
[components.md](../../operator/components.md#verified-on-the-rig). With federation and attestation switched off,
`validateClientAttestation` and `federationPolicy` on the client-credentials mapping answered `false` on the engine's
classloader (400 `invalid_grant`, and "OGNL criterion ... answers false: ATTESTATION_AUTH is DISABLED" in server.log). The 15 s grace for a dependency blip was not seen
there: nothing moves a serving part to `FAILED_DEPENDENCY` at run time today but the SSF transmitter's store probe, and
the matrix did not drop a database under a serving node (U-0355). Unit tests hold it with a hand-moved clock.

**The engine's copy cannot see the webapp's parts.** `CriterionGate` answers from the switch and the profile; a part
that failed on a dependency, or on a configuration only its start reads, is invisible to it (F-0345). The criterion's
own state then decides, as before.

**Where this departs from the spec.** Explicit registration without the anchor's keys is `DEGRADED`, a change to
`OpenIdRegistrationServlet`'s start function, because otherwise `FEDERATION` is `FAILED_CONFIG` and ready 503 on the
very bootstrap F-0192 describes. FAPI's rule (F-0270) and the gate's lock-free read (F-0272), both filed for S9b, are
done here. The logout filter's subject extraction now catches a linkage error too, which the surface matrix found
stopping the logout.
