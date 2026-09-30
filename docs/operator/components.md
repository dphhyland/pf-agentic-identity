# Components and their enable switches

From 0.6.0 each feature this repository adds to PingFederate is a component that starts on its own, fails on its
own and is switched on or off on its own (plan item S-9: S9a, then S9b). A component that cannot start no longer
stops `pf-runtime.war`: its own surfaces answer 503 or step aside, as [each surface's rule](#each-surfaces-rule)
says, ready is 503, and PingFederate's own SSO and OAuth endpoints keep serving. What each state looks like from
outside is in [health.md](health.md).

## The nine components

| Component | Switch | What it serves | Settings that make it "present" |
|---|---|---|---|
| `FEDERATION` | `OIDF_FEDERATION_ENABLED` | the Entity Configuration, fetch, list, resolve, Trust Mark and historical-keys endpoints, explicit registration (`/federation/register`) | `OIDF_FEDERATION_TRUST_ANCHORS`, `OIDF_FEDERATION_SUBORDINATES`, `OIDF_FEDERATION_TRUST_ANCHOR_JWKS`, `OIDF_FEDERATION_SELF_ANCHOR`, `OIDF_FEDERATION_TRUST_MARK_TYPES`, `OIDF_FEDERATION_ENDPOINT_AUTH` |
| `AUTO_REGISTRATION` | `OIDF_AUTO_REGISTRATION_ENABLED` | automatic registration at `/as/token.oauth2`, `/as/authorization.oauth2` and `/as/par.oauth2` | `OIDF_FEDERATION_TRUST_CONTROLLER_HOST`, `OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL`, `OIDF_AUTO_REGISTRATION_FAIL_CLOSED`, `OIDF_AUTO_REGISTRATION_FRONT_CHANNEL` |
| `ATTESTATION_AUTH` | `OIDF_ATTESTATION_AUTH_ENABLED` | `attest_jwt_client_auth` at the token and PAR endpoints | `OIDF_BRIDGE_SIGNER_BACKING`, `OIDF_BRIDGE_SIGNING_KEYS`, `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING`, `OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT` |
| `ATTESTATION_ISSUER` | `OIDF_ATTESTATION_ISSUER_ENABLED` | the client attester's `/federation/attestation` | `OIDF_ATTESTER_SIGNING_JWK`, `OIDF_ATTESTER_FEDERATION_ENTITY`, `OIDF_ATTESTER_OP_ISSUER`, `OIDF_ATTESTER_CIMD_URL`, `OIDF_ATTESTER_SPIRE_ENTRIES_URL` |
| `HOSTING` | `OIDF_HOSTING_ENABLED` | hosted subordinates, `/federation/agents/*` and `/federation/resources/*` | `OIDF_AUTHORITY_ENTITY_ID`, `OIDF_AUTHORITY_JDBC_URL`, `OIDF_AUTHORITY_DATA_STORE_ID`, `OIDF_OPENBAO_URL` |
| `SSF` | `OIDF_SSF_ENABLED` | the Shared Signals transmitter | `OIDF_SSF_ISSUER`, `OIDF_SSF_JDBC_URL`, `OIDF_SSF_DATA_STORE_ID` |
| `SSF_RECEIVER` | `OIDF_SSF_RECEIVER_ENABLED` | the Shared Signals receiver | `OIDF_SSF_RECEIVER_EXPECTED_ISSUER`, `OIDF_SSF_RECEIVER_JWKS_URL`, `OIDF_SSF_RECEIVER_POLL_URL` |
| `OPERATOR_API` | `OIDF_OPERATOR_API_ENABLED` | the federation operator API, `/federation/admin/*` | `OIDF_AUTHORITY_ADMIN_TOKEN` |
| `FAPI` | `OIDF_FAPI_ENABLED` | FAPI 2.0 enforcement for the clients it names | `OIDF_FAPI2_CLIENTS` |

The lists are the same as each switch's description in
[components.json](../../libs/platform/src/main/resources/META-INF/oidf-settings/components.json) and its generated
page, [docs/configuration/components.md](../configuration/components.md). A setting counts as present when it is set
in the environment and not blank; a setting given only as a system property or an init-param (such as
`oidf.authority.entity_id` or `oidf.fapi2.clients`) does not count, so production infers that component without
saying so.

`OIDF_OPENBAO_URL` is shared: the attester's signing key reads it too. An attester-only node that sets it for that key
and leaves `OIDF_HOSTING_ENABLED` unset has `HOSTING` `FAILED_CONFIG` in production, with the switch named; set
`OIDF_HOSTING_ENABLED=false`.

The SSF switches apply as the others do from ST-5 (package ST5C): the transmitter and the receiver start through
their parts ([servlets/ssf/README.md](../../servlets/ssf/README.md#start-up)), so `OIDF_SSF_ENABLED=false` disables SSF
and its servlets answer 404, and `OIDF_SSF_RECEIVER_ENABLED=false` keeps the transmitter from building the receiver
([F-0271](../findings/F-0271.yaml)). The receiver runs inside the transmitter: with SSF off, a receiver switched on
is `FAILED_CONFIG`.

## How a switch is read

A switch is `true`, `false` or unset. It is read through `Settings.of("components")`, so a value other than `true`
or `false` is refused.

- **`false`** disables the component, whatever else is set. Its start never runs; its servlets answer 404, and its
  filters pass every request on except the component's own traffic, which is told the feature is off
  ([each surface's rule](#each-surfaces-rule)).
- **`true`** starts it. A component switched on without the settings it needs is `FAILED_CONFIG`, and the reason
  says `OIDF_<NAME>_ENABLED=true but` what is missing.
- **Unset, in development** (`OIDF_DEPLOYMENT_PROFILE=development`): inferred from the component's settings, as
  before the switches existed. The table in [libs/platform's README](../../libs/platform/README.md#health) says what
  each component infers.
- **Unset, in production** (the default profile): inferred only while none of the component's settings in the table
  above is set. A component whose settings are present and whose switch is unset is `FAILED_CONFIG`, with a reason
  naming the switch and the settings that are set - a configuration the operator has not finished. The Phase 3 plan
  (decision 1) makes this `FAILED_CONFIG` rather than `REFUSED`: `REFUSED` is the profile's answer to a governed
  setting, which PR-5 adds; the fix here is to set the switch, and nothing retries it.

`OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY` is a superseded name for `OIDF_ATTESTATION_AUTH_ENABLED`, catalogued as its
alias: it is still read (its system property `oidf.attestation.require.bridge.key` too) with a warning, and the two
set to different values is refused, which makes `ATTESTATION_AUTH` `FAILED_CONFIG`. `false` under either name
disables the component, and that is allowed in production: disabling a component is not a violation. Running it
without a bridge key is: `ATTESTATION_AUTH` switched on or inferred with no bridge signing configured is
`FAILED_CONFIG`.

**What a node inferred** is in two places. The start-up audit in server.log ("Start-up audit for / (ROOT):") lists
each component with its state and, beside a state that needs no reason, how its switch was read. From the rig on
2026-09-30 (development profile, `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false` in its variables):

```
  components:     ATTESTATION_AUTH DISABLED: OIDF_ATTESTATION_AUTH_ENABLED=false
                  ATTESTATION_ISSUER READY: OIDF_ATTESTATION_ISSUER_ENABLED unset: inferred (development profile)
                  HOSTING DISABLED: OIDF_HOSTING_ENABLED unset: inferred (development profile)
```

with, earlier in the log, the superseded name's warning: "OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY is deprecated; set
OIDF_ATTESTATION_AUTH_ENABLED instead". The health detail (`/agentic-identity/health`, with the admin token)
carries the same text as the component's `reason`.

## What a component does when it fails

Each servlet's and filter's `init` hands its start function to its part and returns, whatever happened: nothing it
used to throw reaches the container. The part records the outcome - `DISABLED`, `READY`, `DEGRADED`,
`FAILED_CONFIG` or `FAILED_DEPENDENCY` - and the component is the worst of its enabled parts.

Shared state is published once, whole. The authority's signer, entity id and configuration builder are one value
assigned in one write, so a reader sees all three or none, and `HostedEntityServlet.configureAuthority` resolves its
store, domain metadata policy and signer before it publishes the registry, so a policy that is not one leaves no
registry behind (`SurfaceGateTest.aStoreIsNotPublishedWhenALaterStepOfTheAuthorityFails`, which fails with the old
order).
`FrontChannelAutoRegistrationFilter` publishes what its requests need as one value at the end of its start.

## Each surface's rule

The first statement of every request method of a component's servlets and filters is platform-pf's `ComponentGate`
(plan item S9b, which replaced S9a's fail-closed floor). A surface's part is **serving** when it is `READY` or
`DEGRADED` and no part of its component is `REFUSED`; **disabled** when it is `DISABLED`; and **failed** in every
other state - `STARTING`, `FAILED_CONFIG`, `FAILED_DEPENDENCY`, `REFUSED`, or a sibling part `REFUSED`, because a
violation of the deployment profile refuses the whole component (the programme's decision 4). Serving, the gate does
nothing. Otherwise:

| Surface | Disabled | Failed |
|---|---|---|
| Federation endpoints (`FEDERATION`: the Entity Configuration, fetch, list, resolve, Trust Mark and historical-keys endpoints, `/federation/register`; `HOSTING`: `/federation/agents/*`, `/federation/resources/*`; `OPERATOR_API`: `/federation/admin/*`) | 404 `{"error":"not_found",...}` | 503 `{"error":"temporarily_unavailable",...}` |
| SSF (`SSF`, `SSF_RECEIVER`), the attester (`ATTESTATION_ISSUER`) and the challenge endpoints | 404, no body | 503 `{"error":"temporarily_unavailable",...}` |
| Automatic registration filters (`AUTO_REGISTRATION`, over `/as/token.oauth2`, `/as/authorization.oauth2`, `/as/par.oauth2`) | a request naming a federation client: 401 `invalid_client`; every other request goes on to PingFederate | a request naming a federation client: 503; every other request goes on |
| Attestation filter (`ATTESTATION_AUTH`, where it authenticates clients) | a request with `OAuth-Client-Attestation` or its PoP: 401 `invalid_client`; a client that authenticates only with an attestation: the filter's own 401; every other request goes on | attestation traffic: 503; such a client: 401; every other request goes on |
| FAPI filter (`FAPI`) | every request goes on | a request from a client `OIDF_FAPI2_CLIENTS` names: 503; every other request goes on |
| Logout filter (`SSF`, over `/idp/init_logout.openid`) | the logout goes on; nothing is emitted | the logout goes on; nothing is emitted |
| OGNL criteria (`validateClientAttestation`, `attestationClaim`: `ATTESTATION_AUTH`; `validateTrustChain`, `federationPolicy`: `FEDERATION`) | `false` (`attestationClaim`: empty) | `false` (`attestationClaim`: empty) |

Every body is JSON with `Cache-Control: no-store`, and the 503's `error_description` names the component
(`"FEDERATION is not available"`). `SurfaceMatrixTest` (in servlets/ssf and servlets/attestation-issuer) drives
every row in every state for every surface the war maps: it finds the servlets from their `@WebServlet`
annotations and the filters from build/pingfederate/filters.xml rather than from a list, so a surface added without
a gate fails it (the Phase 3 plan's risk 4). A method a servlet has no handler for may get HttpServlet's own 405 or
501 instead of the gate's answer, which serves nothing; every method it handles must meet the gate. On its first run
it found the logout filter letting a linkage error out of its subject extraction, which stopped the logout; the
filter now lets the logout go on whatever the extraction meets.

**Why the part and not the component.** A servlet or filter serves what its own start configured, so a part that
finished its start is not half-configured whatever a sibling did. On the rig on 2026-09-30, a PingFederate that names
itself trust controller before its anchor's keys are pinned had explicit registration unable to start while
`OpenIdFederationServlet` was `READY`; gating on the component would have closed the Entity Configuration that those
keys are captured from ([F-0192](../findings/F-0192.yaml)). From S9b explicit registration without the anchor's keys
is `DEGRADED` - "`OIDF_FEDERATION_TRUST_ANCHOR_JWKS` is unset (and no `OIDF_FEDERATION_SELF_ANCHOR`): explicit
registration answers 503 until the trust anchor's keys are configured" - so `FEDERATION` is ready while the rest of it
serves, and each registration answers 503.

**Which requests name a federation client.** The automatic registration gate reads three signals:

- the `client_assertion` carries a `trust_chain` header (the request asks to be registered from that chain), or the
  gate cannot read the assertion (a header or claims that are not a JSON object in base64url or standard base64, or a
  `sub` that is not a string - read as jose4j, and so the healthy filter, reads them, and closed rather than guessed);
- a client it names - the assertion's `sub`, the `client_id` parameter, or the `OAuth-Client-Attestation`'s `sub` -
  is an Entity Identifier (an https URL with a host: OpenID Federation 1.0 §1.2 defines it so, and every client this
  repository registers through the federation is known by one) and PingFederate has no such client, or has one this
  repository registered (the extended property `status` is `registered` or `auto_registered`);
- PingFederate's client store cannot say (503 in both states: nobody can tell whose client it is).

None of them can turn an ordinary client's request away. Each is read from the request itself, so a caller changes
only how its own request is treated; the one that names a stored client asks PingFederate's store, where a client
made in the console, by Terraform or by the admin API carries no federation `status`, and registration never
overwrites a client it did not register. An ordinary client whose id happens to be an https URL is looked up and goes
on. A client id that is not an Entity Identifier is never looked up.

**Disabled is told, failed is asked to wait.** While automatic registration is disabled nothing keeps a federation
client's registration current or enforces its expiry, so its client may not authenticate: 401 `invalid_client`, RFC
6749 §5.2's "Client authentication failed (e.g., unknown client, no client authentication included, or unsupported
authentication method)". A client that sends an attestation to a server with `attest_jwt_client_auth` off is told
the same way - an unsupported authentication method - with the `WWW-Authenticate` §5.2 asks for when it used the
`Authorization` header. A failed component answers 503: it may come back.

**The FAPI filter** decides FAPI's traffic from its client list, which it reads as its start does - the system
property `oidf.fapi2.clients`, then `OIDF_FAPI2_CLIENTS` - so a failed FAPI closes only the clients it names and
PingFederate's other clients keep their token endpoint ([F-0270](../findings/F-0270.yaml)). A list that names every
client (`*`), an assertion whose owner cannot be read, and a list that cannot be read make every request FAPI's.

**The OGNL criteria** run on PingFederate's engine classloader, whose copy of platform is not the webapp's: statics are
per loader ([classloaders](../development/classloaders.md)), so it sees none of the webapp's parts, and nothing in
it runs an `init`. `CriterionGate` answers there from what that copy can read for itself, once per component: the
enable switch (off, or a value that is not `true` or `false`, is not serving), then the production profile's refusals
(`ProfileRefusals.refused`, which that copy evaluates from the same process-wide environment and system properties
the webapp's sweep read). Otherwise the criterion runs, and its own lazily built state - the trust anchors, the
containment models, the attesters - refuses the token when it cannot be built, as before. The engine's copy cannot
learn that the webapp's part failed on a dependency, or on a configuration its start alone reads: it has no
supervisor and no view of the webapp ([F-0345](../findings/F-0345.yaml)). A criterion that answers `false` - or throws
- denies the token with PingFederate's 400 `invalid_grant` and the criterion's Error Result as `error_description`
(the rig, 2026-09-30, below), and `CriterionGate` logs why once per component at WARN, then at DEBUG.
`delegationActChain` has no gate of its own: the acting party's `agent_id` and attester come through
`attestationClaim`, which is gated, and the rest - `context.ClientId` and a subject token this PingFederate signed -
needs no component.

Since a disabled component's criterion answers `false`, a mapping that asks `validateClientAttestation` needs
`ATTESTATION_AUTH` on. Before 0.6.0 a deployment could switch the filter off (`OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false`)
and let the criterion verify the attestation itself; from 0.6.0 that denies every token the mapping issues.

**The 503 and 404 bodies.** OpenID Federation 1.0 §8.9 (Final, 17 February 2026; fetched 2026-09-30 from
https://openid.net/specs/openid-federation-1_0.html): "If the request was malformed or an error occurred during the
processing of the request, the response body SHOULD be a JSON object with the content type application/json." Its
`temporarily_unavailable`: "The server hosting the federation endpoint is currently unable to handle the request due to
temporary overloading or maintenance. The HTTP response status code SHOULD be 503 (Service Unavailable)." Its
`not_found`: "The requested Entity Identifier cannot be found. The HTTP response status code SHOULD be 404 (Not
Found)." `error_description` is REQUIRED there, and the gate sends it. The OAuth-style surfaces use RFC 6749's error
object; RFC 6749 defines `temporarily_unavailable` for the authorization endpoint (§4.1.2.1: "The authorization server
is currently unable to handle the request due to a temporary overloading or maintenance of the server"), and has no
code for an endpoint that is not there, so a disabled one answers 404 with no body.

## The supervisor and readiness

**The supervisor.** A part that ends its start in `FAILED_DEPENDENCY` - the exception or one of its causes is an
`IOException`, `UncheckedIOException`, `SQLException`, `TimeoutException` or `LinkageError` - is started again by
`platform.component.Supervisor`, on a managed executor of the webapp's copy: after a wait drawn uniformly between
zero and a ceiling that starts at 5 s and doubles to 300 s (full jitter, so a fleet that lost the same dependency does
not come back in step). Before each attempt the part moves to `STARTING`; the attempt runs the same start function
as `init` and records its outcome. A part retried to `READY` stops being retried; one that fails on configuration
stops too. `FAILED_CONFIG` and `REFUSED` are never retried: a restart or a configuration change fixes them. Each
attempt counts in `oidf_component_retries_total{component}`. Only the webapp's copy of platform schedules a retry
([classloaders](../development/classloaders.md), rule 2); in any other copy a part that failed on a dependency keeps
that state until it starts again.

**Readiness** is 503 exactly when an enabled component is neither `READY` nor `DEGRADED`; a disabled component never
counts. A component that was serving and then failed on a dependency is in a blip: while the supervisor retries it,
its state goes between `FAILED_DEPENDENCY` and `STARTING`, and for the first 15 s of the blip ready counts it as
`DEGRADED` (the health detail marks it `"graced": true` beside its true state), so a database that drops for a few
seconds does not take every node out of rotation at once. 15 s is the supervisor's first two ceilings, 5 s and 10 s:
a dependency that is back by its second retry never shows in ready. A component that has never served - one failing
at boot - gets no grace ([health.md](health.md#what-ready-means)).

## Every part starts at deploy

Four servlets used to start on their first request, so readiness did not see them until someone called them
([F-0193](../findings/F-0193.yaml)): `OpenIdRegistrationServlet`, `HostedEntityServlet`, `FederationAdminServlet`
and `AttestationIssuanceServlet`. They are now `loadOnStartup = 1`. The alternative - a separate class that
registers their parts at deploy while the servlets still start lazily - would split a part's registration from the
start function the supervisor retries, and leave a window in which the part says `READY` for a servlet that has not
started. Load-on-startup is safe now because their `init` never throws: before S9a, a load-on-startup servlet whose
`init` threw took the whole war down (below). `SsfReceiverServlet`, the fifth lazy servlet, moved with the rest of
the SSF start-up (ST-5): it is `loadOnStartup = 2`, after `SsfConfigurationServlet`, whose transmitter builds the
receiver.

## Verified on the rig

What PingFederate 13.1.3's Jetty does with an `init` that throws, the three cases S9a had to know:

1. **A load-on-startup servlet** (2026-09-27, [U-0023](../findings/U-0023.yaml)): the merged `pf-runtime.war` fails
   whole. With `OIDF_FEDERATION_TRUST_ANCHORS` unset, `OpenIdFederationServlet`'s init threw; Jetty ee9 logged
   "Failed startup of context" for pf-runtime.war and every runtime endpoint on 9031 answered 503, while the admin
   console on 9999 answered 200.
2. **A filter** (2026-09-29, main at a5a2d49e, the rig on its own ports, [U-0281](../findings/U-0281.yaml)): the same. With no trust controller
   configured, `FrontChannelAutoRegistrationFilter.init` threw, and server.log said:

   ```
   WARN  [org.eclipse.jetty.ee9.webapp.WebAppContext] Failed startup of context oeje9w.WebAppContext@5d685156{ROOT,/,...}{/opt/out/instance/server/default/deploy/pf-runtime.war}
   jakarta.servlet.ServletException: OpenID Federation automatic registration: No trust controller configured: set OIDF_FEDERATION_TRUST_CONTROLLER_HOST (and OIDF_FEDERATION_TRUST_ANCHOR_JWKS) - every trust chain is refused until then
   	at com.pingidentity.ps.oidf.servlet.clientregistration.FrontChannelAutoRegistrationFilter.init(FrontChannelAutoRegistrationFilter.java:118)
   	at org.eclipse.jetty.ee9.servlet.FilterHolder.initialize(FilterHolder.java:133)
   ```

3. **A servlet that is not load-on-startup** (2026-09-30, main at a5a2d49e, the rig's own configuration, which names
   no authority, [U-0280](../findings/U-0280.yaml)): only that servlet fails, and the rest of the war keeps serving. The first
   `GET /federation/agents/probe-1` ran `HostedEntityServlet.init`, which threw "HostedEntityServlet requires
   'authorityEntityId'"; Jetty logged it at WARN against the request, PingFederate's error servlet logged "Top level
   error", and the request answered 500 with PingFederate's error page. Every later request to that path answered
   404 (Jetty keeps the servlet unavailable and does not call `init` again), while discovery on the same port
   answered 200.

So "init never throws" is needed for servlets and filters alike, and a lazily started servlet that throws is not a
safe alternative either: it answers 500 once and 404 from then on, with nothing in readiness until S9a.

What this change does instead, in production (2026-09-30, this branch at 7497bd2b, the rig in production profile with
`OIDF_AUTO_REGISTRATION_ENABLED` unset, `OIDF_FEDERATION_TRUST_CONTROLLER_HOST=not a url`, and the rig's other
components switched explicitly: `OIDF_FEDERATION_ENABLED=true`, `OIDF_FAPI_ENABLED=true`,
`OIDF_OPERATOR_API_ENABLED=false`): the war started and every `init` returned. The start-up audit said

```
AUTO_REGISTRATION FAILED_CONFIG: FrontChannelAutoRegistrationFilter: OIDF_AUTO_REGISTRATION_ENABLED is unset and OIDF_FEDERATION_TRUST_CONTROLLER_HOST is set: in production set OIDF_AUTO_REGISTRATION_ENABLED to true or false; TokenEndpointAutoRegistrationF...
```

and the health detail gave both automatic-registration parts that reason. Ready answered 503 `{"status":"DOWN"}`;
live, `/pf/heartbeat.ping` and the Entity Configuration answered 200. At `/as/token.oauth2`, a
`client_credentials` request from `conformance-ssf-emitter` (a PingFederate client with a secret) answered 200
with a Bearer token, and one naming an unknown plain client answered PingFederate's own 401 `invalid_client`,
while one whose `client_id` is an https URL answered 503 `{"error":"temporarily_unavailable","error_description":
"AUTO_REGISTRATION is not available"}`. `FEDERATION` was `FAILED_CONFIG` too, from explicit registration (the
trust controller names no pinned anchor keys), and `OpenIdFederationServlet` stayed `READY`. Left unset in
production, the rig's `OIDF_FAPI2_CLIENTS` makes `FAPI` `FAILED_CONFIG` and every token request answers 503
(the same boot with only the two switches unset): the FAPI floor is every request ([F-0270](../findings/F-0270.yaml)).
