# Components and their enable switches

From 0.6.0 each feature this repository adds to PingFederate is a component that starts on its own, fails on its
own and is switched on or off on its own (plan item S-9, first half: S9a). A component that cannot start no longer
stops `pf-runtime.war`: its surfaces answer 503, ready is 503, and PingFederate's own SSO and OAuth endpoints keep
serving. What each state looks like from outside is in [health.md](health.md).

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

**The SSF switches are not applied yet.** `OIDF_SSF_ENABLED` and `OIDF_SSF_RECEIVER_ENABLED` are catalogued and
parsed, but the SSF servlets start as their own settings say until ST-5 moves their start-up onto the component
parts (Phase 3, wave 3); until then setting either changes nothing ([F-0271](../findings/F-0271.yaml)).

## How a switch is read

A switch is `true`, `false` or unset. It is read through `Settings.of("components")`, so a value other than `true`
or `false` is refused.

- **`false`** disables the component, whatever else is set. Its start never runs; its filters pass every request on
  and its servlets answer 404.
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

**The floor on each surface.** The first statement of every request method of these nine classes is platform-pf's
`ComponentGate`. It reads the surface's own part: what a servlet or filter serves is what its own start configured,
so a part that finished its start is not half-configured whatever a sibling did. The component counts only when one
of its parts is `REFUSED`, because a violation of the deployment profile refuses the whole component (the
programme's decision 4; PR-5 adds the refusals).

| The part's state | Servlet | Filter over PingFederate's own endpoint |
|---|---|---|
| `READY`, `DEGRADED` (and no part of the component `REFUSED`) | serves | runs |
| `STARTING`, `FAILED_CONFIG`, `FAILED_DEPENDENCY`, `REFUSED`, or a sibling `REFUSED` | 503 `{"error":"temporarily_unavailable",...}`, never runs | 503 for the component's own traffic, never passes it on; every other request goes on to PingFederate |
| `DISABLED` | 404 `{"error":"not_found",...}` | passes every request on |

Why the part and not the component: on the rig on 2026-09-30, a PingFederate that names itself trust controller
before its anchor's keys are pinned had `FEDERATION` `FAILED_CONFIG` from `OpenIdRegistrationServlet` (explicit
registration needs the pinned keys) while `OpenIdFederationServlet` was `READY`. Gating on the component would have
closed the Entity Configuration that those keys are captured from ([F-0192](../findings/F-0192.yaml)). Readiness
still reads the component: ready is 503 while either part is failed.

The component's own traffic is what the filter acts on when it is healthy, read from the request alone:
automatic registration's is a request whose `client_id`, or `client_assertion` `sub`, is an https URL with a host
(OpenID Federation 1.0 §1.2 defines an Entity Identifier so), or whose assertion carries a `trust_chain` header,
or whose assertion the gate cannot read (a header or claims that are not a JSON object, or a `sub` that is not a
string) - the floor fails closed rather than guess, and it decodes base64url and standard base64 alike, as jose4j and
so the healthy filter do;
attestation's is a request with `OAuth-Client-Attestation` or its PoP; FAPI's is every request, because a FAPI
filter that did not start does not know its client list. A token request from any of PingFederate's own clients
therefore keeps working while automatic registration is failed. S9b (Phase 3, wave 4) replaces this floor with each
surface's own rule.

The 503 body is the one OpenID Federation 1.0 §8.9 (fetched 2026-09-30 from
https://openid.net/specs/openid-federation-1_0.html) gives: "If the request was malformed or an error occurred
during the processing of the request, the response body SHOULD be a JSON object with the content type
application/json." Its `temporarily_unavailable`: "The server hosting the federation endpoint is currently unable to
handle the request due to temporary overloading or maintenance. The HTTP response status code SHOULD be 503 (Service
Unavailable)." `error_description` is REQUIRED there, and the gate sends it. RFC 6749 §5.2's token error has the
same shape.

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

## Every part starts at deploy

Four servlets used to start on their first request, so readiness did not see them until someone called them
([F-0193](../findings/F-0193.yaml)): `OpenIdRegistrationServlet`, `HostedEntityServlet`, `FederationAdminServlet`
and `AttestationIssuanceServlet`. They are now `loadOnStartup = 1`. The alternative - a separate class that
registers their parts at deploy while the servlets still start lazily - would split a part's registration from the
start function the supervisor retries, and leave a window in which the part says `READY` for a servlet that has not
started. Load-on-startup is safe now because their `init` never throws: before S9a, a load-on-startup servlet whose
`init` threw took the whole war down (below). `SsfReceiverServlet` is the fifth lazy servlet; ST-5 moves it with the
rest of the SSF start-up.

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
