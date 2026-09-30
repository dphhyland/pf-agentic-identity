# Components start on their own, fail on their own and are switched on their own

## Changelog

- Every `init` of the nine classes that serve a component - `OpenIdFederationServlet`, `OpenIdRegistrationServlet`,
  `TokenEndpointAutoRegistrationFilter`, `FrontChannelAutoRegistrationFilter`, `ClientAttestationAuthFilter`,
  `Fapi2ProfileFilter`, `HostedEntityServlet`, `FederationAdminServlet` and `AttestationIssuanceServlet` - returns,
  whatever happened. What it used to throw is the part's state (`FAILED_CONFIG`, or `FAILED_DEPENDENCY` when a cause
  is an I/O, SQL, timeout or linkage failure) with its reason, and a failed component no longer takes
  `pf-runtime.war` down (plan item S-9, first half).
- A request-path gate, platform-pf's `ComponentGate`, is the first statement of each of those classes' request
  methods. A surface whose part is starting or failed, or whose component has a refused part, answers 503
  `{"error":"temporarily_unavailable",...}` and goes no further; a filter answers so only for its component's own
  traffic and passes the rest to PingFederate. A servlet that is off answers 404 `not_found`; a filter that is off
  passes everything on.
- A supervisor, `platform.component.Supervisor`, starts a part that failed on a dependency again, on a managed
  executor of the webapp's copy only, after a wait drawn between zero and a ceiling of 5 s doubling to 300 s. Each
  attempt counts in `oidf_component_retries_total{component}`. Configuration failures are never retried.
- Nine enable switches, `OIDF_{FEDERATION,AUTO_REGISTRATION,ATTESTATION_AUTH,ATTESTATION_ISSUER,HOSTING,SSF,SSF_RECEIVER,OPERATOR_API,FAPI}_ENABLED`,
  catalogued in platform's new `components.json` ([docs/configuration/components.md](../../configuration/components.md)).
  The SSF two are catalogued and parsed, and change nothing until ST-5 moves the SSF start-up.
- `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY` is now an alias of `OIDF_ATTESTATION_AUTH_ENABLED` and leaves
  federation-runtime's catalogue.
- Explicit registration, hosting, the operator API and the attester's issuance endpoint load at start-up, so their
  parts register at deploy rather than on the first request (finding F-0193, closed).
- The authority's signer, entity id and configuration builder are published in one write, and
  `HostedEntityServlet.configureAuthority` builds the signer before it configures the registry, so a failure leaves
  no half-configured authority. `FrontChannelAutoRegistrationFilter` publishes its wiring the same way.
- New operator page, [docs/operator/components.md](../../operator/components.md); [health.md](../../operator/health.md)
  says what changed for ready.

## Before you deploy

1. **Set each component's enable switch in production.** From 0.6.0 each component has a switch,
   `OIDF_FEDERATION_ENABLED`, `OIDF_AUTO_REGISTRATION_ENABLED`, `OIDF_ATTESTATION_AUTH_ENABLED`,
   `OIDF_ATTESTATION_ISSUER_ENABLED`, `OIDF_HOSTING_ENABLED`, `OIDF_SSF_ENABLED`, `OIDF_SSF_RECEIVER_ENABLED`,
   `OIDF_OPERATOR_API_ENABLED` and `OIDF_FAPI_ENABLED`, each `true` or `false`. Why: in production (the default
   profile) a switch left unset is inferred only while none of its component's settings is set; a component whose
   settings are present and whose switch is unset is `FAILED_CONFIG`, its surfaces answer 503 and ready is 503, with
   a reason such as "OIDF_AUTO_REGISTRATION_ENABLED is unset and OIDF_FEDERATION_TRUST_CONTROLLER_HOST is set: in
   production set OIDF_AUTO_REGISTRATION_ENABLED to true or false". What to change: set `true` for every component
   you run and `false` for every one you do not; which settings make each component present is listed in
   [docs/operator/components.md](../../operator/components.md#the-nine-components). How to tell: the start-up audit
   in server.log lists each component with its state and how its switch was read ("AUTO_REGISTRATION READY:
   OIDF_AUTO_REGISTRATION_ENABLED=true"), and the health detail carries the same text as the component's reason.
   `true` with the component's settings missing is `FAILED_CONFIG` too. Development-profile escape: with
   `OIDF_DEPLOYMENT_PROFILE=development` every unset switch stays inferred, as before 0.6.0.
2. **A failed component now answers 503 instead of stopping the war.** Until 0.5.0 a servlet or filter that could not
   start took `pf-runtime.war` down: every runtime endpoint answered 503 and the node was plainly broken. From 0.6.0
   the war starts; the failed component's own surfaces answer 503 `temporarily_unavailable`, ready
   (`/agentic-identity/health/ready`) is 503, and live, `/pf/heartbeat.ping` and PingFederate's own SSO and OAuth keep
   answering. The exception is `FAPI`: its filter cannot tell a FAPI client from any other without the client list it
   failed to read, so while it is failed every request to the endpoints it covers answers 503. Why: one broken feature
   must not take PingFederate's own endpoints with it. What to change: route the load balancer on ready if a node with
   a failed component should be taken out, and alert on ready or on the health detail rather than on the heartbeat; a
   component that failed on a dependency becomes ready by itself once the dependency is back (watch
   `oidf_component_retries_total`), one that failed on configuration waits for a restart. How to tell: the start-up
   audit and the health detail name each failed component and why. There is no development-profile escape: the war no
   longer stops in either profile.
3. **`OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY` is superseded.** It is now an alias of `OIDF_ATTESTATION_AUTH_ENABLED`:
   `false` under either name disables attestation authentication, and that is allowed in production. It is still
   read, with a warning in server.log ("OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY is deprecated; set
   OIDF_ATTESTATION_AUTH_ENABLED instead"), and the two names set to different values makes `ATTESTATION_AUTH`
   `FAILED_CONFIG`. What to change: replace it with `OIDF_ATTESTATION_AUTH_ENABLED` and the same value. Why: a
   component is switched off by its own switch; running attestation authentication without a bridge key is
   `FAILED_CONFIG` whether the switch is `true` or inferred. No development-profile escape is needed: the old name
   still works in both profiles.

## Notes

**The gate reads the part, not the component.** The spec had the floor answer by the component's state. On the rig
(2026-09-30, the branch at 65b35781, development profile) a PingFederate that names itself trust controller before
its anchor's keys are pinned had `FEDERATION` `FAILED_CONFIG` from `OpenIdRegistrationServlet` - which now starts at
deploy - while `OpenIdFederationServlet` was `READY`; a component-wide gate would have closed the Entity
Configuration the keys are captured from. So a surface answers by its own part, and by the component only when one
of its parts is `REFUSED` (decision 4). Readiness still reads the component.

**The switches are `choice` entries.** The spec asked for `bool` with no default; platform.settings refuses a `bool`
without a default ("a switch has a default"), so each is a `choice` of `true` and `false`, whose unset value is null.

**What PingFederate does with an `init` that throws**, verified on the rig and recorded in
[components.md](../../operator/components.md#verified-on-the-rig): a load-on-startup servlet fails the merged war
(2026-09-27, U-0023), a filter the same (2026-09-29), and a servlet that is not load-on-startup answers 500 on its
first request and 404 from then on while the rest of the war serves (2026-09-30, U-0280).

**Not in this change.** The SSF servlets keep their own start-up until ST-5 (wave 3), so the two SSF switches change
nothing yet (F-0271). The per-surface rules - 404 when disabled for every surface, pass-through for traffic that is
not the component's, OGNL criteria answering `false` - are S9b's (wave 4), which closes F-0013. So is a narrower floor
for `FAPI`, which answers 503 to every request its filter covers while it is failed (F-0270).
