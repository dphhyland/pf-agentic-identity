# The RAR plugin refuses its development switches in production, holds an AuthZEN context to an allow-list, and ships reference PingAuthorize policies

## Changelog

- The "Attestation-aware RAR to PingAuthorize" processor refuses, under the production profile, a configuration with
  "Skip TLS verification (dev only)" or "Trust a client-asserted principal" on, and one with "Fail open on engine
  error" on unless `pdp-fail-open` is in `OIDF_ACCEPTED_RISKS` (plan item PR-3). The rule is the settings catalogue's
  class for each field, applied by platform's read-time rule, so the message names the field, the value, the fix and
  the development escape. It runs when the admin console or the admin API saves the instance, and again at configure,
  which is the only check an imported archive gets. Until 0.6.0 both development switches were saved in production and
  ignored there, with a WARNING at configure. A plaintext PDP URL keeps its own rule, now also classed in the
  catalogue.
- An AuthZEN decision's `context` reaches the granted detail only through the members the new field "AuthZEN context
  members merged into details" names for the detail's type (H-RAR-1, F-0065). The default,
  `sales_agent: @model; account_information: @model`, lets those two types take the members their models declare and
  `payment_initiation` none. A member the field does not name is dropped, counted in
  `oidf_rar_context_dropped_total{form}` and logged by name, never merged; `context.statements` is held to the same
  list by the first part of each name. A listed member that would widen the detail is still refused by the model. An
  entry splits at its last colon, so a URI type (`urn:example:transfer: amount`) can be named.
- `enrich`'s decision step emits `rar.decision.permitted`, `rar.decision.denied` (reason class `pdp_deny`,
  `pdp_widened`, `pdp_unreachable` or `pdp_failed`) and `rar.decision.failopen`, with the type, the principal source,
  the principal hashed and the client id, catalogued in the plugin's new `rar` event catalogue. They go to
  `server.log` under `com.pingidentity.ps.oidf.rar.event` and are counted in the plugin's own
  `oidf_events_total`; they are not audit events (F-0376).
- The settings catalogue records the removed "Deny unless PERMIT" field (removed in 0.4.0) under `removed`, so the
  generated configuration page shows it (F-0231). A stored value is still ignored, not refused.
- The plugin jar carries its own classes and Jackson, rar-model and platform (with platform's HttpCore), each
  relocated, and nothing else: Jackson's unrelocated multi-release classes and the bundled artefacts' Maven
  descriptors are gone, Jackson's service files are relocated with their classes, and the plugin's event index and
  platform's are appended into one. The plugin's README lists the jar's contents.
- Reference PingAuthorize policies for `sales_agent`, `payment_initiation` and `account_information` are files in
  `plugins/rar-paz-plugin/paz/policies`, authored into a Policy Editor by `paz/author-policies.py`, with decision
  tests (`paz/decision-tests.py`: a permit, a deny and a narrowing per type, and the edges below) and a Policy
  Editor compose file that
  needs nothing from outside this repo but Ping's evaluation licence. The three one-off scripts and the compose file
  that mounted a checkout beside this one are gone. No script in `paz/`, and not `probe-decision.sh`, has a default
  secret any more, and the probe now verifies the PDP's certificate (its CA in `PAZ_CA_FILE`), skipping the check
  only for a PDP on `localhost`, `127.0.0.1` or `[::1]`.

## Before you deploy

1. **The RAR processor refuses development switches in production.** From 0.6.0, under the production profile (an
   unset `OIDF_DEPLOYMENT_PROFILE` is production), the processor refuses a configuration with "Skip TLS verification
   (dev only)" or "Trust a client-asserted principal" on. Why: both only ever took effect in development, and saved in
   production they read as protection or trust that was not there. How to tell: the admin console and the admin API
   refuse the save (the admin API answers 422 with a message that starts with the field's name, `=true, which the
   production profile forbids`); an instance that already holds the value, or arrives in an imported archive, is
   kept by PingFederate 13.1.3, which logs `Unexpected exception thrown attempting to configure plugin: <instance>`
   at ERROR with the same message when it first uses the instance, and every token request carrying one of its types
   is answered 400 `invalid_authorization_details` ("the processor bound to it is not configured"); PingFederate's
   other flows keep serving. What to change: turn both switches off on every instance, then save it (or fix the
   archive) before the upgrade. The development-profile escape: with `OIDF_DEPLOYMENT_PROFILE=development`, as the
   rig and the demos set, the switches still save and take effect.
2. **Fail-open needs the `pdp-fail-open` risk.** From 0.6.0, under the production profile, "Fail open on engine
   error" on is refused unless `OIDF_ACCEPTED_RISKS` names `pdp-fail-open`. Why: failing open grants a request without
   the PDP's narrowing whenever the PDP cannot be reached, which is a risk an operator accepts in writing, not a
   default. How to tell: as in **The RAR processor refuses development switches in production** - the save is
   refused, or an imported instance is left unconfigured and refuses its types - with a message naming
   `pdp-fail-open`. What to change: either add `pdp-fail-open` to `OIDF_ACCEPTED_RISKS` in PingFederate's
   environment, or turn the switch off. The development-profile escape: in development the switch saves without the
   risk.
3. **Only allow-listed AuthZEN context members reach a detail.** From 0.6.0, with the `authzen` PDP dialect, a member
   of a decision's `context` (or a `context.statements` entry) reaches the granted detail only when "AuthZEN context
   members merged into details" names it for the detail's type. Why: until now any member but `id`, `reason_admin`
   and `reason_user` was merged, so whatever could shape the PDP's answer could write into what PingFederate grants,
   held back only by the model's check that the grant stays within the request (F-0065). How to tell: a PDP that
   narrowed details through a member the default does not name - any member of a `payment_initiation` answer, or a
   member the type's model does not declare - now has it dropped: the detail is granted without that narrowing,
   `oidf_rar_context_dropped_total` rises, and `server.log` has `RAR AuthZEN: dropped the context member '<name>' for
   type '<type>'`. What to change: list each member your PDP's policy narrows through in the field, per type (`type:
   member, member`, entries separated by `;`; `@model` is every member the type's model declares). The
   governance-engine dialect is not affected. There is no development-profile escape: the field is the control, in
   every profile.
4. **Reference PingAuthorize policies are in plugins/rar-paz-plugin/paz/policies.** From 0.6.0 the repo ships one
   reference policy per built-in type, with decision tests, and no longer ships the author-local compose file and
   the three scripts that edited a demo branch by hard-coded ids with Ping's public demo secret as their default.
   Why: a deployment needs a starting point for all three types, and a script with a default secret is one someone
   runs against something real. How to tell: `paz/01-author-permit.py`, `02-author-containment.py` and
   `03-align-plugin-scalars.py` are gone, and `probe-decision.sh` stops with "no PDP secret" unless `PAZ_PDP_SECRET`
   or `PAZ_PDP_SECRET_FILE` is set. What to change: author from the files with `paz/author-policies.py` (see
   `paz/README.md`) and adapt the policies to your own limits before any use; give the probe its secret from the
   environment or a file. Nothing deployed changes, so there is no escape to name.

## Notes

- The rig (2026-09-30, slot 2, PingFederate 13.1.3.0): under the development profile an instance with "Skip TLS
  verification (dev only)" on saved and was exported; the rig recreated under the production profile booted from that
  archive, the instance was kept and failed to configure at first use, a client-credentials request with a
  `sales_agent` detail got 400 `invalid_authorization_details`, the same request without details got a token, and
  the admin API refused a new instance with that switch on, or with "Fail open on engine error" and no accepted risk,
  with 422. This answers U-0068. No conformance plan was re-run: the rig's plans do not use the RAR plugin.
- The decision tests ran on 2026-09-30 against `pingidentity/pingauthorizepap:11.1.0.0-latest` brought up by
  `paz/paz-compose.yml`. The first ten cases passed, but review found the `sales_agent` policy permitting `MEA`
  against an attested `EMEA APAC` (its rule was `Contains` over the space-joined lists, a substring test), an empty
  list and no principal, and `account_information` permitting any datatype but `transactions`. The policies now
  compare whole values (`Equals`, and `RegularExpression`, which the 11.1.0.0 engine matches against the whole
  value), `sales_agent` against a pattern the Policy Editor builds from the attested regions with each one quoted, and
  deny an identity hint or no principal. On 2026-10-01 all 27 cases passed against the same image, among them `MEA`,
  an empty list, an attested and an unattested region together, an attested region with pattern punctuation, and
  words that contain `initiate` or `balances`. They ask the Policy Editor's own decision endpoint; a PingAuthorize
  Server in external mode in front of it, called by the plugin, was not run (U-0385).
- "Per-type validate" (H-RAR-1) is S4D2's `validate`, which already holds each detail to its own type's model where
  it arrives; this package adds no rule to it.
- The generated configuration page says a removed name is refused; for "Deny unless PERMIT" it is ignored (F-0375).
