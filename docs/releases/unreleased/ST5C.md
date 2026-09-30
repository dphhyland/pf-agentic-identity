# SSF reads its settings strictly and starts as one part

## Changelog

- Every SSF transmitter setting is read through the `ssf-transmitter` catalogue with platform's `Settings`
  (plan item ST-5): the servlet's init-param, then the system property `oidf.ssf.<init-param>`, then
  `OIDF_SSF_<UPPER_SNAKE>`, the order `SsfConfiguration.param` used. The 42 camelCase system properties
  (`oidf.ssf.signingAlgorithm` and the rest) are catalogued under their real names, so nothing that was read stops
  being read (finding F-0235, closed), and a secret can be given as a file (`OIDF_SSF_JDBC_PASSWORD_FILE` and the
  like). The logout filter's `OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM` is read through `ssf-logout-signal` the same way.
- Values are parsed strictly and every refusal names its setting: the seven switches are `true` or `false`, the six
  numbers whole numbers, the three choices one of their choices (in any case now: `rs256` is `RS256`), and the three
  URLs http or https URLs with a host.
- The transmitter starts once, as the `SSF` component's part, from `SsfConfigurationServlet` (plan item S-9), and
  its whole state - configuration, store, minter, services, receiver and receiver authenticator - is built first and
  published in one write, or not at all (finding F-0040, closed). A setting that does not parse is `FAILED_CONFIG`
  with an ERROR naming it (findings F-0191 and F-0237, closed); a store that cannot be reached is `FAILED_DEPENDENCY`,
  and platform's supervisor starts it again with backoff until it opens - SSF's own 30-second boot retry is gone.
- `OIDF_SSF_ENABLED` and `OIDF_SSF_RECEIVER_ENABLED` now apply (finding F-0271, closed). `SsfReceiverServlet` loads
  at start-up after the transmitter, so the receiver's part registers at deploy (the last servlet of F-0193); a
  receiver nobody configured is `DISABLED` whatever became of the transmitter.
- Every SSF servlet's request methods start with a gate: 503 `temporarily_unavailable` while SSF (or, for the push
  endpoint, the receiver) is starting, failed or refused, and 404 `not_found` while it is off. Until 0.6.0 those
  requests failed inside the servlet with a 500. A refused SSF no longer configures itself and serves (finding F-0295,
  closed).
- Only `SsfConfigurationServlet`'s init-params configure SSF. The other SSF servlets start nothing; until 0.6.0 the
  first of them to initialise could configure the transmitter from its own init-params.
- The store is checked on one connection before it is used, so a database that is down fails at start-up for the
  `ldm` dialect too; H2 and HSQLDB are refused in every profile, as since 0.5.0, now as a configuration failure that
  is not retried.
- In production an in-memory SSF store needs the `in-memory-state` risk, and a store that is not PostgreSQL is
  refused (plan decisions 9, 10 and 15; PR-2), through `ProfileRefusals`, so both show in the start-up audit.
- The receiver's settings (`OIDF_SSF_RECEIVER_*` but the receiver scope) refuse `SSF_RECEIVER` only when the
  production profile refuses one, not the transmitter as well (finding F-0297's SSF part).
- `tools/settings-scan.py` no longer lets a catalogue entry leave out an `oidf.ssf.<camelCase>` property.

## Before you deploy

1. **SSF settings are parsed strictly.** What to do: check every `OIDF_SSF_*` variable, `oidf.ssf.*` system
   property and SSF init-param you set. The seven switches - `OIDF_SSF_KAFKA_ENABLED`,
   `OIDF_SSF_INTROSPECTION_INSECURE_TLS`, `OIDF_SSF_VERIFICATION_EVENT_ENABLED`, `OIDF_SSF_RECEIVER_INSECURE_TLS`,
   `OIDF_SSF_RECEIVER_ACTIONS_ENABLED`, `OIDF_SSF_RECEIVER_INSTANCE_REGISTRY` and `OIDF_SSF_AUDIT_EVENTS_ENABLED` -
   take `true` or `false` only (in any case); the numbers (`OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS`,
   `OIDF_SSF_PUSH_RETRY_BACKOFF_SECONDS`, `OIDF_SSF_POLL_MAX_EVENTS`, `OIDF_SSF_SET_TTL_SECONDS`,
   `OIDF_SSF_RECEIVER_JWKS_CACHE_SECONDS`, `OIDF_SSF_RECEIVER_POLL_INTERVAL_SECONDS`) take a whole number; the URLs
   (`OIDF_SSF_INTROSPECTION_ENDPOINT`, `OIDF_SSF_RECEIVER_JWKS_URL`, `OIDF_SSF_RECEIVER_POLL_URL`) an http or https URL
   with a host; `OIDF_SSF_DEFAULT_EVENT_TYPES` at least one event type. Why: until 0.6.0 a switch set to anything but
   `true` was quietly `false` (`receiverActionsEnabled=yes` turned the receiver's actions off), and a number or choice
   that did not parse turned SSF off with an INFO line that blamed the issuer. What now happens: SSF is
   `FAILED_CONFIG`, its endpoints answer 503, readiness is 503, and server.log has an ERROR such as "SSF transmitter
   NOT started: OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS must be a whole number, not lots". How to tell: the start-up audit
   lists "SSF FAILED_CONFIG" with that reason. What to change: the value, to the strict spelling. Development-profile
   escape: with `OIDF_DEPLOYMENT_PROFILE=development` a switch's legacy spelling (`yes`, `no`, `1`, `0`, `on`, `off`)
   is still read, as `false` - what the reader before 0.6.0 made of it - with a WARN naming the strict spelling, and
   the banner lists it under "legacy values"; production refuses it. A number or URL has no escape: it was refused
   before too, only more quietly.
2. **Set `OIDF_SSF_ENABLED`.** What to do: in production set `OIDF_SSF_ENABLED=true` where SSF runs and `false` where
   it does not, and `OIDF_SSF_RECEIVER_ENABLED` the same for the receiver. Why: the switches now apply to SSF as to the
   other components ("Set each component's enable switch in production", package S9A). Unset in production, SSF is
   inferred only while none of `OIDF_SSF_ISSUER`, `OIDF_SSF_JDBC_URL` and `OIDF_SSF_DATA_STORE_ID` is set - with one
   of them set it is `FAILED_CONFIG`, naming the switch - and the receiver likewise with
   `OIDF_SSF_RECEIVER_EXPECTED_ISSUER`, `OIDF_SSF_RECEIVER_JWKS_URL` or `OIDF_SSF_RECEIVER_POLL_URL`. Only the
   environment counts for that inference; a setting given as a system property or init-param does not. With
   `OIDF_SSF_ENABLED=true` and no issuer, SSF is `FAILED_CONFIG` with an ERROR naming `OIDF_SSF_ISSUER`;
   `OIDF_SSF_ENABLED=false` disables it whatever else is set, and its endpoints answer 404. How to tell: the start-up
   audit's line for SSF says how its switch was read ("SSF READY: OIDF_SSF_ENABLED=true"). Development-profile
   escape: with `OIDF_DEPLOYMENT_PROFILE=development` an unset switch is inferred from the settings, as before 0.6.0.
3. **An in-memory SSF store needs the `in-memory-state` risk in production.** What to do: give SSF a store - a
   PingFederate JDBC data store on PostgreSQL, `OIDF_SSF_DATA_STORE_ID` - or, if one node's memory is what you want,
   add `in-memory-state` to `OIDF_ACCEPTED_RISKS`. Why: with neither `OIDF_SSF_DATA_STORE_ID` nor
   `OIDF_SSF_JDBC_URL` set, streams, subjects and undelivered SETs live in one node's memory, are lost at a restart and
   are seen by that node only (plan decision 9: state held in memory needs the accepted risk until clustering, C-1,
   says more). What now happens: SSF is `REFUSED`, its endpoints answer 503, and server.log has "Production profile:
   SSF refused - the SSF store is in memory (no OIDF_SSF_DATA_STORE_ID), which the production profile allows only with
   the risk 'in-memory-state' accepted". How to tell: the start-up audit lists the refusal. Development-profile escape:
   with `OIDF_DEPLOYMENT_PROFILE=development` the in-memory store is used with a WARN, as the conformance rig does.
4. **SSF's store must be PostgreSQL in production.** What to do: point `OIDF_SSF_DATA_STORE_ID` at a PingFederate
   data store on PostgreSQL. Why: the store's `tables` layout and the `ldm` dialect (the Identity Object Model's
   PostgreSQL schema) are written and tested for PostgreSQL only (plan decision 10). How it is told: on one connection
   at start-up, by the product name the JDBC driver reports (`DatabaseMetaData.getDatabaseProductName()`, which is
   `PostgreSQL` for PostgreSQL's driver) - a data store id shows no URL - and, for `OIDF_SSF_JDBC_URL`, by its
   `jdbc:postgresql:` prefix before anything connects. What now happens: any other database makes SSF `REFUSED`, with
   an ERROR naming the product ("the SSF store's database (PingFederate data store 'ssf') is MySQL, not PostgreSQL");
   H2 and HSQLDB stay refused in every profile. `OIDF_SSF_JDBC_URL` itself remains forbidden in production, as
   classed since 0.5.0. How to tell: the start-up audit lists the refusal. Development-profile escape: with
   `OIDF_DEPLOYMENT_PROFILE=development` another database is used with a WARN, untested.

## Notes

**Rig runs** (2026-09-30, slot 3: `PF_RIG_NAME=pfai-p3-st5c`, PingFederate 13.1.3.0 on java 21.0.12.1, the
conformance profile's settings, development profile, a suite at release-v5.3.1 from `suite/suite-compose.yml`), on
the branch at `d63629ea`: `openid-ssf-transmitter-test-plan` (poll), plan `UMrqIK7ZhRNrR`, 19 of 19 PASSED;
`openid-ssf-transmitter-caep-test-plan`, plan `T2nmjH2FzFLcC`, 13 of 13 PASSED. Start-up on the same rig: with
`OIDF_SSF_JDBC_URL` naming a PostgreSQL that was not running, SSF was `FAILED_DEPENDENCY` with 503 on its endpoints,
and the supervisor's attempt 38 s after the database started made it `READY` (U-0282, closed); at `2d952243`,
`OIDF_SSF_PUSH_RETRY_MAX_ATTEMPTS=lots` gave `FAILED_CONFIG` with the ERROR naming it and 503,
`OIDF_SSF_VERIFICATION_EVENT_ENABLED=yes` was read as `false` with the legacy WARN, and `OIDF_SSF_ENABLED=false` gave
`DISABLED` and 404. The production refusals were not seen on a running PingFederate: the image refuses the rig's
plaintext archive in production (U-0340).

**Found on the way.** The image carries no PostgreSQL JDBC driver, so `OIDF_SSF_JDBC_URL` cannot open a store in it
(F-0330); a receiver JWKS that cannot be reached is not a start-up failure, since it is fetched on the first SET
(F-0331, for HSSF1); a Kafka publisher that cannot be built leaves SSF `READY` with no fan-out (F-0332, for HSSF3).

**Where this departs from the specification.** The four transmitter servlets with no part of their own (stream
management, poll, `events:emit`, SCIM) got the gate as their first statement, one call each, because "the endpoints
503 in between" needs it; S9B replaces the floor with each surface's own rule. docs/operator/components.md's SSF
paragraph was rewritten because it said the switches did not apply. A choice is now read in any case, as platform's
parser reads every choice. The specification's "FAILED_DEPENDENCY for a JWKS that is unreachable" is F-0331.

**Tests.** servlets/ssf's 427 tests with its method coverage gate (the start-up's methods added to it) on JDK 20 and
17, and on the image's java 21; `SsfSettingsTest` reads every setting from each of its three sources and refuses a
bad value of each, `SsfComponentsTest` drives the start functions through a supervisor with a hand-run scheduler, and
`SsfSupportBootTest` has four threads read the state while it is being built.

**Findings.** Closes F-0040, F-0191, F-0235, F-0237, F-0271 and F-0295, and U-0282; opens F-0330, F-0331, F-0332 and
U-0340. F-0025 is the umbrella (plan decision 6: named, not edited).
