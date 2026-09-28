# Settings catalogues for the SSF transmitter, device-enrolment and gm-api, and SET order on any Postgres collation

## Changelog

- Plan item ST-3, part 3 of 3: servlets/ssf, services/device-enrolment and services/gm-api/servlet have settings
  catalogues - `ssf-transmitter.json` (SsfConfiguration's 43 settings), `ssf-logout-signal.json`
  (`OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM`), `device-enrolment.json` (31 environment variables, the non-OIDF names
  included) and `gm-api.json` (six init-params and their environment fallbacks). Each entry records its default,
  what today's parser does with a wrong value and its profile class. Nothing reads through them yet (ST-5).
- `tools/settings-scan.py` reads computed names: a literal or constant prefix `+` a name, or `+`
  `camelToUpperSnake(name)`. `SsfConfiguration.param(config, "x")` is a read of init-param `x`, system property
  `oidf.ssf.x` and `OIDF_SSF_<X>`, and the scan checks that one call's names are one entry's sources in the order
  `param` tries them. The ST3C group of the scan's exemption file is gone; services/harness joins the "not shipped"
  group.
- The two Postgres SSF stores order a second's SETs by `jti COLLATE "C"`, so the order is the one the store
  contract promises on a database with a linguistic collation too (F-0236). The Build workflow runs the SSF store
  suites on a glibc-collated Postgres as well as the alpine one. New in the register: F-0235, F-0236, F-0237,
  F-0238. F-0025 and F-0026 stay open.

## Before you deploy

1. **An SSF JDBC store on a database that is not PostgreSQL.** `JdbcSsfStore`'s two reads of pending SETs now say
   `COLLATE "C"`, which is PostgreSQL's syntax: on MySQL 8.4 it fails with `Unknown collation: 'C'` (checked
   2026-09-28), so on a MySQL data store every `peek` and `dueForPush` fails where the old ORDER BY ran. H2 and
   HSQLDB are already refused at boot, and 0.5.0 supports PostgreSQL only.
   If `jdbcUrl` or `dataStoreId` points the transmitter at another engine, move it to PostgreSQL before upgrading.

## Notes

What changed. Every setting servlets/ssf, device-enrolment and gm-api read is now in a catalogue, so the scan holds
them to it both ways and ST-4 can generate their reference rows. The catalogues record the code as it is on
2026-09-28, lenient parsers included: SsfConfiguration's seven booleans, the logout filter's switch and device-enrolment's six read anything
but `true` as false, and the entries say so; ST-5 moves them onto platform.settings' strict parsers (F-0025).

Where the catalogue cannot say what the code does. SsfConfiguration reads the system property `oidf.ssf.<name>`
with the init-param's camelCase name, and a catalogue's system-property names are lower case, so 42 of the 43
entries carry the init-param and the environment variable only; the scan matches each call's system property to
the entry by the other two names ([F-0235](../../findings/F-0235.yaml)). The properties are still read, as before;
ST-5 has to settle this before it moves SSF onto platform.settings, or they stop being read. device-enrolment's
`DATABASE_URL` is an entry of its own, read only to refuse it when `IDM_DATABASE_URL` is unset, because the
format's removed names are refused whenever set, and Main ignores `DATABASE_URL` once `IDM_DATABASE_URL` is. gm-api's
`AUTHZEN_BASE_URL` and `GM_AUDIENCE` are recorded as the fallbacks they are in the code, and the entries say the
shipped web.xml sets both init-params, so the war never reads them ([F-0238](../../findings/F-0238.yaml)).

services/harness is exempt rather than catalogued: it is verification CLIs run by hand, nothing in `build/` or
`.github/` stages or releases it, and a catalogue would put a developer's variables in the operators' reference.

SET order. The SSF store contract says a second's SETs come back in `jti` order from `peek` and `dueForPush`, and
InMemorySsfStore compares `jti` as Strings. On a database whose collation is glibc's `en_US.utf8` - the Debian
postgres image's default - both Postgres stores returned them in the collation's order, which folds case and skips
`-` and `_`, and the contract test failed; on postgres:16-alpine, whose musl collation is bytewise, it passed. The
ORDER BY clauses now say `COLLATE "C"`. It does not make the order the order the SETs were generated in: that is
still [F-0095](../../findings/F-0095.yaml), for S-10.

How it was verified, on 2026-09-28. `python3 tools/settings-scan.py` is clean with the ST3C group deleted, and its
fixtures cover computed names, the order check and a name the format cannot hold. The SSF store suites failed on
postgres:16 (Debian) before the change and pass on it and on postgres:16-alpine after, on JDK 17; with the change,
the whole reactor's `mvn verify` - every store suite and the coverage gates - passes against the Debian image on
JDK 17.

Residual risk. A wrong SSF number still turns the transmitter off with an INFO line that does not name the setting
and says the issuer is missing ([F-0237](../../findings/F-0237.yaml)); ST-5's strict parsers fix the message.
