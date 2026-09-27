# The settings scan, and the federation side's catalogues

## Changelog

- Plan item ST-3 (part 1 of 3): `tools/settings-scan.py` checks, in the Build workflow's lint job, that every
  setting the reactor's main code reads is declared in a settings catalogue and that every catalogued setting is
  read. A read is an `OIDF_` name that is the whole of a string literal, a `System.getenv`, `System.getProperty`
  or `getInitParameter` call (or a PingFederate plugin field or a client's `extproperties.` name) whose argument
  is a literal, a constant or a loop over an inline list of them, and the same through any helper method that
  passes its parameter on. A read through one of those calls, or through a helper, whose name it cannot work out
  is refused rather than ignored; a lookup in the whole environment as a map (`System.getenv()` passed on) is not
  seen, beyond the `OIDF_` literal rule. A read through `platform.settings` (`settings.secret(URL_SETTING)`, as
  platform's Redis client reads the `platform-redis` catalogue) reads the entry it names, and with it the entry's
  sources and aliases. Modules not catalogued yet are listed, by the package that will catalogue them, in
  `tools/settings-scan-exemptions.txt`.
- Eleven catalogues, one per component, under `src/main/resources/META-INF/oidf-settings/`: `deployment-profile`
  (platform), `pf-audit` (platform-pf), `outbound-fetch` (oidf-jose), `federation-entity` and
  `hosted-entity-signing` (openid-federation), and `federation-runtime`, `registration`,
  `attestation-token-endpoint`, `client-properties`, `fapi2-profile` and `hosted-entities` (pf-integration) - 127
  settings with their sources, defaults, types, profile classes and whether they bear on security. The jars carry
  them; nothing reads them at run time yet.

## Before you deploy

None.

## Notes

Nothing a deployment sets changes: no reader was touched, and the catalogues describe what the code reads today,
lenient readers included (ST-5 makes them strict in Phase 3). Where docs/federation/configuration.md and the
code disagreed, the catalogue follows the code; the disagreements are F-0199, which ST-4 closes when it generates
the reference and `docs/extended-properties.json` from the catalogues. The per-client `trust_chain_*` extended
properties are among them: they are catalogued, so the generated file will ask consumers to declare three more
names.

What the catalogues found, recorded as findings: the JVM hostname flag cannot be catalogued because the format's
system-property names are lower case (F-0195); the registration sweeper's latch is a system property that stops
the sweeper when set by hand, and platform.exec's `oidf.exec.owner.<executor>` claims are the same kind, which
the scan excuses by prefix (F-0196); the federation servlet and `FederationRuntimeConfig` read
`OIDF_FEDERATION_IGNORE_SSL_ERRORS` and `OIDF_FEDERATION_TRUST_CONTROLLER_HOST` from different sources (F-0197);
two automatic-registration limits wrap past an int, and `trust_chain_request_max_age` has two defaults (F-0198).

Verified on 2026-09-28: every catalogue loads through `platform.settings`' own `Catalogue.parse` on JDK 17; the
scan passes on this branch; `tools/tests/test_settings_scan.py` holds its rules to fixtures (the literal and
comment rules, constants across classes and static imports, helpers to a fixpoint with varargs and derived
system property names, `platform.settings` reads, both directions, the per-module scope of init-params, and the
exemption file). What the
scan does not see is in its docstring: names built by concatenation (servlets/ssf's computed names, which ST3C
adds), lookups in the environment or the system properties as a map, and reads outside Java. The scan also
refuses an `accepted-risk:` profile whose id `AcceptedRisk` does not register, which the loader would refuse at
run time.
