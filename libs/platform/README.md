# platform

What every module of this repository shares and PingFederate does not provide (plan item F-1, decision 10).
Package `com.pingidentity.ps.oidf.platform`, one subpackage per owner. JDK only at runtime: no Jackson, jose4j,
servlet API or PingFederate, and commons-logging only when the loader can see it (see [Logging](#logging)).
`oidf-jose` depends on it, so everything built on `oidf-jose` reaches it; `stage-modules.sh` stages its jar into
PingFederate beside the other modules, and a plugin that uses it shades and relocates its own copy. Its
PingFederate side is [libs/platform-pf](../platform-pf/README.md). How the copies in PingFederate's loaders
behave is in [docs/development/classloaders.md](../../docs/development/classloaders.md).

## Who owns what

Each package of Phase 2 writes only in its own subpackage, adds jacoco includes only under its own anchor
comment in `pom.xml`, and adds its section to this page only under its own anchor comment below. Two packages
built at the same time then edit different lines and merge cleanly. This table is written once, with every
owner, so nobody edits it.

| Subpackage | Holds | Package (plan item) | Phase 2 wave |
|---|---|---|---|
| `lifecycle` | `Lifecycle`: what one loaded copy closes at shutdown, and whether it is the webapp's copy | F1 (F-1) | 1 |
| `component` | `Components`, `ComponentRegistry`: each component's state, in S-9's names | F1 (F-1) | 1 |
| `json` | `Json`: a JDK-only JSON reader and canonical writer | F1 (F-1) | 1 |
| `log` | `PlatformLog`: how platform code writes a log line | F1 (F-1), then O-6 | 1 |
| `settings` | strict parsers, the `Setting` model, the resolver, catalogues | ST12 (ST-1, ST-2) | 2 |
| `profile` | the deployment profile and accepted risks | PR1 (PR-1) | 2 |
| `tls` | `InsecureTls`, the only trust-all | PR1 (PR-1) | 2 |
| `events` | events, catalogued per component, with a PII class per field | O1 (O-1) | 2 |
| `metrics` | counters and timers with bounded labels, one MXBean per loader | O3 (O-3) | 2 |
| `health` | liveness, readiness and detail over the component registry | O4 (O-4) | 3 |
| `redis` | the Redis client | C2 (C-2) | 3 |
| `http` | outbound HTTP with deadlines, budgets, capped bodies and address pinning | S5A, S5AR (S5a) | 3, 4 |
| `exec` | managed executors | C3 (C-3) | 3 |

## lifecycle

`Lifecycle.current()` is this loader's registry of things to close: `register(name, resource)` adds an
`AutoCloseable`, and `shutdown()` closes them the last registered first, once. A close that throws is logged
and reported, and the rest are still closed. The wait is bounded (`DEFAULT_BUDGET`, ten seconds, or the
budget passed): each close runs on a short-lived daemon thread and is waited for only until the budget runs
out, so a hung close cannot hold up an undeploy; it carries on in the background and is reported as timed out.
Reverse order holds only while every close finishes in time: after a timeout, or once the budget is spent, the
remaining closes start at once while the hung one is still running, so a resource registered earlier - one the
hung resource may still be using - can close under it. A resource registered after shutdown is closed at once,
on a closer thread started by whichever copy and caller registered it, and not kept. `shutdown` returns one `Closed` per
resource, in the order it closed them.

Whether a copy is the webapp's - the one allowed to start background threads - cannot be seen from inside it.
`loaderRole()` is `UNKNOWN` until the webapp's lifecycle listener (F2, plan item F-2) calls `markWebapp()`. The
engine's copy and a plugin's get no such callback and stay `UNKNOWN`.

## component

`Components.register(name, enabled)` records a component in this loader's `ComponentRegistry` as `STARTING`
when enabled and `DISABLED` when not, and returns the handle it reports through: `ready()`, `degraded(reason)`,
`failedConfig(reason)`, `failedDependency(reason)`, `refused(reason)` and `starting()`. The seven states are
S-9's: `DISABLED`, `STARTING`, `READY`, `DEGRADED`, `FAILED_CONFIG`, `FAILED_DEPENDENCY`, `REFUSED`.
`snapshot()` lists every component's state, reason and the time it entered the state, ordered by name, for
health (O4) to read.

- A disabled component stays disabled: its handle does nothing and answers `false`.
- Registering a name again (a servlet initialised a second time) starts it afresh and retires the earlier
  handle, so a destroyed instance's late report cannot overwrite the new one's.
- A name is S-9's spelling, the part of its `OIDF_<NAME>_ENABLED` switch between prefix and suffix (`FEDERATION`,
  `AUTO_REGISTRATION`, `SSF_RECEIVER`): 1-64 of `A-Z`, `0-9` and `_`, starting with a letter. Anything else is
  refused with `IllegalArgumentException`, because names are constants and a bad one is a bug for the caller's
  tests to find.
- A reason is operator text kept to one line: control, format and separator characters become `?`, and it is
  cut at 256 characters without splitting a surrogate pair. A state that needs a reason and gets none says
  "no reason given".

There is no supervisor and no retry here: S-9's backoff is S9a (Phase 3).

## json

`Json` is rar-model's JDK-only reader and canonical writer, copied with its limits (nesting 32, number
literals 128 characters, 64 digits written out), its messages and PR #26's fix that makes a number read the
same on JDK 17 and 20. `JsonTest` is rar-model's test of it, with its tests of the digit count and the quoting.
rar-model is not changed: the duplication is finding [F-0130](../../docs/findings/F-0130.yaml), which says who
unifies the two and when. Until then a fix to one is made to the other in the same change.

## Logging

`PlatformLog` writes through commons-logging when the loader platform sits in can see
`org.apache.commons.logging.LogFactory`, and through `java.lang.System.Logger` when it cannot. The choice is
made once per loaded copy, against the loader that loaded it.

Why commons-logging, and why the fallback - what each place platform runs in sees, checked 2026-09-28:

| Where platform runs | commons-logging | Where a line goes |
|---|---|---|
| PingFederate 13.1.3, the webapp's copy (`pf-runtime.war` `WEB-INF/lib`) | yes: `server/default/lib` in the pinned image has two jars that define `LogFactory`, `commons-logging.jar` (with `log4j-jcl.jar` beside it, whose service entry names log4j's `LogFactoryImpl`) and `spring-jcl.jar` 6.2.19 (whose `LogAdapter` picks the Log4j API unless log4j's `SLF4JProvider` is present, and no jar there has it) | log4j either way - which `LogFactory` a loader resolves depends on classpath order - so server.log at the line's level |
| PingFederate 13.1.3, the engine's copy (`server/default/deploy`) | yes, the same jar | the same |
| A plugin that shades and relocates platform | yes: commons-logging is `provided` here, so shading leaves it out and the relocated copy calls PingFederate's | the same |
| `services/device-enrolment`, `demo-rs`, `harness` | yes: each declares commons-logging at compile scope | commons-logging's own discovery |
| A standalone program without commons-logging | no | `System.Logger`, which is `java.util.logging` unless the program installs a provider |

`java.util.logging` is the wrong route inside PingFederate. The image ships `log4j-jul.jar`, but its `run.sh`
sets no `java.util.logging.manager` (read 2026-09-28 in the pinned image), so a `java.util.logging` line goes
to standard error, and PingFederate logs standard error at `ERROR [SystemErr]` whatever the line's level
(finding [F-0075](../../docs/findings/F-0075.yaml), seen on the rig 2026-09-27). So `System.Logger` is only the
fallback that keeps the jar JDK-only. Not yet seen: a platform line in server.log, because nothing logs through
`PlatformLog` on the rig yet, so the route rests on the jars above until the first caller (F-2's banner, or
O-1's events) is seen on the rig. `CommonsLoggingSink` is the only class that names commons-logging, and
the JVM loads it only when it is chosen: `PlatformLogTest` loads platform in a loader without commons-logging
and shows it logs and never loads that class.

## Future owners' sections

<!-- settings (ST-1, ST-2): add this package's section below this line -->

## settings

How a setting is read (plan items ST-1 and ST-2). The catalogue format is in
[docs/development/settings-catalogue.md](../../docs/development/settings-catalogue.md).

- `Parsers` holds the strict parsers, moved out of `FederationRuntimeConfig` with their messages:
  `strictBoolean` and `bool` (`true` or `false` in any case, nothing else), `wholeNumber` and `inRange`,
  `choice`, `words`, `jsonObject`, `httpsUrl` and `httpOrHttpsUrl`, `path`, `strictly` (a parse's
  `IllegalArgumentException` refused naming the setting), `aliased` (a superseded name: warned, or refused when
  it disagrees) and `blankToNull`. A refusal is a `SettingRefused`, an `IllegalStateException` naming the
  setting (`setting()`) and the value refused. `jsonObject` reads with `platform.json`, not Jackson: the
  differences are listed in `FederationRuntimeConfigTest` and the ST12 release note.
- `Catalogue` loads `META-INF/oidf-settings/<component>.json` from the caller's classloader and checks it
  strictly: an unknown member, a missing one, a default its type refuses, a name declared twice, a removed name
  whose replacement is not in the catalogue are each refused, naming the file, the entry and the member. The
  same file found more than once is accepted when the copies are identical - PingFederate stages each jar in
  `pf-runtime.war` and in `server/default/deploy`, and the webapp's loader returns both - and refused when they
  differ. `refuseRemoved(sources)` refuses any removed name that is set.
- `Setting` is one entry: name, kind, type, default, range or choices, description, when it's wrong, profile
  class, security flag, sources in precedence order, aliases, and whether a secret may come from a `_FILE`
  variant. Its resolution rule - sources, `_FILE`, aliases, default - is on `Setting.resolve` and in the
  format page.
- `Settings.of("<component>")` reads a catalogue through typed accessors (`bool`, `integer`, `longValue`,
  `duration`, `string`, `choice`, `httpsUrl`, `url`, `jsonObject`, `words`, `path`, `secret`), each checking the
  entry's type, so a reader converted to it keeps its meaning; `resolve` also returns the provenance, the
  source and name that supplied the value. `Sources` is the environment, the system properties and the
  init-params (platform-pf's `InitParams` supplies those). Every read first refuses any of the catalogue's
  removed names that is set, whichever setting it is for. A warning is logged once per loaded copy.
- `UnknownKeys.find(environment, catalogues)` lists the `OIDF_*` names set under a catalogue's family that no
  catalogue declares. A mechanism only: nothing calls it at run time and nothing is refused for it until the
  start-up audit (PR-5) and the reader conversion (ST-5) wire it in, in Phase 3.

Nothing reads through `Settings` yet. `FederationRuntimeConfig` calls `Parsers` and is otherwise unchanged;
ST3A, ST3B and ST3C write the production catalogues, and ST-5 converts the readers.

### Lenient reads: ST-5's worklist

Every read found on 2026-09-28 (origin/main `276bcd6`) that takes a wrong value as something else rather than
refusing it. A boolean read with `Boolean.parseBoolean`, or compared with `"true"`, reads a typo as `false`; a
number whose parse failure falls back reads a typo as the default. Found by searching main code for
`Boolean.parseBoolean`, `Boolean.valueOf`, `"true".equalsIgnoreCase` and `catch (NumberFormatException`, then
reading each hit; reads that refuse are left out.

| Module | Where | Setting | What a wrong value does |
|---|---|---|---|
| servlets/pf-integration | `FederationRuntimeConfig.from` | `OIDF_FEDERATION_IGNORE_SSL_ERRORS` (and `oidf.federation.ignore.ssl.errors`, and the superseded `OIDF_TRUST_CONTROLLER_IGNORE_SSL`, `oidf.trust.controller.ignore.ssl`) | read as `false` |
| servlets/pf-integration | `FederationRuntimeConfig.pdpSettings` | `OIDF_FETCH_ALLOW_HTTP` (environment only, for the PDP URL check) | read as `false` |
| servlets/pf-integration | `RegisteredClientsServlet.init` | `OIDF_REGISTERED_CLIENTS_ENABLED` (init-param `registeredClientsEnabled`, `oidf.registered.clients.enabled`) | read as `false` |
| servlets/pf-integration | `ClientAttestationAuthFilter.requireHostedAgentSetting` | `OIDF_ATTESTATION_REQUIRE_HOSTED_AGENT` (and its system property) | read as `false` |
| servlets/pf-integration | `ClientAttestationUtils.boolProp` | extended property `attestation_challenge_required` | read as `false` |
| servlets/pf-integration | `ClientAttestationUtils.longProp` | extended properties `attestation_pop_max_age`, `attestation_dpop_max_age`, `attestation_clock_skew`, `trust_chain_request_max_age` | warned and ignored |
| servlets/pf-integration | `OIDFederationUtils.longSetting` | extended properties `trust_chain_leaf_max_time`, `trust_chain_trustanchor_max_time`, `trust_chain_request_max_age` | warned, default for that request |
| servlets/pf-integration | `PfAuditEventSink` | `OIDF_EVENTS_MAX_VALUE_LENGTH` | warned, the current length kept |
| libs/oidf-jose | `OutboundUrlPolicy.from` | `OIDF_FETCH_ALLOW_HTTP`, `OIDF_FETCH_ALLOW_PRIVATE_NETWORKS` | read as `false` |
| libs/oidf-jose | `OutboundUrlPolicy.parseLong` | `OIDF_FETCH_MAX_BODY_BYTES` | not a number, or not above 0: the default |
| libs/openid-federation | `FederationConfiguration` | `OIDF_FEDERATION_IGNORE_SSL_ERRORS` (init-param `ignoreSslErrors`); init-param `corsEnabled` | read as `false` |
| libs/openid-federation | `AttestationMetadataConfig` | init-param `attestationChallengeEndpointEnabled` | read as `false` |
| libs/client-attestation | `ClientAttestationChallengeServlet.init` | init-param `replayCacheMaxEntries` | warned and ignored |
| libs/client-attestation | `ChallengeEndpointServlet.init` | init-params `challengeCacheMaxEntries`, `challengeTtlSeconds`, `challengeRateLimitPerWindow`, `challengeRateLimitWindowSeconds`, `challengeRateLimitMaxCallers` | warned and ignored: the default |
| servlets/ssf | `SsfConfiguration.parseBoolean` | `kafkaEnabled`, `introspectionInsecureTls`, `verificationEventEnabled`, `receiverInsecureTls`, `receiverActionsEnabled`, `receiverInstanceRegistry`, `auditEventsEnabled` (each init-param, `oidf.ssf.<name>`, `OIDF_SSF_<NAME>`) | read as `false` |
| servlets/ssf | `LogoutEventFilter.allowSubParameter` | `OIDF_SSF_LOGOUT_ALLOW_SUB_PARAM` (and its system property) | read as `false` |
| servlets/attestation-issuer | `AttesterConfigurationServlet`, `AttestationIssuanceServlet`, `ClientAttestationServiceMetadataServlet` | init-param `challengeRequired`; init-param `challengeEndpointEnabled` | read as `false` |
| services/device-enrolment | `Main` | `REQUIRE_COMPLIANT_DEVICE`, `APPLE_ALLOW_DEVELOPMENT`, `ALLOW_SELF_ASSERTED_KEYS`, `PF_AUTHORITY_INSECURE_TLS`, `APPLE_MACOS_REQUIRE_KEY_POLICY`, `APPLE_REQUIRE_RENEWAL_ASSERTION` | read as `false` |
| plugins/ciba-sim | `SimulatorGate.enabled` | `OIDF_CIBA_SIM_ENABLED` | anything but `true` is off: safe, but a typo is silent |
| plugins/rar-paz-plugin | `AttestationAwareRarProcessor.parseInt` | plugin field "Request timeout (ms)" | the default, silently |
| plugins/instance-registry-datasource | `InstanceRegistryDataSource.configure` | plugin field "User verification max age (seconds)" | warned, the default |

Not shipped, so not on the list: `services/harness` (`OIDF_HARNESS_INSECURE_TLS`, `OIDF_NO_CHALLENGE`) and
`libs/testkit` (`CI`).
<!-- profile (PR-1): add this package's section below this line -->
<!-- tls (PR-1): add this package's section below this line -->
<!-- events (O-1): add this package's section below this line -->
<!-- metrics (O-3): add this package's section below this line -->
<!-- health (O-4): add this package's section below this line -->
<!-- redis (C-2): add this package's section below this line -->
<!-- http (S5a): add this package's section below this line -->
<!-- exec (C-3): add this package's section below this line -->

## Build

```sh
mvn -pl libs/platform -am verify     # -> target/platform-<version>.jar (tests on)
```

Versions come from `bom/pom.xml` (no parent pom). The coverage gate is 100% line and branch per method over
the decision methods named in `pom.xml`, each package's under its own anchor; the rule must always name at
least one real method, because `tools/coverage-report.py` fails a gate that matches nothing.
