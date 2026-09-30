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
budget passed): each close runs on a short-lived daemon thread (`oidf-platform-close-<n>`, started through
[exec](#exec)'s `startDaemon`) and is waited for only until the budget runs
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

**The enable switches.** `ComponentSwitches` reads S-9's nine switches, `OIDF_<NAME>_ENABLED`, from platform's
`components` catalogue (`Settings.of("components")`), and gives each component a `Verdict`: `ENABLED` (`true`),
`DISABLED` (`false`), `INFERRED` (unset, and allowed to be) or `FAILED_CONFIG`. Unset is inferred in the development
profile; in production only while none of the component's presence settings (`ComponentSwitches.PRESENCE`) is set
in the environment and not blank, and `FAILED_CONFIG` otherwise, with a reason naming the switch. A value that does
not parse, and `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY` (the catalogued alias of `OIDF_ATTESTATION_AUTH_ENABLED`)
disagreeing with it, are `FAILED_CONFIG` too. The operator's view is
[docs/operator/components.md](../../docs/operator/components.md).

**The supervisor.** `Supervisor` starts a part that failed on a dependency again: the first wait is drawn uniformly
from zero to 5 s, and each later ceiling doubles to 300 s (full jitter, `Supervisor.backoff(failures, random)`).
Each attempt counts in `oidf_component_retries_total{component}`, then moves the part to `STARTING` and runs its
start function; the retries stop when the part leaves `FAILED_DEPENDENCY` or registers again. `FAILED_CONFIG` and
`REFUSED` are never retried. `Supervisor.shared()` schedules on one managed executor (`exec`) created on the first
retry, and only in the copy `Lifecycle.current().isWebapp()` marks as the webapp's: in any other copy `retry` answers
`false`, schedules nothing and starts no thread ([classloaders](../../docs/development/classloaders.md), rule 2).

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

## profile

`DeploymentProfile.current()` is this process's profile, read from `OIDF_DEPLOYMENT_PROFILE`: `development` -
trimmed, in any case - is `DEVELOPMENT`, and everything else is `PRODUCTION`, unset and blank included, so a typo
lands on the safe side. There is no third profile and no system property of the same meaning. Every module
reads the profile here (plan item PR-1): client-attestation's store and Redis client, attestation-issuer's
evidence policy, CIMD resolver and discovery document, rar-model, the RAR plugin and ciba-sim (both shade
platform). Two readings differ from the rule, each kept as it was and pinned by a test:

- rar-model's common-fields fallback takes exactly `development`, trimmed, lower case
  (`DeploymentProfile.isExactlyDevelopment`), so `Development` leaves it off - finding
  [F-0160](../../docs/findings/F-0160.yaml).
- The image's entrypoint (`is_development` in build/pingfederate/pf-entrypoint.sh) does not trim, so
  `" development"` is production there. `DeploymentProfileShellTest` runs one table through both and pins that
  difference - finding [F-0161](../../docs/findings/F-0161.yaml). The shell is the stricter side.

`AcceptedRisks` reads `OIDF_ACCEPTED_RISKS`: a comma-separated list of the ids below, each alone or as
`id@YYYY-MM-DD`, the last day (UTC) the acceptance holds. An entry is refused, and its risk not accepted, when
it is empty, names an unknown id, carries a date that is not `YYYY-MM-DD` or does not exist, has expired,
leaves out the date a dated risk needs, or names a risk twice (both go). Each refusal is a message naming the
entry, in `refusals()`. The ids are stable: one is never renamed or reused.

| Id | Dated | What accepting it lets happen | The switch PR-2 ties it to |
|---|---|---|---|
| `no-metadata-policy` | no | federation registration with no superior's metadata policy | `OIDF_REQUIRE_METADATA_POLICY=false` |
| `attester-binding-off` | no | a client whose bridge-key entry names no attesters is served | `OIDF_ATTESTATION_REQUIRE_ATTESTER_BINDING=false` |
| `registration-fail-open` | no | a registration goes ahead unnarrowed when its policy decision cannot be had | PR-2 names it |
| `expiry-log-mode` | yes | an expired registration is logged and still served | `OIDF_REGISTRATION_EXPIRY_ENFORCEMENT=log` |
| `pdp-fail-open` | no | a request goes ahead without the PDP's narrowing when the PDP cannot be reached | `OIDF_PDP_FAIL_OPEN=true`, and the RAR plugin's own switch |
| `pkce-off` | no | front-channel relying parties registered without requiring PKCE | `OIDF_AUTO_REGISTRATION_REQUIRE_PKCE=false` |
| `resolve-any` | no | the resolve endpoint resolves any entity for anyone | `OIDF_FEDERATION_RESOLVE_DISCOVERY=any` |
| `audit-off` | no | security events kept out of PingFederate's audit log | `OIDF_EVENTS_AUDIT=false` |
| `in-memory-state` | no | a store keeps its state in one node's memory (standalone only; forbidden when clustered) | decision 4; PR-2 names the stores |

The first eight are PR-2's list of accepted risks and the ninth is decision 4's in-memory state when
standalone; `expiry-log-mode` is dated because the plan says so. The switch column is where each id is meant
to go, from each module's documented settings on 2026-09-28; PR-2 wires them.

`ProfileGuard` asks the three questions a governed switch asks, each returning null when it is allowed and a
`Refusal` - the setting, and a message naming it and the reason - when it is not:

- `forbidInProduction(setting, on, reason)`: refused when on under production.
- `requireInProduction(setting, on, reason)`: refused when off under production.
- `requireRisk(setting, on, risk, reason)`: refused when on under production and the risk is not accepted.

Under development every answer is null. This is the mechanism only (PLAN.md decision 7): nothing asks these
questions yet and nothing is refused at run time. PR-2 (Phase 3) wires each governed switch, PR-5 turns a
refusal into a refused component, and until then the start-up audit (F-2) reports the profile, the accepted
risks and `refusals()`.

<!-- tls (PR-1): add this package's section below this line -->

## tls

`InsecureTls` is the only place a trust-all trust manager is built and the only place the JDK HTTP client's
hostname check is turned off (plan item PR-1, finding [F-0042](../../docs/findings/F-0042.yaml)).
`tools/trust-scan.py`, a step in build.yml's lint job, fails on any other Java main source that implements or
instantiates an `X509TrustManager` (or the extended one), builds a hostname verifier that returns true, sets the
endpoint identification algorithm to null or empty, or names the JVM property, and on start-up configuration
that sets the property; it exempts this class and the gm-api example, and says why. It is a regression lint over
those shapes, with CodeQL behind it: its docstring lists what it misses, including the rig's Python and shell
trust-alls.

- `trustAnyCertificate(builder, setting, insecureTls)` returns the `HttpClient.Builder` unchanged when
  `insecureTls` is false, and with a trust-all context when it is true. The first use for a setting name in a
  loader logs one WARN naming it.
- `disableJdkHostnameVerification(setting, disable)` sets `jdk.internal.httpclient.disableHostnameVerification`
  for the whole JVM. Only the harness calls it.
- `uses()` lists every setting that asked, with what for and when, for the start-up audit (F-2);
  `jdkHostnameVerificationDisabled()` reads the property as the JDK does, wherever it was set (F-0035).

It refuses nothing under the production profile. PR-2 (Phase 3) forbids ignore-TLS in every form, and the JVM
property, in production; until then the start-up audit reports each use.

What "trust-all" means here, because it is not what the switch names say. The context is handed only to
`java.net.http`, and the JDK's HTTP client sets the endpoint identification algorithm itself on every TLS
connection. In `jdk.internal.net.http.AbstractAsyncSSLConnection`, the same in JDK 17 and JDK 21 (read in the
17.0.11 `src.zip` and openjdk/jdk21u on 2026-09-28):

```java
if (!disableHostnameVerification)
    sslParameters.setEndpointIdentificationAlgorithm("HTTPS");
```

The trust manager is a plain `X509TrustManager`, which JSSE wraps and follows with that identity check
(`SSLContextImpl.chooseTrustManager` wraps any `X509TrustManager` that is not an `X509ExtendedTrustManager`,
and the wrapper checks the endpoint identity when an algorithm is set). So the chain is not checked, but the
certificate must name the host dialled - unless the JVM property is set, when nothing is. `InsecureTlsTest`
shows each case against self-signed certificates made for the run, and the same cases ran in the pinned
PingFederate image's JDK (OpenJDK 21.0.12.1, BellSoft) on 2026-09-28:

| Client | Certificate | JDK flag | Result |
|---|---|---|---|
| trust-all | self-signed, for `localhost` | unset | 200 |
| trust-all | self-signed, for `wrong.example` | unset | refused: `No subject alternative DNS name matching localhost found.` |
| default | self-signed, for `localhost` | unset | refused: `unable to find valid certification path to requested target` |
| trust-all | self-signed, for `wrong.example` | set | 200: nothing is checked (F-0035) |
| default | self-signed, for `wrong.example` | set | refused on the chain |

An `SSLSocket` (or `HttpsURLConnection`'s socket layer) given the same context and no endpoint identification
would check no name at all (`anSslSocketWithTheSameContextChecksNoName`), which is why the context is not handed
out. No site here uses one: `MiniRedisClient` builds its own `SSLSocket`, verifying, with the algorithm set.

Every site, with the semantics it had before and keeps:

| Site | Setting | What it trusts | Host name |
|---|---|---|---|
| oidf-jose `JdkHttpClient` (and `JdkHttpGetClient`) | `OIDF_FEDERATION_IGNORE_SSL_ERRORS` | any chain | checked; the null endpoint identification it used to set was overridden by the JDK and is gone |
| RAR plugin `JdkHttpTransport` | field "Skip TLS verification (dev only)", honoured only under development | any chain | checked |
| ssf `SetVerifier`, `PollReceiverClient`, `ReceiverStreamClient` | `OIDF_SSF_RECEIVER_INSECURE_TLS` (init-param `receiverInsecureTls`) | any chain | checked |
| ssf `PfIntrospectionReceiverAuthenticator` | `OIDF_SSF_INTROSPECTION_INSECURE_TLS` (init-param `introspectionInsecureTls`) | any chain | checked |
| device-enrolment `HostedEntityRegistrar` | `PF_AUTHORITY_INSECURE_TLS` | any chain | checked; as for oidf-jose |
| harness `AttestationFlowHarness` | `OIDF_HARNESS_INSECURE_TLS`, and the JVM property set on every run | any chain when the switch is on | never checked (F-0162) |
| gm-api `examples/java/GrantManagementClient.java` | `--insecure` | any chain | checked; exempt from the scan: a single-file example outside the reactor that cannot import platform (F-0163) |

Each site's test runs it against a certificate for the wrong name. The alternative this plan does not take: a
trusted CA bundle (`OIDF_*_CA_FILE`, as `OIDF_REDIS_CA_FILE` already is) in place of every ignore-TLS switch
would remove trust-all altogether, and this class with it. It changes what every rig and demo sets, so it is
breaking and belongs to PR-2.

CodeQL's `java/insecure-trustmanager` does not report `InsecureTls`, by its own library's rule (CodeQL 2.27.1 on
this change's pull request, 2026-09-28: no result - [U-0170](../../docs/findings/U-0170.yaml)): a sink is
an `SSLContext.init` whose trust managers flow from a class whose `checkServerTrusted` cannot throw, and it is
not a sink when "guarded by a flag that suggests an intentionally insecure use" - a guard on a boolean whose
name matches `(?i).*(secure|disable|selfCert|selfSign|validat|verif|trust|ignore|nocertificatecheck).*`
(`InsecureTrustManager.qll`, github/codeql main, read 2026-09-28). `trustAnyCertificate` calls `init` only
inside `if (insecureTls)`. What CodeQL reported on this change is in F-0042.

<!-- events (O-1): add this package's section below this line -->

## events

Events moved here from `libs/openid-federation` (plan item O-1): `Event`, the record - code, outcome, reason,
subject, partner, role, description, fields, request `jti`, audit, category and now component; `EventSink`, where
events go; `Events`, this loader's sink, the first `configure` winning; `LoggingSink`, one line per event in
server.log; and `LogSafe`, which digests anything shaped like a JWT, replaces control characters and caps a value's
length. The privacy rule moved with them: `instance_subject` and `spiffe_id` are never recorded beside `agent_id`.
openid-federation keeps façades over these until O-2 (Phase 3) moves the emitters.

**Catalogues are data.** Each module that declares event codes ships `META-INF/oidf-events/<component>.json`, one
per component, and lists its components in `META-INF/oidf-events/index.txt`. A catalogue names its component, its
module, the logger its events are written on (the category is appended) and the audit log's `protocol` for them;
gives every field one `PiiClass`; and gives every code a description, `audit`, `outcomes`, `level` (`debug` or
`info`), the fields it may carry and `declaredOnly`. `audit` records the emitters' choice - an emitter still marks
an event audit itself - and the scan below holds the two equal. `EventCatalogue.parse` refuses an unknown or missing member, a
name outside its rule, a field an event carries that the catalogue does not classify, and a classified field no
event carries. `EventCatalogues.load` reads every index a loader can see, each catalogue from its index's own jar;
the same document seen twice (a module in the war and on the engine's classpath) is read once, and a second,
different document for a component, or a code two components declare, is set aside and logged at ERROR. Today's
catalogues: `federation` in libs/openid-federation, `attestation-issuer` in servlets/attestation-issuer.

**Nothing uncatalogued reaches a log.** `Events.emit` admits every event through the catalogues before any sink
sees it (`admit`), and `LoggingSink` and platform-pf's audit sink apply the same rule again without counting
(`readmit`; readmitting an admitted event changes nothing): the event's component becomes the catalogue's that
declares its code, and a field that code does not declare is dropped. `Events.emit` counts each event once:
`droppedFields()` the fields dropped, `uncataloguedEvents()` the events whose code no catalogue declares, which keep
their head and lose every field. The first drop of each code and field is a WARN line naming the field, never its
value. O4 (plan item O-4) turns the counts into metrics.

**The PII policy.** `PiiPolicy` says, for server.log and for PingFederate's audit log, what happens to each class:
kept, replaced by `sha256:` and twelve hex digits, or dropped. The subject and partner are `PSEUDONYMOUS_ID`; the
reason, role and request `jti` are operational and never removed. The description is free text with no class and
its own treatment per log (`withDescription`): emitters put in it an administrator's free-text `reason`, an external
policy decision point's `reason_admin`, exception messages, and client ids and key thumbprints (checked 2026-09-28),
so it can carry a value of any class, a person's name included, and a policy that digests or drops a class must set
the description's treatment too (finding [F-0166](../../docs/findings/F-0166.yaml)). `PiiPolicy.DEFAULT` keeps every
class and the description in both logs, which is what reached them before the catalogues (checked 2026-09-28 against
the emitters):

| Class | What it holds | server.log | audit log |
|---|---|---|---|
| `OPERATIONAL` | modes, counts, endpoint names, decisions, times | kept | kept |
| `PSEUDONYMOUS_ID` | client ids, entity identifiers, key ids, a workload's subject; the subject and partner | kept | kept (the subject and connection columns) |
| `DIRECT_ID` | can name a person: `actor`'s self-declared name from `X-Federation-Actor` | kept - finding [F-0165](../../docs/findings/F-0165.yaml) | kept |
| `NETWORK` | addresses and host names; no field today, but platform-pf's audit sink writes the caller's address in the audit log's `ip` column under this class | kept | kept |
| `CREDENTIAL_DIGEST` | key thumbprints, evidence digests | kept | kept |

An unkeyed digest of a guessable value can be reversed by guessing, so `DIGEST` hides a direct identifier from a
casual reader of server.log, not from a determined one; whether to use it, or a keyed pseudonym, is the PII policy
of plan item D-6 (Phase 7).

`LoggingSink` writes on the catalogue's logger and the event's category
(`com.pingidentity.ps.oidf.federation.event.registration`, as before): at DEBUG for a code the catalogue marks
`debug`, at WARN for a failure marked audit, otherwise at INFO. It writes through `PlatformLog.get(String)` - the
one line this package adds outside its own subpackage, a logger by name beside the logger by class. An
uncatalogued code is written on `LoggingSink.FALLBACK_LOGGER`, the federation prefix, as it was.
`EventsCataloguedTest` in servlets/pf-integration holds the emitters to the catalogues (see
libs/openid-federation's README). Seen on the rig on 2026-09-28 (PingFederate 13.1.3): an event line through
`PlatformLog` reached server.log at WARN on `com.pingidentity.ps.oidf.federation.event.client`, through
commons-logging and log4j, not as `[SystemErr]`.

<!-- metrics (O-3): add this package's section below this line -->
## metrics

`Metrics.counter`, `Metrics.timer` and `Metrics.gauge` register a metric in this loader's `MetricRegistry`, once,
with a name, a one-line help text and fixed labels, and return the handle the code counts through:

```java
private static final Counter DECISIONS = Metrics.counter("oidf_attestation_decisions_total",
        "Client attestation decisions at the token endpoint", Label.oneOf("outcome", "accepted", "refused"));

DECISIONS.inc("refused");
```

Names start `oidf_`; a counter's ends `_total` and a timer's `_seconds`, and a gauge's ends in none of `_total`,
`_count`, `_sum`, `_bucket` and `_max`, so no rendered line of one metric can take another's name. Registering a
name again with the same kind and labels returns the first metric (a servlet initialised twice counts into the
same one); another kind or other labels, a bad name, help or label is an `IllegalArgumentException`, because
these are constants and the caller's tests should find them. Passing the wrong number of label values is the same.

### Bounded labels

Every label is bounded, so no sequence of calls can grow the registry without bound:

| What | Bound | Past it |
|---|---|---|
| A label's values | `Label.oneOf(name, values...)`: a declared set; `Label.capped(name, max)`: the first `max` distinct values (1-1024) | the value is counted as `other`, and `oidf_metrics_label_folds_total{metric="..."}` rises |
| A value | 1-128 characters, no control character | counted as `other` (so is `null`) |
| One metric's series | the product of each label's values plus `other`, at most 2048 | refused at registration (`IllegalArgumentException`) |
| Metrics in a registry | 256 | the registration is refused: the caller gets a metric that counts and is never shown, `oidf_metrics_refused_total` rises, and the log says so the 1st, 2nd, 4th, 8th... time |
| Series in a registry | 16384, reserved at registration from each metric's own bound | the same |

`other` is always kept and never takes a place under a cap. `MetricRegistryTest` passes 100,000 distinct values
through a capped label and a declared one, and 100,000 distinct names through the registry, and shows each
stops at its bound. A capped label is for values that come from data, such as a client id; where a set can be
declared - an outcome, an event code - declare it.

A cap keeps the first values it sees for the life of the copy, so feed a capped label only values that have
already been checked - an authenticated client's id, not the `client_id` parameter of a request that has not yet
authenticated. Otherwise anyone can spend the cap on junk early and every real client counts as `other` until the
next restart; the fold counter shows it happened but cannot undo it. Never use a direct identifier of a person (a
subject, an e-mail address) or anything derived from a credential as a label value: the MXBean and O-5's endpoint
show every value.

### Timers and gauges

A timer keeps a count, a sum, a max and fixed buckets. The buckets are the same for every timer, so O-5's
Prometheus text has one set of `le` values and any two timers compare: 1 ms, 2.5 ms, 5 ms, 10 ms, 25 ms, 50 ms,
100 ms, 250 ms, 500 ms, 1 s, 2.5 s, 5 s, 10 s, 30 s and 60 s (`Timer.BUCKETS_SECONDS`), then `+Inf`. The low end
is for decisions made in process - an OGNL criterion, a signature check - the middle for database, Redis and
federation calls, and 30 s and 60 s for background runs such as the registration sweeper's. A recording lands in
the first bucket whose bound it does not exceed, as Prometheus's `le` means. The count is the sum of the buckets,
so `_count` always equals the `+Inf` bucket. The max is the longest recording since the copy was loaded, not over
a window. A recording longer than a day counts as a day in the sum and the max (it is in `+Inf` either way), and a
`Duration` too long for nanoseconds counts as a day too, so a stray value cannot throw or send the sum negative. Changing the buckets changes every histogram's series and breaks dashboards built on them, so it is a
"Before you deploy" item whenever it happens.

A gauge reads a supplier when the metrics are read - a snapshot, the MXBean, O-5's endpoint - never on the hot
path; binding a new supplier to a series replaces the old one. A supplier that throws, or fails to link, reads
as `NaN`, so it cannot break the reader.

### What O-5 renders

`MetricRegistry.snapshot()` returns every metric as a `MetricSnapshot` - name, help, kind, label names and its
series, ordered by name and then by label values - with the registry's own two among them. Each `SeriesSnapshot`
carries what its line needs and nothing left to compute: a counter's count, a gauge's value, a timer's count, sum
and max in seconds and its buckets, already cumulative and aligned to `Timer.BUCKETS_SECONDS` with `+Inf` last.
O-5 writes `# HELP` and `# TYPE`, a counter as `counter`, a gauge as `gauge`, and a timer as a `histogram`
(`_bucket{le=...}`, `_sum`, `_count`) plus a `gauge` named `<name>_max`. `Samples.escape` escapes a label value
as the text format requires.

### One MXBean per loaded copy

Each copy of platform (see [classloaders](../../docs/development/classloaders.md)) has its own registry and
registers one MXBean, the first time a metric is registered in it or when `Metrics.registerMXBean()` is called -
F-2's listener calls it for the webapp. It is registered in the JVM's platform MBean server as
`com.pingidentity.ps.oidf:type=Metrics,copy="<package> from <where it was loaded from>"`. The package tells a
plugin's relocated copy from the others, and the place tells the webapp's copy (`pf-runtime.war`'s
`WEB-INF/lib`), the engine's (`server/default/deploy`) and another war's (`oidf.war`'s or `gm-api.war`'s
`WEB-INF/lib`) apart. Two copies from the same place - two loaders over one jar - would clash, so a taken name is retried as `... #2`,
`#3` and so on, up to 16: neither registration fails the other. A registration that fails for any other reason
is logged once and not retried; the metrics count without it. `ClassLoaderCopiesTest` loads platform twice in
one JVM through two `URLClassLoader`s over the same classes, and shows two names, two registries, and each
copy's shutdown removing only its own MXBean.

The MXBean's attributes are open types: the copy, its loader role (`WEBAPP` once F-2 has marked it), the counts
of metrics, series, folds and refusals, the bucket bounds, every `MetricSnapshot` as `CompositeData`, and a flat
`Samples` table keyed as a Prometheus line names each sample (`oidf_x_total{outcome="refused"}`), which a JMX
console shows as it is. A reader in another loader can rebuild the snapshots through `JMX.newMXBeanProxy`.

Unregistering goes through platform.lifecycle: the registration hands this copy's `Lifecycle` a close that
unregisters the MXBean, and a copy whose lifecycle has shut down registers none again. F-2's listener runs the
lifecycle's shutdown when the war that holds it - `pf-runtime.war`, `oidf.war` or `gm-api.war` - is undeployed,
which removes that copy's MXBean and with it the MBean server's reference to that war's loader. Nothing runs the engine's copy's lifecycle - no
servlet `init` or `destroy` runs for jars in `server/default/deploy` - so its MXBean stays until the JVM stops,
and that is what is wanted: the OGNL issuance criteria and access-token mappings run in the engine's copy, and
their decisions are security decisions that have to stay visible. The MBean server's reference would keep that
loader reachable if PingFederate ever discarded it without a restart; nothing seen so far does, and the rig check
in U-0180 includes it. A plugin's relocated copy is the same. Until F-2 lands nothing shuts any copy's lifecycle down, and until O-4 and C-3 nothing
registers a metric, so no MXBean appears yet.

O-5's endpoint is served by the webapp and can read the engine's copy only through the MBean server, which
[classloaders](../../docs/development/classloaders.md) rule 4 does not list as a channel between loaders; finding
[F-0170](../../docs/findings/F-0170.yaml) records that O-5 has to add it there or render each copy on its own.
What the rig shows is [U-0180](../../docs/findings/U-0180.yaml).

### Cost

The hot path takes no lock once a value is known: a lookup per label and one for the series in
`ConcurrentHashMap`s, then a `LongAdder` increment (for a timer, one bucket's `LongAdder`, the sum's and a
`LongAccumulator` for the max). A lock is taken only to admit a new value under a cap, at most the cap's number
of times per label, and inside `computeIfAbsent` to create a series, at most once per series. Measured on
2026-09-28 on this Mac (12 cores; JDK 17.0.11 and 20.0.2 alike, a plain loop of 20 million calls after two
warm-up rounds, not JMH): about 6 ns for an increment with no labels, 30 ns with one declared label, 45 ns with
a capped label and a declared one, 32-35 ns for a timer with one label, and 30-36 ns per call with eight threads
on the same series. Label values are passed as varargs, so each call allocates the array and the series key.

### Counting events (for O-4)

Every catalogued event counts itself in the copy that emits it. O-4 registers one counter, once per loader,
after platform.events has read every catalogue that loader sees:

```java
Metrics.counter("oidf_events_total", "Events emitted, by catalogued code and outcome",
        Label.oneOf("code", <every code in the catalogues>), Label.oneOf("outcome", <every outcome they declare>));
```

and platform.events calls `inc(code, outcome)` for each event it accepts, before any sink runs, so a sink that
fails still leaves the event counted. The catalogue is the label's declared set, so an uncatalogued code or
outcome counts as `other` and raises the fold counter, which is how an emitter that has drifted from its
catalogue shows up. The series bound is (codes + 1) x (outcomes + 1) and must stay within 2048; if a catalogue
ever outgrows that, the counter splits by component (`oidf_<component>_events_total`), not by a looser label.
An event the engine's copy emits - from an OGNL criterion - is counted in the engine's registry, which is why that
copy's MXBean stays registered.

<!-- health (O-4): add this package's section below this line -->
## health

What the health endpoints decide (plan item O-4), with no servlet API; platform-pf's `HealthServlet` serves it
([libs/platform-pf, health](../platform-pf/README.md#health)).

**Components and their parts.** One S-9 component can be served by more than one class - automatic registration
by a filter at the token endpoint and another at the authorization and PAR endpoints - and `ComponentRegistry`
holds one state per name, retiring the earlier handle when a name registers again. So a servlet or filter
registers a *part* from its `init`, through `Startup.begin(component, part)`, and `ComponentParts` publishes the
component's state to the registry: the worst state among its enabled parts, `DISABLED` when none is enabled.
Worst first: `FAILED_CONFIG`, `REFUSED`, `FAILED_DEPENDENCY`, `STARTING`, `DEGRADED`, `READY`. The reason is each
part in that state as `part: reason`, joined with `; `. `Startup` holds S-9's nine names as constants and this
loader's `ComponentParts`; statics are per loader, and nothing in the engine's copy runs an `init`, so the engine's
registry stays empty ([classloaders](../../docs/development/classloaders.md), rule 1).

A part starts `STARTING`. Its `init` hands the part its start function and returns, whatever happened:

```java
this.part = Startup.begin(Startup.AUTO_REGISTRATION, "TokenEndpointAutoRegistrationFilter");
this.part.start(() -> {
    ... what init did, with part.notConfigured(what) where its settings are absent,
    part.failedConfig(reason) where it refuses, and a throw for anything else ...
});
```

`start` reads the component's switch first: `false` makes the part `DISABLED` and its start never runs, a switch
verdict of `FAILED_CONFIG` records that and never runs it either. Otherwise it runs the start function and records
the outcome, and never throws. What the function throws is `FAILED_DEPENDENCY` when the exception or one of its
causes (16 at most, never round a cycle) is an `IOException`, `UncheckedIOException`, `SQLException`,
`TimeoutException` or `LinkageError` (a jar missing where it runs), and `FAILED_CONFIG` for anything else
(`ComponentParts.stateFor`); the reason is the message, with the deepest cause's when it says something the message
does not, and the stack goes to the log. A function that returns leaves a part still starting `READY`.
`notConfigured(what)` is the part's "my settings are absent": `DISABLED` when the switch is unset (as before the
switches), `FAILED_CONFIG` naming the switch when it is `true`. A part that ends in `FAILED_DEPENDENCY` goes to the
supervisor (above), which runs the same function again. A disabled part stays disabled, and registering a part
again (a second `init`) starts it afresh and retires the earlier handle. A reason is cut to one line of 256
characters, as the registry cuts it.

The pull probe stays for a part that prefers it: one whose dependency something else keeps retrying - the SSF
transmitter's boot retry - passes a check with `failedDependency(reason, probe)`, the supervisor leaves it alone,
and `ComponentParts.refresh()`, which health calls before it reads, makes the part ready once the check returns.

Each request method of a part's servlet or filter starts with platform-pf's `ComponentGate`
([libs/platform-pf, component](../platform-pf/README.md#component)), which answers for the surface while its part is
starting or failed, or its component has a part refused.

**Which class serves which component**, and what an unset switch infers from the configuration (in development
always, in production while none of the component's settings is set):

| Component | Part (class) | Enabled | Starts |
|---|---|---|---|
| `FEDERATION` | `OpenIdFederationServlet` | always | at deploy |
| `FEDERATION` | `OpenIdRegistrationServlet` (explicit registration, a federation endpoint) | always | at deploy |
| `AUTO_REGISTRATION` | `TokenEndpointAutoRegistrationFilter` | always; `FAILED_CONFIG` while the anchor's keys are not pinned | at deploy |
| `AUTO_REGISTRATION` | `FrontChannelAutoRegistrationFilter` | unless `OIDF_AUTO_REGISTRATION_FRONT_CHANNEL=false`; `FAILED_CONFIG` while the keys are not pinned | at deploy |
| `ATTESTATION_AUTH` | `ClientAttestationAuthFilter` | unless `OIDF_ATTESTATION_AUTH_ENABLED=false` (or its superseded alias `OIDF_ATTESTATION_REQUIRE_BRIDGE_KEY=false`, whether or not bridge signing is configured); `FAILED_CONFIG` when on or inferred with no bridge signing; `DEGRADED` while the keys are not pinned | at deploy |
| `ATTESTATION_ISSUER` | `AttestationIssuanceServlet` | always | at deploy |
| `HOSTING` | `HostedEntityServlet` | when an authority entity id is set | at deploy |
| `SSF` | `SsfConfigurationServlet` | when the transmitter's settings parse (an issuer is set) | at deploy |
| `SSF_RECEIVER` | `SsfReceiverServlet` | when SSF is and a receiver issuer is set | first request |
| `OPERATOR_API` | `FederationAdminServlet` | when `OIDF_AUTHORITY_ADMIN_TOKEN` is set | at deploy |
| `FAPI` | `Fapi2ProfileFilter` | when `OIDF_FAPI2_CLIENTS` names a client | at deploy |

The SSF states are read after `SsfHttp.bootstrap`, which never throws, by servlets/ssf's `SsfComponents`, and the
SSF switches change nothing until ST-5 moves that start-up onto the parts. Every other part starts at deploy
(finding [F-0193](../../docs/findings/F-0193.yaml), closed by S9a); `SsfReceiverServlet` still starts on its path's
first request and is absent from readiness until then. A transmitter setting that does not parse reads as SSF not configured,
as the bootstrap reads it (F-0191).

**Readiness.** `Health.readiness` is `DOWN` when an enabled component is neither `READY` nor `DEGRADED` - starting,
failed or refused - and `UP` otherwise, disabled components and no components at all included. `DEGRADED` counts
as ready, per S-9: a dependency blip must not eject every node at once. Liveness is always `UP`. `Health.status`
is the whole body of both, `{"status":"UP"}`; `Health.detail` is the document only an authorised caller sees:
the status, the deployment profile, the versions and every component with its state, reason, the time it entered
the state and its parts. A PingFederate that names a trust controller before its anchor's keys are pinned is
therefore not ready (finding [F-0192](../../docs/findings/F-0192.yaml)).

**Every event counts itself.** `Events.emit` counts each event it admits in `oidf_events_total{code,outcome}`
(`EventMetrics`, the one class this package adds to platform.events) before any sink runs, as the metrics section
above describes: both labels are declared sets taken from the catalogues this loader reads, so an uncatalogued code
counts as `other` and raises the fold counter, and the counter is registered once per loader on the first event -
in the engine's registry for an event an OGNL criterion emits. With today's two catalogues that is 41 codes and two
outcomes, 126 series. Two gauges read the catalogues' own counts: `oidf_events_dropped_fields` and
`oidf_events_uncatalogued`. A registration the registry refuses is logged once and the events go uncounted;
counting never fails an event.

<!-- redis (C-2): add this package's section below this line -->

## redis

`RedisClient` is the platform's Redis client (plan item C-2): 0.4.0's `MiniRedisClient` from client-attestation,
moved here with S3a's rules unchanged and a bounded pool, a deadline on every command, key prefixes, the commands
leases and rate limits need, and Sentinel added. It speaks RESP itself, so no Redis library reaches PingFederate's
loaders. client-attestation's stores are its first user; X-D01's replay store and C-4's leases are the next. The
plan's X-A02 ("Absorbs X-A02", under C-2) is defined nowhere else in the plan; this package takes it as absorbed.

**What 0.4.0 did, and still does.** A URL is `redis://[user[:password]@]host[:port][/db]` or `rediss://`.
`rediss://` verifies the server as a browser does - the chain, to the JVM's CAs or the PEM file
`OIDF_REDIS_CA_FILE` names; the name, by the HTTPS endpoint identification algorithm; the host as SNI - and
completes the handshake before `AUTH` is written. Under the production profile `redis://` is refused, the
decision `ProfileGuard.forbidInProduction` makes and the message 0.4.0 wrote. No message quotes a URL's userinfo.
One thing is kept that should not be: the userinfo is decoded twice, so a `+` in a password is a space
([F-0180](../../docs/findings/F-0180.yaml)). Nothing connects until the first command.

**The pool and the deadlines.** At most `OIDF_REDIS_POOL_SIZE` connections are open at once, in use or idle (0.4.0
opened as many as the load asked for and kept four). A command waits up to `OIDF_REDIS_BORROW_TIMEOUT_MS` for one,
and then has `OIDF_REDIS_COMMAND_TIMEOUT_MS` for everything else: connecting, the handshake, `AUTH` and `SELECT`,
finding the master, the command and the one retry. Each read waits only what is left of that; a command's own
bytes are written untimed, since they fit a socket's send buffer ([F-0181](../../docs/findings/F-0181.yaml)). An
exhausted pool, a deadline passed and a
closed client are an `IOException`, which the stores answer as `STORE_UNAVAILABLE` - the same 503 as a Redis that
is down. An error reply is a `RedisErrorReply` (an `IllegalStateException`, as 0.4.0 threw) and is not retried. A
command that fails on a reused connection is retried once on a fresh one, as 0.4.0 did, because the server may
have closed an idle connection. That retry can run a command twice when the first one ran and only its reply was
lost - a `SET NX` then answers "already set" and a `DEL` "nothing deleted", a verdict rather than an outage -
exactly as 0.4.0's could; nothing else is retried after a command was sent. A reply past 64 KiB for a line, 64 MiB for a bulk string or a million array
elements is a protocol failure, not an allocation.

**Key prefixes.** `client.keyspace("oidf:as")` is a `RedisKeyspace`: every key it is given becomes
`oidf:as:<key>`. client-attestation's four namespaces are keyspaces over one client, and write byte for byte the
keys 0.4.0 wrote - `oidf:as:*`, `oidf:cas:*`, `oidf:fed:endpoint:*`, `oidf:admin:dpop:*` - so a rolling upgrade
from 0.4.0 finds the challenges and spent proofs the old nodes recorded. `RedisClientTest` and client-attestation's
`RedisAttestationStoreTest` write keys the 0.4.0 way and find them.

**The commands.** `set` and `setIfAbsent` (`SET ... [NX] PX`), `get`, `del`, `incr`, `pexpire`, and `eval`, which
sends a `RedisScript` by its SHA-1 (`EVALSHA`) and by its source (`EVAL`) when Redis answers `NOSCRIPT` - after a
restart or a `SCRIPT FLUSH`. Three scripts are built in: `compareAndDelete` and `compareAndExtend`, which release
and renew a lease only while it still holds the caller's token (C-4), and `countInWindow`, a fixed-window counter
for rate limits (X-A11) that increments and, when the key has no TTL, sets the window's, in one atomic step, so a
counter never lives without one. It answers the count and the time the window has left.

**Sentinel.** With `OIDF_REDIS_SENTINEL_MASTER` and `OIDF_REDIS_SENTINELS` set, the client asks each sentinel in
turn `SENTINEL get-master-addr-by-name`, connects where the first answer says, and checks with `ROLE` that the
server is the master. Each sentinel gets an equal share of what is left of the command's deadline - of 3000 ms and
two sentinels, the first has 1500 - so one that accepts and never answers, or whose host drops packets, leaves the
rest time to answer; the sentinel that answered is asked first next time. It asks again when a connection to the
master is lost, or the master answers `READONLY` - it has become a replica, so a failover has happened. The
command is retried once on the new master, within the same deadline, after `READONLY` (which refused it) or when
no connection to the master could be opened (so nothing was sent); a new connection lost after the command was
sent is an outage, not a retry, because the command may have run. Losing the master closes every connection to it: those idle at once, those in use when they come
back. The URL still says `redis` or `rediss`, the password and the database; its host is not dialled. Over TLS
the sentinels are verified against their own names, with the same CA file. The master is verified against the
name a sentinel gave for it, or, when it gave an address - what Sentinel does unless `announce-hostnames` is on -
against the URL's host, which every node's certificate must then carry
([U-0190](../../docs/findings/U-0190.yaml): C-6's reference cluster settles which). The sentinels are trusted to
say where the master is: a name one gives is checked as itself, so with the JVM's CAs any server holding a public
certificate for that name would be sent `AUTH`. Over TLS with Sentinel, set `OIDF_REDIS_CA_FILE` to the
deployment's own CA, and give the sentinels a password. One thread asks the sentinels while others wait for its
answer, each for at most its own deadline.

| Setting | Default | What it does | When it's wrong |
|---|---|---|---|
| `oidf.redis.url`, then `OIDF_REDIS_URL`, then `REDIS_URL` | unset | The Redis; unset keeps each store in one node's memory | A URL that does not parse, another scheme, or `redis://` under the production profile: every store that would use Redis refuses its requests, the message without the password |
| `OIDF_REDIS_CA_FILE` (`oidf.redis.ca.file`) | the JVM's CAs | A PEM file of CA certificates to trust for `rediss://` | Unreadable or holding no certificate: refused, naming the file |
| `OIDF_REDIS_POOL_SIZE` (`oidf.redis.pool.size`) | 8 | The most connections open at once | Not a whole number from 1 to 256: refused |
| `OIDF_REDIS_BORROW_TIMEOUT_MS` (`oidf.redis.borrow.timeout.ms`) | 1000 | How long a command waits for a free connection | Not from 1 to 60000: refused |
| `OIDF_REDIS_COMMAND_TIMEOUT_MS` (`oidf.redis.command.timeout.ms`) | 3000, 0.4.0's socket timeout | How long a command may take once it has a connection | Not from 1 to 60000: refused |
| `OIDF_REDIS_SENTINEL_MASTER` (`oidf.redis.sentinel.master`) | unset | The master's name in Sentinel | Set without `OIDF_REDIS_SENTINELS`, or the other way round: refused |
| `OIDF_REDIS_SENTINELS` (`oidf.redis.sentinels`) | unset | `host[:port]` of each sentinel, port 26379 when left out, IPv6 in brackets | An entry that is not host or host:port: refused, naming it |
| `OIDF_REDIS_SENTINEL_PASSWORD` (or `_FILE`) | unset | What the sentinels ask for in `AUTH` | Not checked until the sentinels refuse it; every command then fails as an outage |

The catalogue is `src/main/resources/META-INF/oidf-settings/platform-redis.json` ([format](../../docs/development/settings-catalogue.md));
`RedisConfig.current()` reads it from the process, and `RedisConfig.builder` makes a configuration in code.
"Refused" means the first request that needs Redis fails, and every later one, with the message logged once.

**Tests.** `RedisClientTest` and `RedisSentinelTest` run against `FakeRedis`, an in-process RESP server that can be
a master, a replica or a sentinel and stages what real servers do badly: silence, a dropped connection, a reply
cut off or malformed. `RedisClientTlsTest` checks the TLS rules with certificates `keytool` makes for the run.
`RedisLiveTest` runs the commands and the scripts - which the fake only emulates - against a real Redis, with the
variables client-attestation's live test reads (`OIDF_TEST_REDIS_URL`, `OIDF_TEST_REDIS_TLS_URL`,
`OIDF_TEST_REDIS_CA_FILE`), so build.yml's java job runs it. Its Sentinel test needs a Sentinel, which CI does not
start; locally, a master, a replica and one sentinel sharing one network namespace so the sentinel reports an
address the host can reach:

```sh
docker run -d --rm --name s-master -p 127.0.0.1:56390:56390 -p 127.0.0.1:56391:56391 -p 127.0.0.1:26390:26390 \
  redis:7-alpine redis-server --port 56390 --requirepass pw --masterauth pw
docker run -d --rm --name s-replica --network container:s-master redis:7-alpine \
  redis-server --port 56391 --replicaof 127.0.0.1 56390 --requirepass pw --masterauth pw
docker run -d --rm --name s-sentinel --network container:s-master redis:7-alpine sh -c \
  'printf "port 26390\nsentinel monitor mymaster 127.0.0.1 56390 1\nsentinel auth-pass mymaster pw\n" > /tmp/s.conf && exec redis-sentinel /tmp/s.conf'
OIDF_TEST_REDIS_SENTINELS=127.0.0.1:26390 OIDF_TEST_REDIS_SENTINEL_MASTER=mymaster \
OIDF_TEST_REDIS_SENTINEL_URL=redis://:pw@127.0.0.1:6379 OIDF_TEST_REDIS_SENTINEL_FAILOVER=true \
  mvn -o -pl libs/platform verify -Dtest=RedisLiveTest
```

With `OIDF_TEST_REDIS_SENTINEL_FAILOVER=true` the test asks the sentinel for a failover and follows the master to
its new port. On 2026-09-28 (redis:7-alpine, JDK 17.0.11) it did, in 11.5 s, most of it Sentinel's own switch.
The in-process tests also ran on the pinned PingFederate image's JDK (OpenJDK 21.0.12.1) that day, the TLS ones
included.

<!-- http (S5a): add this package's section below this line -->
## http

Outbound HTTP that connects only to an address it checked (plan item S5a; findings
[F-0010](../../docs/findings/F-0010.yaml), open until S5d moves the call sites that bypass it, and
[F-0070](../../docs/findings/F-0070.yaml), closed when S5AR moved oidf-jose onto it). oidf-jose's `JdkHttpClient`, and
so every federation fetch, entity statement, JWKS, trust mark status and AuthZEN PDP call made through it, sends here.

- `Deadline`: an absolute point on the monotonic clock; `remaining()`, `expired()`, `sooner(duration)`, `min`.
- `Budget`: a deadline and a request count; `spend(what)` takes one request and returns the deadline to make it
  by, and a `child` spends its parent too and ends no later than it. S5b threads one through the validator.
- `AddressPolicy`: the URL and address rules, and the one place a host is resolved. `check(url)` returns a
  `Target` holding every address the host resolved to, each checked.
- `OutboundHttp`: `send(request, deadline)` or `send(request, budget)`; GET, POST, PUT, PATCH and DELETE,
  headers on every method, HTTP/1.1, one request per connection, no redirects. A response of any status is
  returned; only a missing response throws `OutboundHttpException`, whose `reason()` says why
  (`REFUSED_URL`, `REFUSED_ADDRESS`, `UNRESOLVED`, `CONNECT_TIMEOUT`, `TLS`, `HEADER_TIMEOUT`, `DEADLINE`,
  `BODY_TOO_LARGE`, `MALFORMED_RESPONSE` and the rest).
- `TlsTrust`: the JVM's trust, a supplied `SSLContext`, a CA bundle (`caBundle(path)`), or
  `insecureIf(setting, insecure)`, which takes `InsecureTls`'s trust-all when the setting asks.
- `Bulkhead`: limits how many requests to one origin run at once; `Bulkhead.NONE` lets everything in, and
  `HostBulkhead` (below) gives each origin so many places.

### Why not java.net.http

The JDK's client cannot be pinned to an address. It resolves the host itself when it builds the connection's
address - `new InetSocketAddress(host, port)` in `jdk.internal.net.http.HttpRequestImpl.getAddress`
(JDK 17.0.11's `src.zip` line 390, openjdk/jdk21u line 404, both read 2026-09-28) - and `HttpClient.Builder` has no
resolver (`javap` of the pinned image's java 21.0.12.1: `cookieHandler`, `connectTimeout`, `sslContext`,
`sslParameters`, `executor`, `followRedirects`, `version`, `priority`, `proxy`, `authenticator`, `localAddress`,
`build`). The only resolver hook, JEP 418's `InetAddressResolverProvider` (JDK 18 on), is JVM-wide and loaded from
the system class path: not something a webapp inside PingFederate can or should install. Pointing the client at
the checked address instead loses the name: `AbstractAsyncSSLConnection` sets SNI only `if
(!serverName.isLiteral())` (line 124 in both), and endpoint identification then checks the certificate against
the address. Setting `Host` needs the JVM-wide `jdk.httpclient.allowRestrictedHeaders` (`Utils`, which lists
`host` among the disallowed headers). And its `HttpRequest.timeout()` ends at the headers, which is F-0010.

### Why HttpCore 5, and not httpclient5 or Jetty

Plan decision 2, as amended on 2026-09-27, asks for a maintained client with a resolver hook before a hand-written
one. What was weighed (read 2026-09-28):

| | Pins? | Total deadline over the body | Threads | Runtime dependencies |
|---|---|---|---|---|
| Apache httpclient5 5.6.4 (classic) | yes: `DnsResolver` resolves once and the socket connects to what it returned, then TLS is layered with the host name (`DefaultHttpClientConnectionOperator`, lines 202, 219 and 263) | no: a per-read socket timeout (line 264), so a peer sending a byte before each timeout holds it forever | none in classic | httpcore5, httpcore5-h2, slf4j-api |
| Jetty `HttpClient` 12 | yes: `SocketAddressResolver` | yes, `Request.timeout` | its own thread pool and scheduler, outside `platform.exec` (C-3) | jetty-http, -io, -util, slf4j-api |
| HttpCore 5.4.4 classic I/O alone | yes, by construction: we open the socket | yes: every read is bounded (below) | none | none |

httpclient5 would pin, but its deadline is per read, and it brings SLF4J, which relocated has no binding and
unrelocated meets PingFederate's. Jetty's client brings threads C-3 would have to own and a larger footprint, and
PingFederate runs on Jetty 12.0.36.1 itself (`/opt/server/lib`). HttpCore is the HTTP/1.1 message layer
httpclient5 is built on - the request writer, the status-line and header parser, and the chunked,
length-delimited and close-delimited decoders - and platform uses exactly that and nothing else: it opens the
socket, layers TLS and hands the socket to HttpCore's `DefaultBHttpClientConnection`. HttpCore is an OSS-Fuzz
project (`projects/httpcomponents-core`, read 2026-09-28), but its fuzzer builds requests and does not reach the
response parser, so `OutboundHttpFuzzTest` fuzzes the response path here.

HttpCore 5.4.4 (Apache License 2.0, no runtime dependencies, 955 KB) is shaded into this jar and relocated under
`com.pingidentity.ps.oidf.platform.http.internal.hc5`, minimised to the 166 classes platform reaches: the jar
grows from 227 KB to 448 KB, and `jdeps --missing-deps` finds nothing missing in it beyond commons-logging, which
was already provided (2026-09-28). HttpCore's LICENSE and NOTICE travel in the jar's `META-INF`. The pinned image
ships its own httpcore5 5.3.4, httpcore5-h2 5.3.4, httpclient5 5.5, httpclient 4.5.13 and httpcore 4.4.16 in
`server/default/lib` (read from each jar's manifest, 2026-09-28); the relocation keeps them apart. A plugin that
shades platform relocates `com.pingidentity.ps.oidf.platform.` and so carries HttpCore along under its own
package. The dependency is optional in `pom.xml`, so no consumer inherits an unrelocated copy; the cost is that a
module in the reactor that uses `platform.http` in a phase before `package` sees platform's classes without
HttpCore, so S5AR's tests run under `verify`, as CI's do.

### The transport

1. `AddressPolicy.check` resolves the host once and checks every address; one non-public address refuses the
   name, because a connection may go to any of them.
2. A socket made with `Proxy.NO_PROXY` connects to the first checked address that accepts before the connect
   deadline, then the next. Nothing resolves the name again: the host only travels on as text.
3. For `https`, `SSLSocketFactory.createSocket(socket, host, port, true)` layers TLS on that socket with
   `SSLParameters` carrying the `HTTPS` endpoint identification algorithm, the host as SNI (unless it is an IP
   literal) and TLS 1.3 and 1.2 only, so the certificate is checked against the name the URL gave.
   `OutboundHttpTlsTest` proves it with a CA made by `keytool` for the run: a stub resolver sends
   `pinned.test`, which no DNS knows, to 127.0.0.1; the server sees `pinned.test` as SNI; a certificate for
   `other.test` and one no trusted CA signed are refused. `OutboundHttpTest` proves the pinning with a resolver
   that answers a checked address first and a refused one after: the request succeeds at the first, and the
   resolver was asked once.
4. The request goes out with `Host` (the URL's authority), the caller's headers, `Content-Length` for a body,
   `Connection: close` and a `User-Agent`. The framing headers are the client's to write and are refused from
   callers, as is any header that could split the message.
5. The response head must arrive within the header deadline; then the body within the total deadline and the cap.

Every read is bounded by what is left of the deadline for its phase (connect and TLS handshake, then headers,
then body): `DeadlineSocket` sets `SO_TIMEOUT` to what is left before each read, so however a peer spaces its
bytes no read, and no sum of reads, passes the deadline. That holds under TLS because JSSE's layered socket reads
the socket it wraps through that socket's `getInputStream()`: `BaseSSLSocketImpl.getInputStream` returns
`self.getInputStream()` when layered, and `SSLSocketImpl.doneConnect` hands `super.getInputStream()` to the
record layer (JDK 17 and 21, openjdk/jdk17u and jdk21u, read 2026-09-28). A body sent a byte every 200 ms stops
at a 1.2 s total, and a head sent a byte every 100 ms stops at a 700 ms header deadline (`OutboundHttpTest`). No
watchdog thread is needed.

A read also ends when its thread is interrupted, as the JDK client's `send` did, so closing a managed executor
(C-3) stops a fetch stuck on a silent peer. A blocking socket read does not see `Thread.interrupt`, so no single
read waits more than 250 ms (`DeadlineSocket.SLICE_MILLIS`): between waits the interrupt is looked at and the
deadline checked, and a slice that runs out before the deadline is read again (the socket stays usable after a
timed-out read). An interrupted read throws `InterruptedIOException`, the exchange fails with reason `IO`, and the
thread keeps its interrupt ([F-0205](../../docs/findings/F-0205.yaml)). Connecting is not interruptible; it waits
at most the connect deadline.

The limits on what a peer can send: at most 100 headers, a status line or header line of at most 8192 bytes,
HTTP/1.0 or 1.1, a status of 100 to 599, at most 8 interim (1xx) responses and never a 101, no `Content-Length`
beside `Transfer-Encoding`, one `Content-Length` of plain digits, `Transfer-Encoding: chunked` and nothing else,
and a body no larger than the cap (256 KiB by default, oidf-jose's; the request may set its own). A declared
length over the cap is refused before a byte of the body is read, and a body refused part-way is not drained:
HttpCore's length-delimited and chunked streams read the rest of the body when closed, so the stream is left and
the socket closed. HttpCore's response parser takes its limits
from its own factory, not the connection's configuration (`DefaultHttpResponseParserFactory.INSTANCE` parses
with `Http1Config.DEFAULT`, 5.4.4), so platform hands the parser the same limits; `exactlyTheMostHeadersIsAccepted`
pins it.

### The address rules

Carried over from oidf-jose's `OutboundUrlPolicy`: `https` only unless http is allowed; a host is required;
credentials in the URL are refused; a port must be 1 to 65535 (the old policy had no port rule either - the port
matters only to an exemption, which pins it); every resolved address must be public; `addressExemptHosts` names
hosts and their subdomains that may resolve privately (still resolved once and pinned); `trusting(urls)` exempts
operator-configured endpoints from the scheme and address rules, pinned to scheme, host, port and path prefix;
`allowPrivateNetworks` turns the address rule off. New: a path is never inside an exemption when, decoded once, it
has a `.` or `..` segment (percent-encoded or not, and with any `;` parameters stripped, so `..;` counts), a backslash
or a percent sign (a second round of encoding), because a server that normalises or decodes it again could take it
out of the prefix.

Non-public, IPv4: 0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16, 172.16/12, 192.0.0/24, the three documentation
ranges, 192.168/16, 198.18/15, 224/4, and 240/4 with the broadcast address. IPv6: all of ::/96 (the unspecified
address, loopback and the deprecated IPv4-compatible form, which no public host uses), 100::/64, Teredo
2001::/32, 2001:db8::/32, fc00::/7, fe80::/10, fec0::/10 and ff00::/8. Forms that embed an IPv4 address are
judged by it: IPv4-mapped ::ffff:0:0/96 and IPv4-translated ::ffff:0:0:0/96 (a dual-stack socket connects to the
IPv4 address itself), NAT64 64:ff9b::/96 and 6to4 2002::/16. Two decisions:

- Teredo is refused outright rather than judged by what it embeds. The client address it carries is reachable
  only through whichever Teredo relay the network routes 2001::/32 to, so what it means depends on a relay this
  process does not choose, and no federation peer is served from a Teredo address.
- NAT64 local-use 64:ff9b:1::/48 lets the operator choose the prefix length (RFC 8215), so the embedded address
  cannot be located from the address alone. It is read at every position RFC 6052 allows inside the /48 (/48,
  /56, /64 and /96) and refused if any reading is non-public, skipping a shorter reading in 0.0.0.0/8, which is
  what the zero padding of a longer prefix looks like. The cost, a false refusal where the operator's own prefix
  bits read as a private address, is [U-0196](../../docs/findings/U-0196.yaml).

### The bulkhead

`HostBulkhead(max)` lets at most `max` requests to one origin (`scheme://host:port`, `AddressPolicy.Target.origin()`)
run at once. `OutboundHttp` asks for a place after the address policy passes and before it connects, and gives it
back when the exchange ends, however it ends (`HostBulkheadTest` covers a refused connect, a malformed response, a
timeout and an interrupted wait). A request that finds every place taken waits for one until its own deadline and is
then refused with `BULKHEAD_FULL`, without connecting; so a request never waits longer for a place than it would
have waited for the peer. An origin is in the table only while a request holds or waits for a place, so
caller-supplied origins cannot grow it past the requests in flight.

What it does and does not buy: a peer that stops answering holds at most `max` sockets from this process, and the
load on a struggling peer stays at `max`. A request waiting for a place still holds its caller's thread until its
deadline, so it does not free threads, and each origin counts alone, so it does nothing against many origins at once
(S5b's budget bounds those). The default, `HostBulkhead.DEFAULT_MAX_PER_ORIGIN`, is 32: a federation fetch from a
healthy peer takes milliseconds, so 32 at once serve hundreds a second to one peer, and the limit bites only when the
peer is slow. oidf-jose's `JdkHttpClient` shares one `HostBulkhead` of 32 across every client in its loaded copy,
because several of its callers make a client per request. There is no setting: a deployment that needs more than 32
concurrent requests to one peer from one node is not one this repository has seen, and a caller that does can build
its own `HostBulkhead`.

### What the deadlines do not bound

Two blocking steps have no timeout in the JDK's API and so are outside every deadline
([U-0195](../../docs/findings/U-0195.yaml)): resolving the name (`InetAddress.getAllByName` waits as long as the
system resolver does) and writing the request (a peer that accepts and stops reading holds a write larger than the
socket's send buffer; a request body is at most 1 MiB, which limits how much a write can be left waiting on, not how
long - in the review's probe on 2026-09-28 a 1 MiB write to a peer that never read returned about 4 s after a 1 s
deadline on macOS and JDK 17, and at the deadline on the image's JDK 21 over loopback). Hostname verification has no off switch here: InsecureTls's
JVM-wide `jdk.internal.httpclient.disableHostnameVerification` governs `java.net.http` alone, and carrying it into
this transport would widen F-0035 rather than keep a behaviour. Under `insecureIf` the chain goes unchecked and the
name is still checked, as InsecureTls documents for the JDK client.

The package's 255 tests pass on JDK 17 and 20 in the reactor, and on the pinned image's own java 21.0.12.1
against the shaded, minimised jar itself (`docker run --entrypoint java` with the JUnit console launcher,
2026-09-28), so the relocated HttpCore, the layered TLS reads and SNI are checked on the runtime PingFederate uses.
The plugins that shade platform carry HttpCore under their own package
(`com.pingidentity.ps.oidf.cibasim.shaded.platform.http.internal.hc5`), and no built jar or war holds an
unrelocated `org.apache.hc` class.

<!-- exec (C-3): add this package's section below this line -->
## exec

`ManagedExecutors` is where the repository's code starts a background thread (plan item C-3). Each job gets an
executor of its own with one daemon thread named `oidf-<name>-<n>`, registered with this copy's lifecycle, listed
in this copy's registry and counted in this copy's metrics:

```java
ManagedExecutors.every("registration-sweeper", Duration.ofSeconds(300), this::sweep);          // first run in 300 s
ManagedExecutors.every("subordinate-refresh", Duration.ZERO, Duration.ofSeconds(240), this::refresh); // first run now
ManagedExecutors.after("some-job", Duration.ofSeconds(30), this::once);
ManagedExecutors.single("ssf-boot-retry").ifPresent(e -> e.after(Duration.ofSeconds(30), this::retry));
```

- `every` runs with a fixed delay: the next run starts one interval after the last one ended, so runs never
  overlap. `after` runs once. `single` schedules nothing, for a job that schedules its own runs (one retry at a
  time) or runs a loop until it is interrupted (`ManagedExecutor.execute`).
- A name is a constant: 1-40 of `a-z`, `0-9` and single hyphens, starting with a letter. Anything else is an
  `IllegalArgumentException`, as is a negative delay or an interval of zero, and both are checked before the
  name is claimed.
- A run that throws - an exception the task did not catch, or an `Error` - is logged at WARN with its stack,
  counted, and the schedule carries on. A bare `ScheduledExecutorService` silently drops a periodic task's later
  runs once one throws, and a bare thread dies. The five jobs below each catch their own exceptions with their own
  log lines, as they always did, so only what those catches let through reaches this.
- `close()` interrupts a run in progress, drops what is queued and waits up to five seconds (`CLOSE_WAIT`) for
  the thread to end, then gives the name back. A run that throws because that close interrupted it is logged at
  INFO as ended by shutdown and is not a failure. `close(Duration.ZERO)` does not wait, as `shutdownNow` did not.
- `whenClosed(hook)` runs something once the executor is closed; the registration sweeper uses it to give back
  its own owner property.

### Which copy may start one

Only the webapp's copy starts threads ([classloaders](../../docs/development/classloaders.md), rule 2). A copy
cannot yet tell it is the webapp's - `Lifecycle.loaderRole()` is `UNKNOWN` until F-2's listener marks it - so a
start is refused, with the reason logged and an empty `Optional` returned, in three cases:

1. **A relocated copy.** A plugin that shades platform relocates this package, and a plugin's loader has nothing
   that would stop a thread. The package name to compare against is built from parts, because a shading
   relocation rewrites string constants that look like the package it moves.
2. **A copy whose lifecycle has shut down.**
3. **A job of that name already running anywhere in the JVM.** The name is claimed in the System property
   `oidf.exec.owner.<name>` under a lock on `System.class`, holding the claiming copy's id, and given back when
   the executor closes. This is the registration sweeper's owner property made general, and classloaders rule 4
   records it. A servlet initialised twice, or the same servlet in `oidf.war` and `pf-runtime.war`, starts one
   loop, not two. For the subordinate refresher that means one instance's cache is warmed and the other's is not
   ([F-0202](../../docs/findings/F-0202.yaml)). `ExecutorCopiesTest` loads platform twice through two `URLClassLoader`s and shows the second
   copy starts nothing while the first runs, and may once the first copy's lifecycle has shut down.

The engine's copy is told apart from the webapp's only by never calling a start: every start is in a servlet's
or filter's `init` (or a boot retry scheduled from one), and no `init` runs in the engine's loader. Once F-2 marks
the webapp, refusing every unmarked copy is one more check here; [F-0200](../../docs/findings/F-0200.yaml)
records it.

### The jobs

| Job | Where | Schedule | Thread before 0.5.0 | Thread now |
|---|---|---|---|---|
| Registration expiry sweep | `RegistrationExpirySweeper.startOnce`, from `TokenEndpointAutoRegistrationFilter.init` | every `OIDF_REGISTRATION_SWEEP_INTERVAL_SECONDS`, first after one interval | `oidf-registration-sweeper` | `oidf-registration-sweeper-1` |
| Subordinate entity-configuration refresh | `FederationService.prewarmSubordinatesAsync`, from `OpenIdFederationServlet.init` | at once, then 240 s after each round | `oidf-subordinate-refresh` | `oidf-subordinate-refresh-1` |
| SSF push delivery and SET expiry | `PushDeliveryService.start`, from `SsfSupport.start` | every `pushRetryBackoffSeconds` (at least 1), first after one tick | `ssf-push-delivery` | `oidf-ssf-push-delivery-1` |
| SSF receiver poll | `PollReceiverClient.start`, from the SSF servlets' wiring | every `receiverPollIntervalSeconds` (at least 1), first after one tick | `ssf-poll-receiver` | `oidf-ssf-poll-receiver-1` |
| SSF boot retry | `SsfSupport.scheduleBootRetry`, when the store cannot be opened at boot | once, 30 s later, one pending at a time | `ssf-boot-retry` | `oidf-ssf-boot-retry-1` |
| Lifecycle closes | `Lifecycle.shutdown` and a `register` after shutdown | one short-lived thread per close | `oidf-platform-close-<resource name>` | `oidf-platform-close-<n>` |

The timing, the log lines and each job's own failure handling are what they were; each job has a test that
drives its loop on the executor (`RegistrationExpirySweeperTest`, `SubordinateRefresherTest`,
`PushDeliveryLoopTest`, `PollReceiverLoopTest`, `SsfSupportBootTest`). Three things differ:

- one of each job runs in the JVM, where the subordinate refresher had no guard and each call started a thread
  (so a second `FederationService` whose refresher is refused keeps a cold cache: F-0202);
- an `Error` thrown by a run is logged and counted and the job carries on, where it used to end the job;
- the subordinate refresher, interrupted at shutdown, stops at the next subordinate rather than logging each of
  the rest as not reachable.

The lifecycle's closer is the one thread here that is not an executor. `ManagedExecutors.startDaemon(name, task)`
starts it - a named daemon, not claimed, not registered and not refused in any copy - because the lifecycle is
what closes executors, and a shutdown that ran its closes on an executor would depend on one being shut down.
That closes [F-0131](../../docs/findings/F-0131.yaml).

### Metrics

Per executor name (a label capped at 64 values; names are constants): `oidf_executor_runs_total`,
`oidf_executor_failures_total` (runs that threw) and `oidf_executor_run_seconds` (a timer; the 30 s and 60 s
buckets are for these). They are registered on the first run, so loading the class registers nothing; from then
on this copy has a metrics MXBean (see [One MXBean per loaded copy](#one-mxbean-per-loaded-copy)).
`ManagedExecutors.snapshot()` lists each executor this copy runs with its own run and failure counts, for health
to read.

### Left for C-4

A managed executor runs a job once per JVM, which on one node is once. On two nodes each runs its own, which is
why 0.5.0 still supports one node ([deployment limits](../../docs/operator/deployment-limits.md)). C-4 (Phase 4)
adds `leaderEvery(job, interval, lease, taskWithToken)` for a job that must run once per cluster: the
registration sweeper, the SSF poll client (each node would poll and acknowledge on its own), and later the MDM
watch loop. The SSF push loop is S-10's engine instead: stream leases with a fencing epoch, not one leader.
Nothing here fixes their shape: `leaderEvery` can build on `single` and `every`, and the claim here stays the
per-JVM rule under it.

Threads the repository does not start through here: services/device-enrolment's HTTP server pool and its
shutdown hook (`EnrolmentHttpServer`, `Main`), which X-A11 replaces; libs/testkit's shutdown hook, which stops a
test database and is never shipped; and the Kafka producer's own I/O thread when the SSF Kafka publisher is on,
which the Kafka client starts ([F-0201](../../docs/findings/F-0201.yaml)).


<!-- auth (S8a): add this package's section below this line -->
## auth

`TokenIntrospector` asks an authorisation server about an access token (RFC 7662, plan item S8a) over
`OutboundHttp`, within 1 s to connect, 2.5 s in all and a 64 KiB answer. The caller supplies how it authenticates
(`ClientAuthentication.clientSecretBasic` or `privateKeyJwt`) and the `AddressPolicy` that lets it reach the
endpoint. The answer is an `Introspection`: `active`, `scope`, `client_id`, `sub`, `aud`, `iss`, `exp`, `iat`, `nbf`,
`token_type` and `cnf` (`jkt`, `x5t#S256`). A token that is not active is a value; no answer - unreachable, a status
other than 200, a body that is not a JSON object of the types RFC 7662 §2.2 gives - is an `IntrospectionException`,
which the caller maps to 503. An active answer is kept for at most 30 s and never past its `exp`, and only when the
caller turns the cache on.

RFC 7662 defines no `cnf`; RFC 9449 §6.2 conveys the DPoP key's thumbprint "as a top-level member of the
introspection response JSON", and PingFederate 13.1.3 sends it, with `token_type` `DPoP`, for JWT and reference
tokens alike (the rig, 2026-09-29; [U-0030](../../docs/findings/U-0030.yaml)). rs-validation's
`DelegatedTokenValidator` checks the binding from it, and platform-pf's `OperatorAuthenticator` is the first user
([docs/operator/operator-authentication.md](../../docs/operator/operator-authentication.md)). The package is
JDK-only, like the rest of platform; JSON goes through platform.json.


## Build

```sh
mvn -pl libs/platform -am verify     # -> target/platform-<version>.jar (tests on)
```

Versions come from `bom/pom.xml` (no parent pom). The coverage gate is 100% line and branch per method over
the decision methods named in `pom.xml`, each package's under its own anchor; the rule must always name at
least one real method, because `tools/coverage-report.py` fails a gate that matches nothing.
