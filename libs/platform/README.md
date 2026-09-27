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
<!-- profile (PR-1): add this package's section below this line -->
<!-- tls (PR-1): add this package's section below this line -->
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
sees it, and `LoggingSink` and platform-pf's audit sink admit it again (admitting twice changes nothing): the
event's component becomes the catalogue's that declares its code, and a field that code does not declare is
dropped and counted (`droppedFields()`; `uncataloguedEvents()` counts codes no catalogue declares, whose events keep
their head and lose every field). The first drop of each code and field is a WARN line naming the field, never its
value. O4 (plan item O-4) turns the counts into metrics.

**The PII policy.** `PiiPolicy` says, for server.log and for PingFederate's audit log, what happens to each class:
kept, replaced by `sha256:` and twelve hex digits, or dropped. The subject and partner are `PSEUDONYMOUS_ID`; the
reason, role, request `jti` and description are operational and never removed. `PiiPolicy.DEFAULT` keeps every
class in both logs, which is what reached them before the catalogues (checked 2026-09-28 against the emitters):

| Class | What it holds | server.log | audit log |
|---|---|---|---|
| `OPERATIONAL` | modes, counts, endpoint names, decisions, times | kept | kept |
| `PSEUDONYMOUS_ID` | client ids, entity identifiers, key ids, a workload's subject; the subject and partner | kept | kept (the subject and connection columns) |
| `DIRECT_ID` | can name a person: `actor`'s self-declared name from `X-Federation-Actor` | kept - finding [F-0165](../../docs/findings/F-0165.yaml) | kept |
| `NETWORK` | addresses and host names; no field today - the audit log's `ip` column is PingFederate's own | kept | kept |
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
