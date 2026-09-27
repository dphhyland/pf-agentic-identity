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
