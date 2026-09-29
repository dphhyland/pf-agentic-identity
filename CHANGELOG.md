# Changelog

Every release of pf-agentic-identity, newest first, in the shape [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
describes: one heading per version with its date, and a few lines on what the version was for. A version is a
tag of this repository (`git tag -l 'v*'`); the dates are the tags' own. Where a version has release notes
under [docs/releases](docs/releases/), the heading links to them. The convention for the version in progress:
it sits under `Unreleased` with the version the poms declare (a `-SNAPSHOT`); the release's pull request gives
it the heading `[<version>] - <date>`, the date the tag is cut, and leaves an empty `Unreleased` for the next
`-SNAPSHOT`.

## [Unreleased] - 0.6.0-SNAPSHOT

## [0.5.0] - 2026-09-29

Phase 2 of the production programme, foundations: every shipped module on the shared `platform` and
`platform-pf` libraries, a settings catalogue per component with the configuration reference generated from them
and held to the code both ways, events, metrics, health and a start-up audit, managed background threads, a pooled
Redis client, an outbound HTTP client pinned to the addresses it checked, PostgreSQL as the only store database,
and the image built, tested and scanned in CI. Notes: [docs/releases/0.5.0.md](docs/releases/0.5.0.md).

- Plan item C-2: `libs/platform` gains `platform.redis`. `RedisClient` is client-attestation's `MiniRedisClient`
  moved to platform with S3a's rules unchanged - `rediss://` verified by chain, name and SNI with the handshake
  before `AUTH`, `OIDF_REDIS_CA_FILE`, `redis://` refused under the production profile (now through
  `ProfileGuard`), no userinfo in a message - and with a pool bounded by `OIDF_REDIS_POOL_SIZE`, a wait for a
  connection bounded by `OIDF_REDIS_BORROW_TIMEOUT_MS` and every command under `OIDF_REDIS_COMMAND_TIMEOUT_MS`.
  `RedisKeyspace` puts a prefix before every key. The commands leases (C-4) and rate limits (X-A11) need are there:
  `SET` with `NX` and `PX`, `GET`, `DEL`, `INCR`, `PEXPIRE`, `EVALSHA` with the `NOSCRIPT` fallback to `EVAL`, a
  compare-and-delete and a compare-and-extend script, and a fixed-window counter.
- Redis Sentinel: with `OIDF_REDIS_SENTINEL_MASTER` and `OIDF_REDIS_SENTINELS` set (and
  `OIDF_REDIS_SENTINEL_PASSWORD` when the sentinels ask for one), the client finds the master through
  `SENTINEL get-master-addr-by-name`, asking each sentinel in turn within an equal share of the command's deadline,
  checks it with `ROLE`, and finds it again after a failover - a `READONLY` reply or a lost connection. The command
  is retried once on the new master after `READONLY`, or when the master could not be reached; a command that may
  have run is not sent twice. TLS and the CA file apply to the sentinels as to the master.
- The Redis settings are catalogued in `platform-redis.json`, read through `platform.settings`:
  `oidf.redis.url`, `OIDF_REDIS_URL` and `REDIS_URL` in that order, `OIDF_REDIS_CA_FILE` and its property, and the
  six new ones. A value its entry refuses stops the Redis stores as a bad URL does, with the setting named.
- client-attestation's stores run on `RedisClient`; `MiniRedisClient` and client-attestation's own
  `DeploymentProfile` are gone. The keys are byte for byte 0.4.0's (`oidf:as:*`, `oidf:cas:*`,
  `oidf:fed:endpoint:*`, `oidf:admin:dpop:*`), the verdicts are still tri-state, and an outage is still 503. New in
  the register: F-0180, F-0181, F-0182, F-0183, U-0190. F-0007 stays open.

- Plan item C-3: `libs/platform` gains `platform.exec`. `ManagedExecutors.every`, `after` and `single` start a
  job on an executor of its own with one daemon thread named `oidf-<name>-<n>`, registered with the copy's
  lifecycle (closed at shutdown within five seconds), listed per classloader, and counted per run in
  `oidf_executor_runs_total`, `oidf_executor_failures_total` and `oidf_executor_run_seconds`. A run that throws
  is logged and counted and the job carries on. A job runs once in the JVM, whichever classloader starts it, and
  a plugin's relocated copy starts none.
- The registration expiry sweeper, the federation subordinate refresher, and the SSF push delivery, receiver
  poll and boot-retry loops run on it, with their timing, log lines and failure handling unchanged. Their threads
  are renamed (see the Notes).
- `Lifecycle` closes each resource on a thread started through `ManagedExecutors.startDaemon`, so platform.exec
  is the one place the repository's shipped PingFederate code starts a thread; closes F-0131. New in the
  register: F-0200, F-0201, F-0202, U-0210.

- The store suites run on PostgreSQL only, each test class in a database of its own: `libs/testkit` (test
  scope, never shipped) creates it on the server `OIDF_TEST_JDBC_URL` names, or in one Testcontainers 1.21.4
  container per JVM, and drops it afterwards; with neither the class is skipped, and under `CI=true` it fails.
  The hosted-entity, Trust Mark, key-history and agent registries run their shipped migrations there instead
  of on H2, and both durable SSF stores are held to the whole `SsfStore` contract on Postgres (DB-1).
- H2 and HSQLDB support is gone: a `jdbc:h2:` or `jdbc:hsqldb:` authority store URL (`OIDF_AUTHORITY_JDBC_URL`)
  or SSF store URL (`OIDF_SSF_JDBC_URL`) is refused at start-up with a message naming PostgreSQL, a PingFederate
  data store id (`OIDF_AUTHORITY_DATA_STORE_ID`, `OIDF_SSF_DATA_STORE_ID`) whose database reports itself as H2 or
  HSQLDB is refused on its first connection, and H2 leaves every module's test classpath.
- `IDM_TEST_JDBC_URL`, `_USER` and `_PASSWORD` are renamed `OIDF_TEST_JDBC_*`; the old names are read in 0.5.x
  with a warning. Testcontainers moves from 1.19.8 to 1.21.4, which finds Docker Desktop 29 (U-0050, closed).

- New modules `libs/platform` (`com.pingidentity.ps.oidf:platform`, JDK only) and `libs/platform-pf`
  (`com.pingidentity.ps.oidf:platform-pf`, PingFederate's jars provided), the shared base Phase 2 builds on
  (plan item F-1). They hold, so far: a per-classloader registry of what to close at shutdown, a component
  registry in S-9's seven states, a copy of rar-model's JDK-only JSON reader and writer, a logger that writes
  through commons-logging where the loader has it, and the guard an OGNL criterion runs behind.
- `oidf-jose` depends on `platform` and `pf-integration` on `platform-pf`, so `oidf.war` carries both jars and
  `stage-modules.sh` stages both, in both profiles, into the war and onto the engine's classpath. The
  `MANIFEST` is now the one list of staged jars: the image README, the Dockerfile, the SSF and `oidf-war`
  READMEs and the showcase point at it instead of counting.
- [docs/development/classloaders.md](docs/development/classloaders.md) writes down the classloader rules the
  libraries follow.

- Plan item F-2: `libs/platform-pf` gains `LifecycleListener`, registered by name in `pf-runtime.war` (through
  `build/pingfederate/filters.xml`, which the war assembler writes into its `web.xml`), in `oidf.war` and in
  `gm-api.war`. At start-up it marks the war's copy of platform as the webapp's, registers its metrics MXBean and logs
  one start-up audit banner at INFO after the war's filters and load-on-startup servlets have started; at undeploy it
  closes that copy's managed executors, MXBean and Redis pools within five seconds. It touches only a copy of platform
  its own war's classloader loaded.
- `gm-api.war` bundles `platform-pf` and `platform` in its `WEB-INF/lib`, so it has its own components, metrics and
  banner, and its own health at `/gm-api/agentic-identity/health/{live,ready}`; its two load-on-startup servlets
  register the component `GM_API`.
- New in the register: F-0210, F-0211 and U-0220. Closed: U-0024 (a `@WebListener` in a `WEB-INF/lib` jar runs in
  `pf-runtime.war` without a `web.xml` entry; one in `server/default/deploy` runs nowhere).

- gm-api imports the BOM like every other module and depends on the real coordinates of what PingFederate
  provides (`pingfederate-sdk`, `jakarta.servlet-api`, `jose4j`, `jackson-databind`, `jackson-core`), all
  `provided` and version-less; ciba-sim and instance-registry-datasource take `org.apache.commons:commons-lang3`
  from the BOM. Nothing names `local.pingfederate` any more.
- The `pf-provided-jars` action installs only `pf-protocolengine` and `pingfederate-sdk`; it still extracts
  `pf-lib` and `pf-jetty-lib` for `tools/pf-linkcheck.py` and `tools/pf-provided-versions.py`, which now checks
  `jackson-core` against the image as well.

- Events live in `platform.events` (plan item O-1): the event record, now with a component, the sink interface, the
  per-classloader sink registry, the server-log sink and `LogSafe`, with the rule that an instance's subject is
  never recorded beside its `agent_id`. `FederationEvent`, `FederationEvents`, `FederationEventSink`,
  `LoggingEventSink` and `LogSafe` in openid-federation are delegating façades, deprecated for removal by O-2.
- Every event code and every field it may carry is catalogued as data, in `META-INF/oidf-events/<component>.json`
  of the module that declares it - `federation` in openid-federation, `attestation-issuer` in the attester - with
  one PII class per field (`OPERATIONAL`, `PSEUDONYMOUS_ID`, `DIRECT_ID`, `NETWORK`, `CREDENTIAL_DIGEST`). A field
  its code does not declare is dropped before any log sees it, and counted.
- PingFederate's audit sink is `platform.pf.audit.PfAuditSink` in platform-pf, with the audit log's `protocol`
  column set per component from its catalogue; `PfAuditEventSink` in pf-integration is a delegating shim.
  `OIDF_EVENTS_AUDIT` and `OIDF_EVENTS_MAX_VALUE_LENGTH` are unchanged.
- `EventsCataloguedTest` fails the build on an emitted code or field that is not catalogued, on a catalogued code
  nothing emits unless it is marked `declaredOnly`, and on an emitter whose audit flag or outcome its catalogue
  does not match.

- Plan item O-3: `libs/platform` gains `platform.metrics` - `Metrics.counter`, `timer` and `gauge`, each
  registered once with fixed, bounded labels (a declared set, or a cap past which values count as `other` and a
  fold counter rises), timers with a count, sum, max and fifteen fixed buckets from 1 ms to 60 s, and a lock-free
  hot path. Each loaded copy of platform registers one MXBean, `com.pingidentity.ps.oidf:type=Metrics,copy=...`,
  unregistered through its lifecycle. Nothing registers a metric yet: O-4 and C-3 are the first users, O-5 the
  Prometheus endpoint. New in the register: F-0170, U-0180.

- Plan item O-4: PingFederate's runtime port answers `/agentic-identity/health/live` and
  `/agentic-identity/health/ready` (open, status only; ready is 503 when an enabled component is not ready or
  degraded), and `/agentic-identity/health` and `/agentic-identity/info` (the detail and the versions, only for the
  static admin bearer `OIDF_AUTHORITY_ADMIN_TOKEN`, 404 for anyone else). `libs/platform` gains `platform.health`
  (component parts, readiness, the documents), `libs/platform-pf` the `HealthServlet`.
- The servlets and filters register their parts under S-9's component names from their `init`, and record a
  failure's state and reason before rethrowing it unchanged; whether any of them starts is as before.
- Every event counts itself in `oidf_events_total{code,outcome}`, labels bounded by the event catalogues, with the
  gauges `oidf_events_dropped_fields` and `oidf_events_uncatalogued`. New in the register: F-0190 to F-0194.

- Plan item F-1, its platform-pf part: `libs/platform-pf` gains `platform.pf.internals.PfInternals`, the one class
  that calls PingFederate's internal services - the issuer lookup, the client manager, the token endpoint base URL
  and the discovery document handlers - and `ClientManager.isBackendDatabase()`, which C-1 will read. Every caller
  in pf-integration and attestation-issuer goes through it, and a test keeps any other production class from
  naming those internals again. platform-pf's README lists every PingFederate class and member the reactor links,
  by kind. New in the register: F-0215.

- `libs/platform` gains `platform.profile` and `platform.tls` (plan item PR-1). `DeploymentProfile` is the one
  reading of `OIDF_DEPLOYMENT_PROFILE` - `development`, trimmed, in any case, and production for everything else,
  unset included - and every module reads it there: client-attestation, attestation-issuer, rar-model, the RAR
  plugin and ciba-sim. `AcceptedRisks` reads the new `OIDF_ACCEPTED_RISKS`, and `ProfileGuard` asks whether a
  switch is forbidden, required or an accepted risk under the production profile. Nothing asks it yet: PR-2 and
  PR-5 (Phase 3) wire the switches and refuse components.
- `InsecureTls` is now the only place a trust-all TLS context is built. The federation fetches
  (`OIDF_FEDERATION_IGNORE_SSL_ERRORS`), the RAR plugin's "Skip TLS verification (dev only)", the SSF
  receiver's and introspection's insecure-TLS switches, device-enrolment's `PF_AUTHORITY_INSECURE_TLS` and the
  harness ask it; each use logs one WARN naming its setting. What each switch trusts is unchanged: any
  certificate chain, and the certificate must still name the host dialled - except in the harness, which turns
  the JDK's host-name check off for every run ([F-0162](docs/findings/F-0162.yaml)).
- `tools/trust-scan.py`, a new step in the lint job, fails on a trust-all trust manager, an always-true
  hostname verifier, a null endpoint identification algorithm or the JDK's hostname flag anywhere else in main
  code (F-0042, CodeQL alerts 4 to 9).
- The RAR plugin and ciba-sim shade and relocate platform, as the RAR plugin already does Jackson and rar-model;
  ciba-sim's jar is now a shaded jar under the same name. rar-model depends on platform.

- `tools/coverage-report.py` also writes `docs/coverage-dashboard.json` (git-ignored, published in the
  `coverage-dashboard` artefact): per module, each jacoco check's methods with their line and branch counters,
  the test counts, and the `@Requirement` ids and matrix rows its tests pin.
- `--gate` fails on a jacoco check or `<include>` pattern that selects no method and on an undeclared
  `@Requirement` prefix, and counts the ids no conformance-matrix row declares.
- `--baseline <json>` ratchets against an earlier build: a check gone or shrunk, a gated method below 100%, or
  fewer pinned matrix rows fails, less the deliberate reductions `tools/coverage-ratchet-allow.txt` names.
  Build's java job runs both, against the newest successful Build on main that the commit descends from
  (`tools/ci/coverage-baseline.sh`, with `actions: read` on that job only).

- `build/pingfederate/Dockerfile` has three targets: `builder` assembles `pf-runtime.war`, `capability` is the
  image with no configuration archive, and `deployment` adds the archive and `overlay/` to it. `deployment` is the
  last stage, so `docker build` with no `--target` builds the image it built before (plan item R-CI6, taking
  plan item R-I3's targets ahead of Phase 3). The bake-ins R-I3 removes - the EULA, DEBUG logging, the 9080
  listener, `ForceUnsupportedImport`, the required claims and the mock attesters - are unchanged.
- Build has an `image` job, and `.github/required-checks.txt` names it, so a release needs it green. It builds
  `capability` for both staging profiles, runs `test-entrypoint.sh --image` in each, runs the war assembler against
  PingFederate's own `pf-runtime.war` (`StockWarGoldenTest`), builds the default target from a placeholder
  archive and without one, publishes a syft SBOM of each image (SPDX JSON, the `image-sbom` artefact), and scans
  each with grype, failing on a HIGH or CRITICAL finding in the layers this repository adds and reporting the
  base image's own without failing.
- `tools/ci/install-lint-tools.sh` installs grype 0.119.0 and syft 1.52.0 by checksum; `.github/grype.yaml` names
  the accepted findings with their reasons; `tools/ci/image-scan-gate.py` decides what is ours.
- `tools/pf-version-check.py` and `tools/pf-version-sync.py` read a `FROM` that names its stage, and treat a
  `FROM` naming an earlier stage as a stage rather than an image.

- New module `build/war-assembler` (`com.pingidentity.ps.oidf:war-assembler`, JDK only, compiled for 17): it
  builds `pf-runtime.war` from the stock war, the staged jars and `build/pingfederate/filters.xml`, which now
  declares the seven filters, their paths and the order rules the script used to write with awk (plan item
  R-I5). It refuses a war in which a declared filter lacks exactly one `<filter>` and one `<filter-mapping>` over
  exactly its paths, an order pair does not hold, a path is one the stock `web.xml` does not serve, the root is
  `metadata-complete="true"`, or a declared filter's class is in no jar, and prints each path's filter chain.
  Published to GitHub Packages with the rest of the reactor from the next release; the release assets do not
  carry it.
- `assemble-pf-runtime-war.sh` keeps its command line and exit codes and is now a wrapper that runs it; the
  `MANIFEST`, profile and namespace checks moved into the assembler with their messages. A refusal still leaves
  no output war, and the wrapper now also removes it when the JVM itself fails. With too few arguments it now exits
  2 with a usage line (it exited 1 on an unbound variable); with more than five it exits 2 too (it ignored the
  extras and assembled). `STOCK_WAR` and `OUT_WAR` naming the same file now exits 2 with nothing touched (the script's
  `cp` failed on it, and its clean-up then deleted the stock war).
- `stage-modules.sh` also stages the assembler, as `assembler/war-assembler.jar` beside `modules/`; the Dockerfile
  copies it with `filters.xml`, and `conformance/compose-context.sh` carries both.

- `platform.http`: an outbound HTTP/1.1 client (`OutboundHttp`) that resolves a host once, checks every address
  it resolves to, and connects only to one of those, with the host name kept as TLS SNI and checked against the
  certificate. Every read is bounded by what is left of a connect, header or total deadline, and the body by a
  cap, whether its length is declared, chunked or delimited by close. GET, POST, PUT, PATCH and DELETE, headers on
  every method, the status always returned, no redirects. With it: `Deadline`, `Budget` (a wall clock and a
  request count, with child budgets), `AddressPolicy` (oidf-jose's URL rules, plus 0.0.0.0/8, 240.0.0.0/4,
  Teredo, the IPv6 forms that embed a non-public IPv4 address, and no exemption for a path a server could
  normalise or decode out of the exempt prefix), `TlsTrust` and a `Bulkhead` seam
  (plan item S5a, part 1). Nothing calls it yet.
- The platform jar now carries Apache HttpComponents Core 5.4.4, relocated under
  `com.pingidentity.ps.oidf.platform.http.internal.hc5` and minimised; it grows from 227 KB to 448 KB.

- oidf-jose's `JdkHttpClient` (and `JdkHttpGetClient`, which delegates to it) sends through platform's
  `OutboundHttp` instead of the JDK's `java.net.http` client. `OutboundUrlPolicy` resolves the host once, checks
  every address, and the connection goes to one of those addresses and nowhere else, with TLS still checking the
  certificate against the URL's host. A name that answers publicly for the check and privately for the connection
  (DNS rebinding) now reaches nothing; before, the JDK client resolved the name again and connected where the second
  answer said (finding F-0070, closed). Every federation fetch, entity statement, JWKS, trust mark status and AuthZEN
  PDP request made through these classes is covered; the public API, the 8 s connect and 15 s request timeouts,
  HTTP/1.1, no redirects and the body cap are unchanged.
- The 15 s request timeout now bounds the whole exchange, the body included. The JDK client's stopped once the
  headers arrived, so a peer could trickle a body for as long as it liked.
- A per-origin bulkhead: at most 32 requests to one `scheme://host:port` run at once in each loaded copy of
  oidf-jose. A request that finds all 32 places taken waits for one until its own deadline and then fails as a
  failed fetch (platform's `OutboundHttpException`, reason `BULKHEAD_FULL`), which every caller already handles as
  it handles a timeout. `platform.http.HostBulkhead` is the implementation; there is no setting.
- `OutboundUrlPolicy`'s scheme and address rules are now platform's `AddressPolicy`, so federation fetches refuse
  the addresses platform refuses and the old policy did not: 0.0.0.0/8, 240.0.0.0/4, the three IPv4
  documentation ranges, all of IPv6 ::/96, discard-only 100::/64, Teredo 2001::/32, 2001:db8::/32, and the
  IPv4-translated, NAT64 and 6to4 forms that embed a non-public IPv4 address. A path with a dot segment, a backslash
  or a percent sign left after one decoding is never inside a `trusting()` exemption. The `OIDF_FETCH_*` settings
  mean what they meant.
- A platform `OutboundHttp` read on a silent peer now ends when its thread is interrupted, as the JDK client's did,
  so closing the subordinate refresher's executor still stops a fetch in progress (finding F-0205, closed).

- Plan items ST-1 and ST-2: `platform.settings` holds the strict parsers `FederationRuntimeConfig` used, with
  their messages (`Parsers`), and the settings model - `Setting`, a resolver that returns each value with the
  source and name that supplied it, aliases, removed names, `_FILE` secrets - loaded from one JSON catalogue per
  component at `META-INF/oidf-settings/<component>.json`, read through typed accessors (`Settings`).
  `UnknownKeys.find` lists `OIDF_*` names under a catalogued family that nothing declares; nothing calls it at
  run time yet. `platform-pf` adds `InitParams`, a servlet's or filter's init-params as a source.
- `FederationRuntimeConfig` reads through `Parsers`; its names, precedence, defaults and messages are unchanged.
  `OIDF_AUTHORITY_METADATA_POLICY` and `OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS` are read by `platform.json`
  instead of Jackson, which refuses a few documents Jackson accepted (see "Check that
  `OIDF_AUTHORITY_METADATA_POLICY` and `OIDF_FEDERATION_SUBORDINATE_CONSTRAINTS` are each one well-formed JSON
  object" below).
- [docs/development/settings-catalogue.md](docs/development/settings-catalogue.md) describes the catalogue
  format, with a worked example.

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

- Plan item ST-3 (part 2 of 3): eight more settings catalogues, one per component, under
  `src/main/resources/META-INF/oidf-settings/`: `attestation-challenge` (client-attestation's two challenge
  endpoints), `rar-models` (rar-model's `OIDF_RAR_MODELS_FILE` and `OIDF_RAR_MODELS`), `attestation-issuer`,
  `evidence-policy` and `issuance-client-properties` (attestation-issuer, the last its eleven per-client
  `attestation_*` extended properties and `attestation_asserted_context_resolver`), `rar-pdp-processor` (the RAR
  plugin's fifteen configuration fields and `OIDF_RAR_EXTRA_TYPES`), `instance-registry` (the data source's two
  fields and its filter field) and `ciba-simulator` (`OIDF_CIBA_SIM_ENABLED` and `OIDF_CIBA_SIM_DIR`) - 58
  settings with their sources, defaults, types, profile classes and whether they bear on security. A plugin field
  is catalogued under the name PingFederate shows for it, and its entry names the plugin's descriptor id. The
  settings scan no longer exempts these six modules. The jars carry the catalogues; nothing reads them at run
  time yet. New in the register: F-0230, F-0231, F-0232.

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

- Plan item ST-4: `tools/config-reference.py` writes the configuration reference from the settings catalogues -
  one page per component in `docs/configuration/`, 24 of them, each saying which catalogue it came from, with the
  style guide's four columns and two more, Profile and Security - and the list of components in
  `docs/configuration/README.md`. The Build workflow's lint job runs it with `--check` and fails, naming the file,
  when a committed page is not what the catalogues generate. The settings A-Z index is written on demand
  (`--index FILE`) and never committed.
- `docs/extended-properties.json` is generated too, from every catalogue's extended-property entries: beside the
  federation module's ten names it now lists 24 more: the nine per-client `attestation_*` properties the token
  endpoint reads, the three `trust_chain_*` limits, and the attester's twelve `attestation_*` names,
  `attestation_asserted_context_resolver` among them. Its `_comment` and shape are unchanged apart from saying
  where it now comes from. The conformance rig's Terraform, which reads the file, declares every one of them,
  each described as read or written by the OIDF modules. Closes F-0041.
- The settings scan's exemption file sets `refuse-shipped-exemptions: yes`: only modules that are never shipped
  may be exempt, each with its reason, and the scan says every shipped module is held to its catalogues. With
  `--check`, the reference is held to the code both ways: the scan holds the code to the catalogues, and the
  generator holds the catalogues to the pages.
- `ConfigurationDocumentedTest` is gone; `FederationClientParamsTest` holds
  `FederationClientParams.EXTENDED_PARAM_NAMES` to pf-integration's `client-properties` catalogue.
- `docs/federation/configuration.md` keeps how a setting is read and what "wrong" means, points each part of the
  federation at the generated pages, and keeps what a row has no room for: examples of the JSON settings'
  shapes, and what the rows leave out.

- New module `libs/shared-signals` (`com.pingidentity.ps.oidf:shared-signals`, package
  `com.pingidentity.ps.oidf.signals`; plan item X-A14): the RFC 8417 SET model, minting behind `oidf-jose`'s
  `SigningKeyProvider` or `JwsSigner`, verification against a supplied key set, the subject identifiers, and the
  CAEP and RISC event types. No HTTP and no PingFederate, so a service outside PingFederate can mint and verify SETs
  with the code `servlets/ssf` uses.
- `SecurityEventToken`, `SetMinter`, `SetVerifier`, `ReceivedSet`, `SubjectId` and `CaepRiscEvents` moved from
  `com.pingidentity.ps.oidf.ssf` to `com.pingidentity.ps.oidf.signals`; no class of the old name is left behind,
  because keeping the package in a second jar would split it across two jars again (the 2026-08-15 unwind in
  [PROVENANCE](docs/PROVENANCE.md)). `SsfEventTypes` stays in `servlets/ssf` as the list the transmitter
  advertises; its URIs are the new `EventTypes`. What needs PingFederate or the network stays in `servlets/ssf`:
  `PfSetSigningKeys` (PingFederate's signing key, resolved on first use as before) and `JwksHttpSource` (the
  receiver's JWKS fetch, which plan item S5d moves onto platform's HTTP client).
- `SubjectId` parses RFC 9493's `did`, `uri` and `aliases`, SSF 1.0's `jwt_id`, `saml_assertion_id` and
  `ip-addresses`, and SSF 1.0's complex subject, and implements SSF 1.0 §8.1.3.1's subject matching (finding U-0033,
  closed). `servlets/ssf` still accepts only the five formats it handled before (`iss_sub`, `email`,
  `phone_number`, `opaque`, `account`) - in stream subjects, the emit API, SCIM ids and an inbound `sub_id` - until
  plan item H-SSF-1 stores, matches and acts on the others.
- The receiver's SET verification is stricter (finding F-0245, closed): `typ` must be `secevent+jwt` (with or without
  `application/`, in any case), not merely contain `secevent`; `alg` must be an asymmetric signature algorithm;
  `iat` must be present and a number; an `exp` that has passed, less 60 seconds, is refused; `events` must be an
  object with at least one member, each an object; a `sub_id` that is not an object is refused.
- `build/pingfederate/stage-modules.sh` stages `shared-signals-<version>.jar` in both profiles, so the image carries
  it and the `MANIFEST` names it.

- Plan item X-B01: each instance-attestation validator now proves a fixed, bounded set of evidence selectors,
  `InstanceIdentity.selectors()`, in one `<evidence type>:<name>` namespace, built only from the claims it verified
  and only after every check passed. Nothing reads them yet and minted attestations are unchanged; X-B09 (Phase 5)
  is to condition ceilings on them. Evidence over the bounds (32 values, 2048 bytes a value) is refused. New in the
  register: F-0140.

- Plan item X-D01: `services/demo-rs` moves to `libs/rs-validation` (`com.pingidentity.ps.oidf:rs-validation`), with
  the package `com.pingidentity.ps.oidf.rs` unchanged. `services/demo-rs` is now a relocation POM: a build that
  depends on `demo-rs` 0.5.0 or later resolves `rs-validation` at the same version.
- `DelegatedTokenValidator` is built with `DelegatedTokenValidator.builder(issuer, audience)`, and `build()` refuses
  without the authorisation server's keys and a `ReplayStore`. The replay store is asked last and refuses a DPoP
  proof it has seen (`invalid_dpop_proof`); a store that cannot answer is a 503. `RedisReplayStore` (`SET NX PX`
  through `platform.redis`) serves more than one node, `InMemoryReplayStore` one.
- The access token's `kid` must name exactly one published key (a token without one is refused, with no fallback
  to trying every key), its `typ` must be RFC 9068's `at+jwt` unless `accessTokenType(...)` says otherwise, and
  `nbf` is checked. The request method and URI are required.
- `act` is strict: a malformed chain, one deeper than 10 levels, and the legacy string form are refused; the string
  form only when this process runs under the development profile, through `allowLegacyStringAct()`.
- New: resource-server DPoP nonces (`DpopNonces`, an HMAC over a time window, with `use_dpop_nonce` and
  `DPoP-Nonce`), mTLS certificate-bound tokens (`cnf.x5t#S256`, under the Bearer scheme when `mtls(true)` is set),
  `RemoteJwks` (the JWKS through `platform.http`, cached by `kid`, refreshed on an unknown `kid` at most every 30 s,
  and its keys no longer used once twice the 10-minute maximum age old while fetches keep failing), and `ResourceServerFilter`, a `jakarta.servlet.Filter` that answers with the RFC 6750 and RFC 9449 challenges.
- Findings: U-0011 and U-0035 closed; F-0225, F-0226, F-0227, F-0228 and F-0229 recorded.

## [0.4.0] - 2026-09-27

Phase 1 of the production programme: the review's blockers closed or mitigated, the findings register, CI
hygiene, and one PingFederate node only until 0.7.0
([docs/operator/deployment-limits.md](docs/operator/deployment-limits.md)). Notes:
[docs/releases/0.4.0.md](docs/releases/0.4.0.md).

- **R-I1 Staging profiles** - `stage-modules.sh --profile production|conformance` (production, the default, leaves
  the CIBA simulator out), a v2 `MANIFEST` naming the profile, a section per module group and a sha256 per jar,
  and an assembler and Dockerfile (`STAGING_PROFILE`, recorded as an image label) that refuse a stage made for
  the other profile.
- **R-I4 Entrypoint hardening** - `umask 077` first; `PF_ARCHIVE_AGE_KEY_FILE` preferred, the inline key piped and
  both variables unset before PingFederate starts; `PF_ARCHIVE_SHA256` checked before the archive is decrypted or
  imported; `PF_ARCHIVE_FILE`, binary or armored age; a plaintext archive refused unless
  `OIDF_DEPLOYMENT_PROFILE=development`; the tmpfs claim corrected; `test-entrypoint.sh`.
- **X-D02 ciba-sim conformance-only** - the decision endpoint (404) and the authenticator (`OOBAuthGeneralException`)
  refuse every request unless `OIDF_CIBA_SIM_ENABLED=true`, `OIDF_DEPLOYMENT_PROFILE=development` and
  `OIDF_CIBA_SIM_DIR` is an existing private directory the plugin owns; the rig sets all three.
- **Information architecture and style** (D-1) - `docs/{operator,configuration,reference,security,development,findings,releases}`
  each with a README saying what belongs there; `SECURITY.md`, `CONTRIBUTING.md` and a pull request template;
  the house style in `docs/development/style-guide.md`, with `tools/doc-lint.py` checking what a machine can
  against a dated baseline, in a new `docs.yml` workflow.
- **Findings register** (D-2) - one YAML file per finding under `docs/findings` (`F-` defects, `U-` unverified
  assumptions), seeded from the 2026-09-26 review, the reviewer reports, the plan's "Found while designing"
  list and `docs/unverified.md`; `tools/findings.py --check` in CI, `--gate` for a release, `list` and `index`
  on demand.
- **CI hygiene** (R-CI1 to R-CI4) - every action pinned to a commit with least-privilege tokens; actionlint,
  zizmor, shellcheck and `terraform validate` in the lint job; the secrets guard's content scan extended to private
  JWKs and every PEM kind, with gitleaks over the whole history beside it; CodeQL for Java, Actions, Python and
  JavaScript; Dependabot; the rig's Terraform lock file committed; CODEOWNERS.

- **iOS reference client** (X-I01a) - `clients/ios`: AgentIdentityKit, a Swift package for the device side of
  `services/device-enrolment` (enrol, re-mint, the user-verification refresh, the counter-race retry) with App
  Attest, the Secure Enclave and PingOne behind protocols, tested with fakes and against the service's own Java; a
  sample app that also captures App Attest vectors; `docs/device/ios-client-contract.md`; a macOS job, `ios.yml`.
  A skeleton until X-I01b.
- **Generated files leave git** (plan decision 18; R-CI5's publish step, brought forward from Phase 2):
  `docs/coverage-dashboard.md` and `.html` and the showcase's rendered documents (now `showcase/docs.js`) are
  generated and git-ignored; a CI Build whose reactor build completes publishes them as its `coverage-dashboard`
  and `showcase` artefacts (a run that fails in `mvn verify` publishes neither); `tools/coverage-report.py` is
  strict by default and exits 1 for a build that left a module without its reports; the Build's `java` job runs
  device-instance's Postgres suite against a service container.
- **Redis verified and tri-state** (S3a) - `rediss://` checks the server's certificate and name and
  completes the handshake before `AUTH`, an optional `OIDF_REDIS_CA_FILE`, `redis://` refused under the
  production profile, a URL's userinfo never quoted in a message; store verdicts are
  `FIRST_USE | REPLAY | STORE_UNAVAILABLE` and `CONSUMED | UNKNOWN | STORE_UNAVAILABLE`, an outage answered
  503 `temporarily_unavailable` and never "replay"; keys under `oidf:as:*`, `oidf:cas:*`,
  `oidf:fed:endpoint:*` and `oidf:admin:dpop:*`. The store interfaces' abstract methods are now `record` and
  `consumeChallenge`.
- **Evidence digested and bound** (S3b) - the attestation carries `workload.instance_attestation_sha256`,
  `_type` and `_exp` and never the evidence (`workload.svid` and `workload.instance_attestation` are gone);
  the digest is the SHA-256 of the evidence's JWS Signing Input, so a re-encoded token is the same evidence;
  evidence binds to the first instance key and client that present it, a second presenter is 401
  `instance_attestation_bound` and an `attestation.evidence.conflict` audit event naming both keys; evidence
  lifetime, whole and remaining, capped at a day in production, the attestation's `exp` never past the
  evidence's.
- **CIMD refused outside development** (M-1) - `OIDF_ATTESTER_CIMD_URL` is honoured only under
  `OIDF_DEPLOYMENT_PROFILE=development`; elsewhere the source is left out with an ERROR naming it, and the CAS
  document does not list `cimd` among its metadata sources.

- **RAR containment model** (S1a) - `libs/rar-model`, JDK only: per-type field rules (`set`, `set_of_values`, `limit`
  with a paired unit, `amount`, `instant_limit`, `equal`, `string`, `object`, `forbidden`), alternatives for a thing
  a type can say two ways, the built-in `sales_agent`, `payment_initiation` and `account_information` models, more
  from `OIDF_RAR_MODELS_FILE` / `OIDF_RAR_MODELS`, strict `contains`, `authorize` with inheritance, and the meet
  `intersect`, over lists held to fixed limits (numbers by the digits they would write); a SHA-256 fingerprint of
  the effective model and the library's semantics; 244 vectors in a test-jar and seeded property tests. The
  library alone: S1b and S1c, below, move the authenticator, the issuer and the plugin onto it, and with them B1
  is closed in this release.

- **S2a, S2b RAR plugin: fail-open and the principal** (blocker B3, F-0003; the "fail-open catches everything"
  high, F-0016) - fail-open is confined to a connection refused or reset, an unresolved name, a deadline, or HTTP
  429/502/503/504, so a 401 from a wrong secret, a body that is not a JSON object, a status line or header the
  client cannot parse (F-0093) and a TLS failure deny; a governance answer's `authorised` must be a boolean;
  "Deny unless PERMIT" is gone and the decision is always deny-unless-PERMIT; the shared secret is an encrypted
  field under the same name (the upgrade from v0.3.0 rehearsed on the rig); the PDP URL must be https and "Skip
  TLS verification" is inert unless `OIDF_DEPLOYMENT_PROFILE=development`; the governance-engine request writes
  the server's attributes last and refuses a field that names one, every `req_`/`att_` mirror included (F-0073);
  `principal_source` is resolved per flow from the user key PingFederate 13.1.3 passes (client credentials
  `client`, refresh and the code flow `authenticated`, CIBA `identity_hint`, token exchange `none` until the
  filter publishes a verified subject, F-0074), and `login_hint` / `_principal_sub` are development-only;
  `payment_initiation` and `account_information` are refused before any PDP call without an authenticated
  principal; the PDP request carries the attester `iss`; logs carry the principal hashed;
  `conformance/verify-rar-principal.sh` drives the flows on the rig.

- **SSF push is no longer starved by paused, disabled or poll backlogs, and no single POST holds it past
  10 s** (S10-0, the B5 stopgap) - the stores select only enabled push streams' SETs; a stream whose delivery
  fails waits out its first SET's backoff as a whole, so the SET that failed goes first and the rest follow
  by `issuedAt`, SETs of the same second by `jti` rather than in the order they were generated (F-0095); the
  POST has deadlines (connect 2 s, exchange 10 s, body read to 4 KiB) and its connection is closed at the
  deadline; the loop starts from the load-on-startup servlet; a store that is down at boot is logged, without
  its `jdbcUrl`, and retried every 30 s instead of failing `pf-runtime.war`; and the stores' push selection
  runs against Postgres in CI (`SsfStoresOnPostgresTest`). An enabled stream with 500 due SETs older than
  another's still fills the batch, and a slow receiver still holds the one thread for up to 10 s a SET, until
  S-10.
- **device-enrolment's unauthenticated `POST /compliance` is gone** (M-2, the B4 mitigation) - compliance
  reaches the registry through a verified SET at PingFederate's SSF receiver and nowhere else; the README
  says why the device path is not production-usable until Phase 6.
- **IOM schema v2 proposed** (X-A03) - [docs/device/iom-schema-v2-proposal.md](docs/device/iom-schema-v2-proposal.md),
  the MAY attributes, view, roles, lease attributes and start-up check the device path needs, written as a
  diff against the model as it is, for David to raise in idp-scim-service.

- **The release waits for its Build** (P0-6, a Phase 0 leftover; F-0069) - `release.yml`'s green-Build gate
  judges the Build workflow's own run on the tagged commit: the newest run a push to `main` or a dispatch
  started, and the latest attempt of each required job in it. A pull request's Build no longer counts, and the
  job's permission `checks: read` is now `actions: read`. The gate reads the runs every 30 seconds for up to 20
  minutes while that run is queued, pending or in progress, then fails on any conclusion but success, after two
  minutes when there is no such run (Build never started on the commit), after three refused reads in a row, and
  at the limit. A `required-checks.txt` that names no job now fails it too; before 0.4.0 it passed. v0.3.0's
  release had failed on a `java` job still running and was re-run by hand.

- **Phase 1 follow-ups** (package HYG, PR #33; plan items X-D02, R-I1, P0-7, M-2, R-CI4 and R-CI5; closes F-0014 and
  F-0066, opens F-0120, F-0121 and U-0130, updates F-0006) - Build's `java` job runs `RedisLiveTest`'s plain half
  on a `redis:7-alpine` service and its TLS half on a TLS-only Redis that `tools/ci/start-tls-redis.sh` starts
  with a CA and a localhost certificate made for the run, and fails if the suite skipped a test; CodeQL does not
  analyse the iOS client's Swift yet, for the reason U-0130 records; the showcase describes the image as the
  staging profiles and the entrypoint left it and the release as its gate runs now; the device-instance,
  device-enrolment and ssf READMEs describe the code as it is.

- **The containment model wired into the token gate and the attester** (S1b, design S-1, blocker B1; PR #37) -
  the authorization server's token gate and the attester compare every `authorization_details` field with
  `libs/rar-model`, a refused request is 400 `invalid_authorization_details`, and an instance ceiling keeps what
  its client's constrains. Closes [F-0034](docs/findings/F-0034.yaml) and [F-0038](docs/findings/F-0038.yaml),
  and with S1c [F-0001](docs/findings/F-0001.yaml); adds [F-0100](docs/findings/F-0100.yaml) and
  [U-0110](docs/findings/U-0110.yaml).

- **The RAR plugin asks the containment model** (S1c; PR #36) - the plugin shades and relocates `libs/rar-model`
  and asks it every containment question - a request before the PDP, the PDP's answer after it (narrow, never
  widen), a refresh against its grant - and compares the attestation context's `rar_models_fingerprint` with its
  own. `RarContainment` and its contract test
  are gone. Closes F-0031 and, with S1b, F-0001 (blocker B1); closes F-0106. New in the register: F-0105, F-0106,
  F-0107, F-0108, U-0115 and U-0116.

- **The attestation PoP audience and the DPoP `htu`** (S4a, its audience and `htu` parts; the ceiling refusal
  code is S1b's; PR #34) - a Client Attestation PoP must name this server's issuer and nothing else, and a
  combined-mode DPoP proof the endpoint URL PingFederate advertises, never one rebuilt from the `Host` header.
  Closes F-0110 and F-0111.

- **Separate challenges for the authorization server and the attester** (S4b; PR #35) - the attester gets its
  own challenge endpoint, `GET /federation/attestation/challenge`, issuing into `oidf:cas:challenge:*`; the
  authorization server keeps `POST /federation/attestation-challenge` in `oidf:as:challenge:*`; a challenge from
  either is refused at the other, and each surface's metadata names only its own endpoint. Closes F-0037. New in
  the register: F-0115, F-0116, F-0117, F-0118 and U-0125.

- **Release-note fragments** (D-7, brought forward in part) - a pull request describes what it changes for a
  consumer in `docs/releases/unreleased/<ID>.md`; `tools/release-notes.py check` holds each fragment to four
  headings and a numbered "Before you deploy" of bold-titled items in the Docs workflow, and `assemble <version>`
  folds them into the release's notes and this file when it is cut. 0.4.0's notes were assembled with it.

## [0.3.0] - 2026-09-27

The first release for PingFederate 13.1.3, and the release that completes OpenID Federation. Notes:
[docs/releases/0.3.0.md](docs/releases/0.3.0.md); the move from v0.1.5:
[docs/operator/upgrading/0.1.5-to-0.3.0.md](docs/operator/upgrading/0.1.5-to-0.3.0.md).

- **PingFederate 13.1.3 and `jakarta.servlet`** - the 0.2.0 cut-over, folded in: every servlet, filter and war is
  compiled against 13.1.3 and does not load on 13.0.x; the RAR plugin reads `getJakartaRequest()` and no longer
  links on 13.0 (PR #7); `pf-13.0` is frozen at v0.1.5, with no backports; upgrades are supported from 0.3.0
  onward.
- **OpenID Federation 1.0, complete** (PR #5): trust chains checked as the Final text says, against pinned anchor
  keys; automatic registration at the token, authorization and PAR endpoints and explicit registration, every
  registration ending with its chain; the token endpoint fail-closed; Trust Marks verified, required and issued;
  every federation endpoint; a policy engine asked over AuthZEN; decisions logged as events.
- **The rig** - `conformance/up.sh` runs a configured PingFederate 13.1.3 from a clone, and the FAPI 2.0, SSF,
  CAEP, FAPI-CIBA and both OpenID Federation plans have been run against it (results in
  [conformance/README.md](conformance/README.md)).
- **Shared Signals** - streams belong to the receiver that created them; SET expiry is enforced; SCIM
  provisioning takes its own scope; the transmitter emits what the CAEP Interop Profile asks.
- **Attestation** - each client bound to the attesters that may vouch for it; the bridge assertion addressed to
  the issuer alone, as a string; the bank's self-signed agents and their mission (PR #6); App Attest on macOS 27
  (PR #9).
- **Release hygiene** - one PingFederate version in `build/pf-version.env` with the image pinned by digest, one
  project version across the reactor with gm-api in the lockstep, and a release workflow that publishes the
  build it verified, with a dry run (PR #10); the docs describe 13.1.3 (PR #8).

## 0.2.0 - 2026-09-24, never tagged

The modules moved to `jakarta.servlet` and PingFederate 13.1.3 became the base (commit `12626ec`). It was the
working version of `main` until 0.3.0 and was never released; everything it held is in 0.3.0. Plan and evidence:
[docs/pf-13_1-jakarta-migration-plan.md](docs/pf-13_1-jakarta-migration-plan.md).

## [v0.1.5] - 2026-09-24

The last `javax.servlet` release, for PingFederate 13.0.x, on the `pf-13.0` branch: everything up to and
including the FAPI-CIBA rig, built on 13.0.3. Supersedes v0.1.4, which was cut before the CAEP Interop and CIBA
work. A 13.0.x consumer pins here; the branch is frozen from 2026-09-26.

## [v0.1.4] - 2026-09-23

The last release built against `javax.servlet` when it was cut, with the assemble script refusing a war whose
staged jars are compiled against the wrong servlet namespace, the FAPI 2.0 profile filter and the SSF
transmitter conformance work, and SSF stream ownership. `PROVENANCE.txt` began stating which PingFederate line
a build targets.

## [v0.1.3] - 2026-08-30

The agent attestation profile with executable conformance, the coverage pass, and the dormant-defect fixes.

## [v0.1.2] - 2026-08-22

Per-client bridge signing, verified-context claims, and no bundled attester trust - the released artefact stopped
being the vulnerable one.

## [v0.1.1] - 2026-08-22

The first complete published build: the PF module set, wars and plugin jars, with `SHA256SUMS` and
`PROVENANCE.txt` recording the commit, so a consumer can pin a build and tell when it is behind. Carries the
Tier 0/1/2 security work. Supersedes v0.1.0.

## [v0.1.0] - 2026-08-22

The release workflow, so a consumer could tell when it was behind. It published its Maven artefacts and then
failed before creating a release; nothing consumed it.

[Unreleased]: https://github.com/dphhyland/pf-agentic-identity/compare/v0.5.0...main
[0.5.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.5.0
[0.4.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.4.0
[0.3.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.3.0
[v0.1.5]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.5
[v0.1.4]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.4
[v0.1.3]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.3
[v0.1.2]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.2
[v0.1.1]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.1
[v0.1.0]: https://github.com/dphhyland/pf-agentic-identity/releases/tag/v0.1.0
