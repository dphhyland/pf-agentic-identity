# platform-pf

platform's PingFederate side: the shared code that only runs inside PingFederate (plan item F-1, decision 10).
Package `com.pingidentity.ps.oidf.platform.pf`, one subpackage per owner. Depends on
[platform](../platform/README.md); `pingfederate-sdk`, `pf-protocolengine`, `jakarta.servlet-api`, `log4j-api`
and `commons-logging` are `provided`, because PingFederate 13.1.3 ships each of them, and they are all declared
now so the packages that add the audit sink, health servlets, lifecycle listener and internals facade add code
without editing the dependency list. `servlets/pf-integration` depends on it, and `stage-modules.sh` stages its
jar beside the other modules, into the war and onto the engine's classpath. How the two copies behave is in
[docs/development/classloaders.md](../../docs/development/classloaders.md).

## Who owns what

As in platform: each package writes only in its own subpackage, adds jacoco includes only under its own
anchor comment in `pom.xml`, and adds its section here only under its own anchor below. This table is written
once, with every owner, so nobody edits it.

| Subpackage | Holds | Package (plan item) | Phase 2 wave |
|---|---|---|---|
| `ognl` | `CriterionGuard`: the boundary an OGNL issuance criterion runs behind | F1 (F-1), then S-9 | 1 |
| `settings` | the settings PingFederate supplies (init-params, extended properties) | ST12 (ST-1, ST-2) | 2 |
| `audit` | `PfAuditSink`, events into PingFederate's audit log | O1 (O-1) | 2 |
| `health` | the health servlets | O4 (O-4) | 3 |
| `lifecycle` | the lifecycle listener: start-up audit, banner, MBeans, clean shutdown | F2 (F-2) | 4 |
| `internals` | `PfInternals`, one facade over the PingFederate internals the repository calls | PFI (F-1) | 4 |

## ognl

`CriterionGuard.evaluate(name, body)` runs an issuance criterion's body and answers what it answers, or
`false` when it throws - an `Error` included, because a `NoClassDefFoundError` is what a missing staged jar
looks like - or has no body, and logs why with the criterion's name. The logged line carries the exception's
class and message as one line of at most 256 characters, control, format and separator characters replaced
with `?`, because a message can carry request-derived text; the stack trace still goes to the log. PingFederate would deny either way: a
throwing criterion denies with the criterion's Error Result (`invalid_grant` on the client-credentials grant,
verified on the rig with 13.1.3.0 on 2026-09-26, finding [U-0015](../../docs/findings/U-0015.yaml)), but the
log would not say why. `ClientAttestationUtils.validateClientAttestation` in `servlets/pf-integration` is the
same boundary written out by hand; nothing calls the guard yet. S-9's rule that a disabled or failed component's
criteria answer `false` is `component.CriterionGate` ([component](#component)), the first statement of each OGNL
entry point.

## Future owners' sections

<!-- settings (ST-1, ST-2): add this package's section below this line -->

## settings

`InitParams` makes a servlet's or filter's init-params the `init-param` source of
[platform's settings](../platform/README.md#settings): `InitParams.of(config)` is the lookup, and
`InitParams.sources(config)` is this process's environment and system properties with it, so a servlet reads
its catalogued settings as `Settings.of("<component>").with(InitParams.sources(config))`, in the precedence its
catalogue gives. A null config has no init-params. Nothing calls it yet: the readers move onto `Settings` in
ST-5 (Phase 3). The extended properties and plugin fields PingFederate supplies are parsed, not resolved
(`Settings.parse`), so they need no source here.
<!-- audit (O-1): add this package's section below this line -->

## audit

`PfAuditSink` is PingFederate's event sink (plan item O-1), the logic `PfAuditEventSink` in servlets/pf-integration
held until now; that class stays as a delegating shim, so its callers' `install()` is unchanged. Every event goes to
server.log through a `LoggingSink`; an event marked audit, while `OIDF_EVENTS_AUDIT` is not `false`, also goes to
PingFederate's audit log through the SDK's `LoggingUtil`. Before either write the event is admitted again by its
catalogue (`readmit`: `Events.emit` has counted it), and the audit record is passed through the `PiiPolicy` for the
audit log, the caller's address as `NETWORK` (platform's README, "events").

The record's columns: `event` (the code), `status`, `subject` (the event's subject), `connectionid` (its partner),
`protocol`, `role`, `ip` (the caller's address, from the supplier the sink is given - pf-integration's
`PfRequestScope`), the request `jti` and a description carrying the reason and fields. `protocol` is per component, from
its catalogue's `auditProtocol`: `OpenID Federation` for `federation`, `Client Attestation` for
`attestation-issuer`, and `DEFAULT_PROTOCOL` (`OpenID Federation`) for a component with no catalogue. The writer
calls `LoggingUtil.init`, the setters and `log`, and puts `protocol` in the log4j `ThreadContext` under the key
PingFederate's own AuditLogger uses, never through `LoggingUtil.setProtocol`, which on 13.0 and 13.1 writes the `ip`
column. It never calls `LoggingUtil.cleanup` (H-FED-7, finding [F-0049](../../docs/findings/F-0049.yaml)): on 13.1.3
`cleanup` removes every audit column on the thread, and a record written in the middle of one of PingFederate's own
requests (an OGNL issuance criterion at the token endpoint) emptied the columns of PingFederate's own line for that
request - its event, subject, ip, client, protocol and host (rig, 2026-10-01). The writer copies the whole
`ThreadContext` first, starts the record from the request's correlation keys alone (`trackingid`, `transactionid`,
`httprequestid`), and in a `finally` puts back exactly what was there. `LoggingUtilAuditWriterTest` pins it through the
SDK's `LoggingUtil`.

`OIDF_EVENTS_AUDIT` (system property `oidf.events.audit` first) and `OIDF_EVENTS_MAX_VALUE_LENGTH` keep their names
and meanings: audit is on unless the value is `false`, and a value that is neither `true` nor `false` leaves it on
with a WARN; the cap is `LogSafe`'s, and a value that is not a number is warned about and ignored. Both WARN lines
are now on the logger `com.pingidentity.ps.oidf.platform.pf.audit.PfAuditSink`. `PfAuditSink.install(Supplier)`
installs the sink in platform's registry directly, for the emitters O-2 moves; nothing calls it yet.

<!-- health (O-4): add this package's section below this line -->
## health

`HealthServlet` serves the health endpoints (plan item O-4) from platform's decisions
([libs/platform, health](../platform/README.md#health)). It is an `@WebServlet`, so it is mapped in whichever war has
platform-pf's jar in `WEB-INF/lib` and answers from that war's own component registry:

| Path | Who | Answer |
|---|---|---|
| `GET /agentic-identity/health/live` | anyone | 200 `{"status":"UP"}` while the webapp answers |
| `GET /agentic-identity/health/ready` | anyone | 200 `{"status":"UP"}`, or 503 `{"status":"DOWN"}` when an enabled component is not ready |
| `GET /agentic-identity/health` | an operator token with `oidf.health.read` | each component's state, reason and parts, the profile and the versions, with ready's code |
| `GET /agentic-identity/info` | the same | `{"agentic-identity": ..., "commit": null, "pingfederate": ..., "java": ...}` |

Live and ready say nothing but the status. The detail and info are operator routes (`HealthServlet.ROUTES`,
`health.detail` and `health.info`), answered through this webapp's `OperatorAuthenticator` (plan item S8b): a
PingFederate-issued access token with `oidf.health.read`, DPoP-bound in production, and in development the static
bearer `OIDF_AUTHORITY_ADMIN_TOKEN` as well; a refusal is the authenticator's 401, 403, 429 or 503 with its
challenge ([operator-authentication.md](../../docs/operator/operator-authentication.md)). The second copy of the
static-bearer rule that lived here, `HealthAccess`, is gone (finding [F-0194](../../docs/findings/F-0194.yaml)). A
war that bundles this jar without rs-validation (gm-api.war) cannot load the authenticator, so its detail and info
answer 503. Only GET and HEAD are served (405 otherwise, before any token is looked at), and
every answer is JSON with `Cache-Control: no-store`. `BuildInfo` reads the versions from the jars on each request:
this repository's from platform-pf's `pom.properties`, PingFederate's from `pf-commons.jar`'s, the JVM's from the
runtime; nothing records the commit yet (finding [F-0190](../../docs/findings/F-0190.yaml)).

**Where it is mapped.** In `pf-runtime.war`, where `assemble-pf-runtime-war.sh` merges the staged jars, so on
PingFederate's runtime port; `HealthPathsTest` holds the four paths clear of every servlet mapping in 13.1.3's stock
`pf-runtime.war` web.xml (a fixture read from the image on 2026-09-28) and of every `@WebServlet` path in this
repository. The engine's copy in `server/default/deploy` is never scanned for annotations and never serves a request.
`oidf.war`, the demo-only packaging, bundles platform-pf through pf-integration and so answers at
`/oidf/agentic-identity/health/...` from its own registry.

**gm-api.war (the decision F-2 needs).** gm-api's web.xml has `metadata-complete="false"`, so once F-2 bundles
platform-pf in it the container maps this servlet there too, at `/gm-api/agentic-identity/health/...` on the same
runtime port. That is kept: gm-api.war is its own war and classloader with its own registry, so its health must
be its own - the pf-runtime.war answer says nothing about whether gm-api deployed - and the plan's contract puts a
service's health beside the service. Its readiness is UP until gm-api registers a part; F-2 registers one from
gm-api's `init` (a component name of its own, such as `GM_API`, since S-9 names none) so that a gm-api that failed
to start reads DOWN. The detail and info take the same bearer: the token is JVM-wide.

<!-- component (S9a): this package's section -->
## component

`ComponentGate` is plan item S-9's per-surface rule (S9a's fail-closed floor, replaced by S9b): the first statement
of every request method of a component's servlets and filters, so a surface whose `init` no longer throws does not
serve half-configured, and one whose component is off or failed does what S-9's table says. It reads the surface's
own part ([libs/platform, health](../platform/README.md#health)) through `Part.gateView()`, without a lock, and the
component only when a part of it is `REFUSED` (the programme's decision 4). A part is serving when `READY` or
`DEGRADED` with no part of its component refused; failed when `STARTING`, `FAILED_CONFIG`, `FAILED_DEPENDENCY`,
`REFUSED` or a sibling refused; no part (`init` never ran) is serving. Each method answers `true` when the gate
answered or passed the request on, and the caller returns.

| Method | Serving | Disabled | Failed |
|---|---|---|---|
| `federationEndpoint(part, response)` | `false` | 404 `{"error":"not_found",...}` | 503 `{"error":"temporarily_unavailable","error_description":"<COMPONENT> is not available"}` |
| `oauthEndpoint(part, response)` (SSF, the attester, the challenge endpoints) | `false` | 404, no body | the same 503 |
| `autoRegistration(part, request, response, chain, clients)` | `false` | a request naming a federation client: 401 `invalid_client`; the rest down `chain` | a request naming a federation client: 503; the rest down `chain` |
| `attestation(part, request, response, chain, rules)` | `false` | where `rules` authenticates: attestation headers 401 `invalid_client`, a client `rules` refuses without an attestation refused by it; the rest down `chain` | the same, with 503 for attestation headers |
| `filter(part, request, response, chain, traffic)` (FAPI, with its client list) | `false` | down `chain` | `traffic`: 503; the rest down `chain` |
| `emits(part)` (the logout filter) | `true` | `false` | `false` |

A request names a federation client (`namesFederationClient`) when its `client_assertion` carries a `trust_chain`
header or cannot be read, or when a client it names - the assertion's `sub`, `client_id`, or the
`OAuth-Client-Attestation`'s `sub` - is an Entity Identifier that `clients` (pf-integration's `FederationClientLookup`,
over PingFederate's client store) reports as unknown or registered through the federation; a store that cannot answer
makes it 503. The bodies are JSON with `Cache-Control: no-store`.

`CriterionGate.serves(component, criterion)` is the OGNL entry points' first statement. In a loader whose registry has
the component it answers from the registry; in the engine's copy, whose registry is empty, from the enable switch and
`ProfileRefusals.refused`, once per component, and it logs why a criterion answers `false` once per component at WARN.
What operators see is in [docs/operator/components.md](../../docs/operator/components.md#each-surfaces-rule).

<!-- lifecycle (F-2): add this package's section below this line -->
## lifecycle

`LifecycleListener` is the one `ServletContextListener` this repository ships (plan item F-2). It works on the copy
of platform its own war loaded, and on no other:

- **`contextInitialized`** marks that copy as the webapp's (`Lifecycle.markWebapp()`), registers its metrics MXBean
  (`Metrics.registerMXBean()`), runs the production profile's sweep, and arranges the start-up audit. The sweep
  (plan item PR-5) is `ProfileAudit.evaluate` over the process's environment and system properties and every
  catalogue the war's loader sees, published in platform's `ProfileRefusals` before any filter's or servlet's `init`,
  so `Startup.begin` makes each part of a refused component `REFUSED` and its gate answers 503. It is logged once:
  at ERROR when a violation refuses something (production), at WARN otherwise, every violation on its own line and
  labelled `REFUSED:`, `not refused (development):` or, for a required setting of a component not switched on,
  `not refused (not switched on):`. A sweep that fails - a fault in this code, never a setting - refuses every
  component under production. The audit It adds a servlet, `oidf-startup-audit`, with no
  mapping and load-on-startup `Integer.MAX_VALUE`; the container initialises filters before servlets and
  load-on-startup servlets in ascending order, so that servlet's `init` runs after the war's filters and other
  load-on-startup servlets have registered their components, and it logs the banner, once, at INFO. A container
  that will not add a servlet then (a listener that was itself added programmatically) gets the banner at once,
  with whatever components had registered by then.
- **`contextDestroyed`** runs the copy's `Lifecycle.shutdown` within five seconds (`SHUTDOWN_BUDGET`, under
  `docker stop`'s default ten with PingFederate's own shutdown still to come) - the managed executors, the metrics
  MXBean and the Redis pools, last registered first - and logs one line naming each close and how it ended. That line
  reaches server.log when a war is undeployed (gm-api.war removed from `server/default/deploy` on the rig), but not
  when the JVM stops: PingFederate stops its logging before it destroys its webapps' contexts (finding
  [F-0210](../../docs/findings/F-0210.yaml)).

**The loader check.** Before either, the listener compares the loader that defined its copy of `Lifecycle` with the
war's own (`ServletContext.getClassLoader()`). The same jars sit in `server/default/deploy`, on the engine's loader,
where the OGNL criteria run; a war whose loader asked its parent first would see that copy, and marking it or
shutting it down would close what the criteria use. When the two loaders differ the listener logs a WARN and does
nothing else.

**Where it is registered, and why by name.** In `pf-runtime.war` through `build/pingfederate/filters.xml`, whose
`<listener>` entry the war assembler writes into the war's `web.xml` and checks is there exactly once; in
`oidf.war`'s and `gm-api.war`'s `web.xml`. It carries no `@WebListener` annotation. An annotated one would run: on the rig (PingFederate 13.1.3.0, Jetty
12.0.36.1, 2026-09-28) a probe `@WebListener` in a jar in `pf-runtime.war`'s `WEB-INF/lib`, with no `web.xml` entry,
ran once per boot, and the same jar in `server/default/deploy` ran in no context, the engine's or any other war's
(finding [U-0024](../../docs/findings/U-0024.yaml)). It is registered by name all the same: the same jars sit in both
places and the engine's loader must never run it, so the registration should not depend on which jars a container
scans; a named entry is one registration the assembler checks, in the one war; and a war with
`metadata-complete="true"` would silently drop an annotated listener.

**The banner**, one INFO event on the logger `com.pingidentity.ps.oidf.platform.pf.lifecycle.LifecycleListener`:

| Line | What it says |
|---|---|
| `version` | this repository's version, from platform-pf's `pom.properties` (`BuildInfo`, as `/agentic-identity/info` reads it) |
| `commit` | `unknown`: no build records the commit where a running PingFederate can read it (finding F-0190). `BuildInfo` is where it would be read, from a manifest entry the build sets from `GITHUB_SHA`; the banner follows it |
| `PingFederate` | PingFederate's version, from `pf-commons.jar`'s `pom.properties` - the file PingFederate's own `VersionUtil` reads - through `BuildInfo`, not through PingFederate's internals |
| `Java` | the running JVM's version |
| `profile` | `development` or `production`, and how `OIDF_DEPLOYMENT_PROFILE` said so (`DeploymentProfile.describe`) |
| `topology` | `standalone` until C-1 (Phase 4) can tell a cluster from one node |
| `accepted risks` | each risk `OIDF_ACCEPTED_RISKS` accepts, with its expiry and what it lets happen |
| `risk refusals` | how many entries did not parse, were unknown, expired or repeated; each is also logged at WARN, naming it, and its risk is not accepted, so a switch that needs it refuses its components |
| `violations` | the sweep's violations, each labelled as the sweep's log labels it |
| `code refusals` | each refusal made in code so far (`ProfileRefusals.refuse`: an in-memory store, say) |
| `profile notes` | the sweep's warnings: an `OIDF_*` name under no catalogue's family, a refused `OIDF_ACCEPTED_RISKS` entry, a legacy spelling |
| `legacy values` | each setting read so far from a legacy spelling (development only), and what it was read as |
| `insecure TLS` | each setting that asked `InsecureTls` for a trust-all context in this war so far, and since when |
| `JDK host names` | whether `jdk.internal.httpclient.disableHostnameVerification` turns the JDK HTTP client's host name check off for the whole JVM |
| `components` | each registered component's state and reason, as health reads them |
| `executors` | this copy's managed executors |
| `metrics MXBean` | the name this copy's MXBean is registered under |
| `platform` | where this copy of platform was loaded from: the war's `WEB-INF/lib` |

Every value is one line of at most 256 characters, with control, format and separator characters replaced by `?`,
because the profile and the risk refusals quote what an operator set; the sweep's own log entry carries each
violation whole. Under production the audit then emits one `platform.profile.refused` event per violation that
refuses something, the sweep's and those made in code - audited, so they reach PingFederate's audit log once the
war's `init`s have installed its sink.

**gm-api.war** bundles platform-pf, and platform through it, in its own `WEB-INF/lib`, so it has its own copy: its
own lifecycle, components, metrics MXBean and banner, and its own health under `/gm-api/agentic-identity/health/...`
(the decision O-4 recorded above). `GrantsServlet` and `McpServlet` register the parts of a component of its own,
`GM_API` (S-9 names none for gm-api), so a gm-api whose servlets failed to start reads `FAILED_CONFIG` in its
banner and DOWN on its ready.

**What it does not do.** It does not stop the war: a refused component answers 503 on its own surfaces while
PingFederate's own endpoints keep serving. It does not make `ExecutorRegistry` refuse an
unmarked copy (finding F-0200): that is one check in platform.exec, now that the webapp's copy is marked, and it is
C-3's code to change; a standalone program using platform would then need to mark itself, which X-A01's service-kit
is the place for. The engine's copy is never marked and never shut down: nothing runs a listener for
`server/default/deploy`, and its MXBean stays until the JVM stops, which is what keeps the OGNL criteria's metrics
visible (the Phase 2 plan's risk 12).

<!-- internals (F-1, PfInternals): add this package's section below this line -->
## internals

`PfInternals` is the one class that calls PingFederate's internal services (plan item F-1, decision 10): classes in
`pf-protocolengine.jar` that are not part of the SDK and, the plan's risks say, "can change in a patch release".
Each member is one call, made when it is called; nothing runs when the class loads, so loading it touches no
PingFederate class, and outside a booted PingFederate each member throws where the caller reaches it, as the
direct call did.

| Member | Calls | Callers |
|---|---|---|
| `issuer(request)` | `OAuthIssuerUtils.getInstance().getIssuerValue(request)` | the issuer resolvers of eight classes in pf-integration and two in attestation-issuer |
| `tokenEndpointBaseUrl()` | `MgmtFactory.getAuthzServerManager().getTokenEndpointBaseUrl()` | `ClientAttestationUtils.configuredTokenEndpointBaseUrl` |
| `addClient`, `updateClient`, `getClient`, `getClients` | the same methods of `MgmtFactory.getClientManager()` | `PfMgmtClientStore` |
| `isBackendDatabase()` | `MgmtFactory.getClientManager().isBackendDatabase()` | nothing yet: C-1 (Phase 4) |
| `discoveryHandler(openIdConnect)` | `ProviderConfigurationInfoHandler.createOpenIDConnectProviderConfigurationInfoHandler()` or `createOAuthProviderConfigurationInfoHandler()`, then `process` | `PfProviderMetadata` |

`ClientManager.isBackendDatabase()` exists in 13.1.3 as `public abstract boolean isBackendDatabase()` on
`org.sourceid.oauth20.domain.ClientManager` (javap on the pinned image's `pf-protocolengine.jar`, 2026-09-28).

**No production class outside platform-pf names `org.sourceid.oauth20.issuer`, `org.sourceid.saml20.domain.mgmt`,
`org.sourceid.openid.connect.handlers`, `ClientManager` or `AuthzServerManager`.** `InternalsBoundaryTest` holds
it over every `src/main` Java source under libs, servlets, services and plugins (a wildcard import of
`org.sourceid.oauth20.domain` counts, since it would let a source name either manager by its simple name), with one
recorded exception:
servlets/ssf's `PfIdTokenVerifier` still calls `OAuthIssuerUtils` itself, because package PFI's scope stopped at
pf-integration, attestation-issuer and platform-pf ([F-0215](../../docs/findings/F-0215.yaml)). The test fails
when that file stops naming it, so the exception goes with the fix.

**The data types stay where they are.** `Client` is what the client manager takes and returns, and `ParamValues`
and `ClientAuthenticationType` are what a `Client` holds. Wrapping them would copy some thirty `Client` accessors
into a type of our own that still links every one of them, and add a translation to keep in step; the facade
would hide nothing. What checks them is `tools/pf-linkcheck.py`, which resolves every member the built jars link
against the pinned PingFederate, in CI's java job.

**Tests.** `PfInternalsTest` replaces PingFederate's statics and checks that each member makes its one call with
its caller's arguments and answers what PingFederate answers, and that the class initialises in a loader with no
PingFederate class on it. `issuer` is not in the coverage gate: `OAuthIssuerUtils` is final and Mockito cannot
redefine it on the test class path ("class redefinition failed: invalid class", 2026-09-28), so its test shows
only that outside PingFederate the lookup throws a `LinkageError`, which is why every caller has an issuer seam.
The callers' own tests keep those seams; none mocked PingFederate's statics, so none needed the facade replaced.

### What the reactor links from PingFederate

Every `org.sourceid.*` and `com.pingidentity.*` class the shipped jars and `gm-api.war` link, read from their
constant pools by `tools/pf-linkcheck.py`'s scanner against 13.1.3.0's `server/default/lib` on 2026-09-28, after
this package. Where a class ships decides its kind: `pingfederate-sdk.jar` is the SDK plugins compile against,
whatever the package; `pf-protocolengine.jar` is PingFederate's own engine.

| Kind | Classes (members linked) | Jar | Linked from |
|---|---|---|---|
| Internal service | `OAuthIssuerUtils` (2) | pf-protocolengine | platform-pf; ssf's `PfIdTokenVerifier` ([F-0215](../../docs/findings/F-0215.yaml)) |
| Internal service | `MgmtFactory` (2), `ClientManager` (5), `AuthzServerManager` (1), `ProviderConfigurationInfoHandler` (3) | pf-protocolengine | platform-pf only |
| Internal data type | `org.sourceid.oauth20.domain.Client` (32: the constructor, getters and setters) | pf-protocolengine | pf-integration, attestation-issuer |
| SDK data type | `org.sourceid.oauth20.domain.ParamValues` (3), `ClientAuthenticationType` (1) | pingfederate-sdk | pf-integration, attestation-issuer |
| SDK | `org.sourceid.saml20.adapter.*` - `AttributeValue`, `conf.Configuration`, `conf.Field`, `conf.SimpleFieldList`, the `gui` descriptors and validators | pingfederate-sdk | pf-integration, gm-api, the RAR plugin, the instance-registry data store |
| SDK | `org.sourceid.util.log.AttributeMap` | pingfederate-sdk | gm-api |
| SDK | `com.pingidentity.access.*` - `AccessGrantManagerAccessor`, `DataSourceAccessor`, `JwksEndpointKeyAccessor` | pingfederate-sdk | pf-integration, ssf, gm-api |
| SDK | `com.pingidentity.sdk.*` - `accessgrant`, `authorizationdetails`, `logging.LoggingUtil`, `oauth20.Scope`, `oobauth`, `GuiConfigDescriptor`, `PluginDescriptor` | pingfederate-sdk | platform-pf (`LoggingUtil`), ssf, gm-api, the RAR plugin, ciba-sim |
| SDK | `com.pingidentity.sources.*` - the custom data source driver and its descriptors | pingfederate-sdk | the instance-registry data store |

The scanner does not see names in strings: servlets/ssf's `SsfAuditLogSource` names five of PingFederate's audit
logger classes (`org.sourceid.websso.profiles.idp.IdpAuditLogger` and four more) as log4j logger names, which
change with nothing linking them.


<!-- auth (S8a): add this package's section below this line -->
## auth

`OperatorAuthenticator` decides who may use an operator API (plan item S8a; the programme's decision 1): a
PingFederate-issued access token, verified against PingFederate's JWKS (`jwt` mode) or its introspection endpoint
(`introspection` mode, platform's `TokenIntrospector`), whose `iss` is PingFederate's issuer through
`PfInternals.issuer` (in introspection mode only when the answer carries one: RFC 7662 §2.2 makes it optional, and
PingFederate 13.1.3's answer for a reference token has none), whose `aud` holds `OIDF_OPERATOR_AUDIENCE`, bound in production by DPoP or a client
certificate, and carrying the route's scope. The actor is the token's `sub`, never a header. Each request it lets
through or refuses emits `admin.request.authorised` or `admin.request.refused` from the `operator` event catalogue.
Failed authentications are limited to 10 a minute per client address and changes to 60 a minute per actor, in Redis
when `OIDF_REDIS_URL` names one. The scopes are `OperatorScopes`, one per surface; a surface names its routes in an
`OperatorRoutes` table and calls `authorise(request, response, route)`, going on only when it answers true.

DPoP is checked in one place (Phase 3 decision 8): the authenticator hands the token, the proof, the method, the
configured base URL plus the path, and the container's client certificate to rs-validation's
`DelegatedTokenValidator`, which uses oidf-jose's `DpopProofValidator`. So platform-pf depends on rs-validation,
declared optional so that a war bundling platform-pf does not take it until it uses the authenticator;
stage-modules.sh stages its jar into PingFederate beside this one.

Nothing calls it in this release: plan item S8b moves the operator surfaces onto it. The settings (the
`operator-auth` catalogue), what each request goes through, every refusal and what PingFederate needs are in
[docs/operator/operator-authentication.md](../../docs/operator/operator-authentication.md).
`OperatorAuthenticatorRigTest` runs it against a running PingFederate when `OIDF_TEST_OPERATOR_RIG` names a file of
tokens minted there; `OperatorRateLimitTest` runs the limits and the replay store on Redis when
`OIDF_TEST_REDIS_URL` is set, as build.yml's java job sets it.


## Build

```sh
mvn -pl libs/platform-pf -am verify     # -> target/platform-pf-<version>.jar (tests on)
```

Needs PingFederate's two provided jars installed, as `servlets/pf-integration` does (see
[CONTRIBUTING.md](../../CONTRIBUTING.md)). The coverage gate is 100% line and branch per method over the
methods named in `pom.xml`, each package's under its own anchor.
