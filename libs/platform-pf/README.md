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
criteria answer `false` (S9b, Phase 3) is where it gets its first callers.

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
calls `LoggingUtil.init`, the setters, `log` and, in a `finally`, `cleanup`, in the order `PfAuditEventSink` did,
and puts `protocol` in the log4j `ThreadContext` under the key PingFederate's own AuditLogger uses, never through
`LoggingUtil.setProtocol`, which on 13.0 and 13.1 writes the `ip` column. Whether `cleanup` also strips
PingFederate's own audit context is finding [F-0049](../../docs/findings/F-0049.yaml) (H-FED-7, Phase 3).

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
| `GET /agentic-identity/health` | the admin bearer | each component's state, reason and parts, the profile and the versions, with ready's code |
| `GET /agentic-identity/info` | the admin bearer | `{"agentic-identity": ..., "commit": null, "pingfederate": ..., "java": ...}` |

Live and ready say nothing but the status. The detail and info answer only a caller whose `Authorization` header
is `Bearer <token>` for the static admin token the federation operator API uses (`OIDF_AUTHORITY_ADMIN_TOKEN`,
system property `oidf.authority.admin_token` first) - Phase 2's decision 6 - and anyone else, including every caller
of a deployment with no token set, gets the container's 404 for every method, as an unmapped path does.
`HealthAccess` repeats pf-integration's `AdminBearer` rule, because platform-pf cannot depend on pf-integration
(finding [F-0194](../../docs/findings/F-0194.yaml)); S8b (Phase 3) moves both to the operator scope
`oidf.health.read`. Only GET and HEAD are served (405 otherwise, after the bearer check on the restricted two), and
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

<!-- lifecycle (F-2): add this package's section below this line -->
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


## Build

```sh
mvn -pl libs/platform-pf -am verify     # -> target/platform-pf-<version>.jar (tests on)
```

Needs PingFederate's two provided jars installed, as `servlets/pf-integration` does (see
[CONTRIBUTING.md](../../CONTRIBUTING.md)). The coverage gate is 100% line and branch per method over the
methods named in `pom.xml`, each package's under its own anchor.
