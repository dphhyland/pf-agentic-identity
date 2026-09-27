# Classloaders

The same class from this repository is loaded more than once inside one PingFederate JVM, by different
classloaders, and each loaded copy is a separate class to the JVM. Five rules follow from that. Each names the
code that shows it today and the loaders it applies to. They bind [libs/platform](../../libs/platform/README.md)
and [libs/platform-pf](../../libs/platform-pf/README.md) (plan item F-1) and every module that uses them.

## The loaders

| Loader | What it loads from | What runs there |
|---|---|---|
| The webapp's | `pf-runtime.war`'s `WEB-INF/lib`, where `assemble-pf-runtime-war.sh` merges the staged jars | the servlets, the filters over PingFederate's own endpoints, their `init` and `destroy` |
| The engine's | `server/default/deploy`, where the Dockerfile copies the same jars | the OGNL issuance criteria and access-token mapping expressions |
| A plugin's | the plugin's own jar in `server/default/deploy`, with what it shades | the RAR plugin, the instance-registry data store, the CIBA simulator |
| A separate war's | that war's own `WEB-INF/lib` | `gm-api.war`; `oidf.war`, which is demo-only packaging (plan decision 17) |

All of them see `server/default/lib` - jose4j, Jackson, commons-logging, log4j - which is why the staged jars
bring none of those ([build/pingfederate/stage-modules.sh](../../build/pingfederate/stage-modules.sh), its
header). A standalone service (`services/device-enrolment`) runs in its own JVM, and none of this applies to it.

## 1. Statics are per loader

A `static` field holds one value per loaded copy, not one per JVM. The webapp's copy and the engine's copy of
`AttestationSupport` each have their own `LOCK`, Redis client and in-memory challenge and replay stores
([AttestationSupport.java](../../libs/client-attestation/src/main/java/com/pingidentity/ps/oidf/clientattestation/AttestationSupport.java),
lines 30-37); without Redis the filter and the OGNL criterion therefore keep separate stores, which the
Dockerfile records as deliberate ([Dockerfile](../../build/pingfederate/Dockerfile), lines 86-89). The same holds
for platform: `Lifecycle.current()` and `Components` are one per loaded copy, so the webapp's copy registers
and closes only what the webapp opened, and health reads the webapp's components, not the engine's.

Applies to every loader. The copies are:

- the webapp's, from `WEB-INF/lib`;
- the engine's, from `server/default/deploy`;
- one relocated copy per plugin that shades platform;
- one per separate war that bundles it, such as `gm-api.war`.

## 2. Only the webapp's copy starts threads

Background work starts from a servlet's or filter's `init`, which only the webapp's loader runs; the engine's
copy has no servlet lifecycle - nothing calls an `init` or a `destroy` for jars in `server/default/deploy` -
so a thread it started would have nothing to stop it. Every thread the repository starts inside PingFederate today follows this:

- the registration sweeper, started by `TokenEndpointAutoRegistrationFilter`'s `init`
  ([RegistrationExpirySweeper.java](../../servlets/pf-integration/src/main/java/com/pingidentity/ps/oidf/servlet/clientregistration/RegistrationExpirySweeper.java),
  `startOnce`);
- the subordinate refresher, started by `OpenIdFederationServlet`'s `init` (`FederationService.prewarmSubordinatesAsync`);
- the SSF push, poll and boot-retry schedulers, started from `SsfHttp.bootstrap(ServletConfig)`, which the SSF
  servlets' `init` calls.

Each of them starts through platform's `ManagedExecutors` (C-3), as `oidf-<name>-1`
([libs/platform, exec](../../libs/platform/README.md#exec)), which refuses a start in a plugin's relocated copy, in
a copy whose lifecycle has shut down, and for a job already running anywhere in the JVM (rule 4). A copy cannot
tell by itself which loader it is in: `Lifecycle.loaderRole()` says `WEBAPP` once the webapp's lifecycle listener
(F-2) has called `markWebapp()`, and `UNKNOWN` everywhere else. Until F-2 lands, the engine's copy is kept from
starting threads only by nothing in it calling a start; refusing every unmarked copy is
[F-0200](../findings/F-0200.yaml). The one other thread platform starts is `Lifecycle`'s short-lived closer, one
per resource during shutdown, and one when a `register()` after shutdown closes its resource at once, in whichever
copy registers it; it starts through `ManagedExecutors.startDaemon` and is refused nowhere, because it is what
closes the executors.

Applies to the engine's copy and the plugins' copies, which must start none.

## 3. Code an OGNL criterion reaches never throws

A criterion that throws denies: PingFederate answers the criterion's Error Result, `invalid_grant` on the
client-credentials grant, verified on the rig with 13.1.3.0 on 2026-09-26
([U-0015](../findings/U-0015.yaml)). But the log then names the criterion's failure and not its cause. So an
entry point OGNL calls catches everything - an `Error` too, because a `NoClassDefFoundError` from a jar missing
on the engine's classpath is the likeliest failure there - logs it, and answers `false`: catch, deny, emit.
`ClientAttestationUtils.validateClientAttestation`
([ClientAttestationUtils.java](../../servlets/pf-integration/src/main/java/com/pingidentity/ps/oidf/servlet/clientregistration/utils/ClientAttestationUtils.java),
the shell at lines 95-132 and the body's catches at 189-205) does it by hand; `CriterionGuard.evaluate` in
platform-pf is the same boundary as one call. The body must be a separate method or lambda from the one OGNL
calls, because a linkage error surfaces where a class is first resolved.

Applies to the engine's copy.

## 4. Loaders talk only through request attributes with string keys, and the JVM-wide System properties already in use

Two copies of a class are two classes, so an object of one cannot be cast to the other, and a static set in one
is invisible to the other. What crosses between loaders is what both see from the JDK:

- **Request attributes with string keys, holding JDK types.** The filter on the webapp's loader stores the
  verified attestation under `com.pingidentity.ps.oidf.attestation.verified` and the criterion on the engine's
  reads it back; the RAR plugin reads `com.pingidentity.ps.oidf.rar.attestation_context` from its own loader
  (`ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE` and `RAR_ATTESTATION_CONTEXT_ATTRIBUTE`, lines 51-72).
  The plugin cannot share the constant, so both sides write the literal and `RarContextKeyTest` holds them equal.
- **The JVM-wide System properties already in use.** The registration sweeper records its owner in
  `oidf.registration.sweeper.owner` under a lock on `System.class`, so two filter instances, or two copies,
  never start two sweepers (`RegistrationExpirySweeper.OWNER_PROPERTY` and `startOnce`), and gives it back when
  its executor closes. Managed executors do the same for every job: `oidf.exec.owner.<name>` holds the id of the
  copy running the job named `<name>`, set and cleared under the same lock, so one of each job runs in the JVM
  whichever copy starts it (`ExecutorRegistry.claim` and `release`). The reasoning is the sweeper's: a
  background job started twice does its work twice, against the same PingFederate and the same stores, and a
  System property is the one thing every loader sees. The subordinate refresher is the exception: it warms its
  own `FederationService`'s cache, so a second instance whose refresher is refused is left cold
  ([F-0202](../findings/F-0202.yaml)).

Nothing else: no shared static, no interface one copy implements and another calls, no new System property
without the same reasoning written beside it.

Applies between every pair of loaders.

## 5. A plugin shades and relocates platform

A plugin that uses platform bundles its own copy, relocated into the plugin's package, as the RAR plugin does
Jackson and rar-model ([plugins/rar-paz-plugin/pom.xml](../../plugins/rar-paz-plugin/pom.xml), the
`maven-shade-plugin` block and the comment above it). Relocated, the plugin's copy can never be the class
another jar's code links to, whatever order PingFederate's loaders search in. commons-logging stays
`provided` and is not shaded, so the relocated copy logs through PingFederate's own
([libs/platform, Logging](../../libs/platform/README.md#logging)). The RAR plugin and ciba-sim shade platform
this way (PR-1), under `com.pingidentity.ps.oidf.rar.shaded.platform` and
`com.pingidentity.ps.oidf.cibasim.shaded.platform`; each plugin's `ShadedJarCheck` fails the build if a class
in the jar still names platform's own package.

Applies to the plugins' loaders.
