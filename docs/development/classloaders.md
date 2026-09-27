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

A copy cannot tell by itself which loader it is in. `Lifecycle.loaderRole()` says `WEBAPP` once the webapp's
lifecycle listener (F-2) has called `markWebapp()`, and `UNKNOWN` everywhere else, so code that starts a thread
can refuse to in any copy not marked. Managed executors (C-3) will start threads only there. The one thread
platform starts itself is `Lifecycle`'s short-lived closer, one per resource during shutdown, which only the
webapp's listener calls; C-3 is where it moves onto the managed executors.

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
  never start two sweepers (`RegistrationExpirySweeper.OWNER_PROPERTY` and `startOnce`).

Nothing else: no shared static, no interface one copy implements and another calls, no new System property
without the same reasoning written beside it.

Applies between every pair of loaders.

## 5. A plugin shades and relocates platform

A plugin that uses platform bundles its own copy, relocated into the plugin's package, as the RAR plugin does
Jackson and rar-model ([plugins/rar-paz-plugin/pom.xml](../../plugins/rar-paz-plugin/pom.xml), the
`maven-shade-plugin` block and the comment above it). Relocated, the plugin's copy can never be the class
another jar's code links to, whatever order PingFederate's loaders search in. commons-logging stays
`provided` and is not shaded, so the relocated copy logs through PingFederate's own
([libs/platform, Logging](../../libs/platform/README.md#logging)). No plugin uses platform yet; PR-1 applies
the shading when the first one does.

Applies to the plugins' loaders.
