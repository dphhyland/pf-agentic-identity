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
looks like - or has no body, and logs why with the criterion's name. PingFederate would deny either way: a
throwing criterion denies with the criterion's Error Result (`invalid_grant` on the client-credentials grant,
verified on the rig with 13.1.3.0 on 2026-09-26, finding [U-0015](../../docs/findings/U-0015.yaml)), but the
log would not say why. `ClientAttestationUtils.validateClientAttestation` in `servlets/pf-integration` is the
same boundary written out by hand; nothing calls the guard yet. S-9's rule that a disabled or failed component's
criteria answer `false` (S9b, Phase 3) is where it gets its first callers.

## Future owners' sections

<!-- settings (ST-1, ST-2): add this package's section below this line -->
<!-- audit (O-1): add this package's section below this line -->
<!-- health (O-4): add this package's section below this line -->
<!-- lifecycle (F-2): add this package's section below this line -->
<!-- internals (F-1, PfInternals): add this package's section below this line -->

## Build

```sh
mvn -pl libs/platform-pf -am verify     # -> target/platform-pf-<version>.jar (tests on)
```

Needs PingFederate's two provided jars installed, as `servlets/pf-integration` does (see
[CONTRIBUTING.md](../../CONTRIBUTING.md)). The coverage gate is 100% line and branch per method over the
methods named in `pom.xml`, each package's under its own anchor.
