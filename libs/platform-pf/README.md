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
<!-- audit (O-1): add this package's section below this line -->

## audit

`PfAuditSink` is PingFederate's event sink (plan item O-1), the logic `PfAuditEventSink` in servlets/pf-integration
held until now; that class stays as a delegating shim, so its callers' `install()` is unchanged. Every event goes to
server.log through a `LoggingSink`; an event marked audit, while `OIDF_EVENTS_AUDIT` is not `false`, also goes to
PingFederate's audit log through the SDK's `LoggingUtil`. Before either write the event is admitted by its
catalogue, and the audit record is passed through the `PiiPolicy` for the audit log (platform's README, "events").

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
<!-- lifecycle (F-2): add this package's section below this line -->
<!-- internals (F-1, PfInternals): add this package's section below this line -->

## Build

```sh
mvn -pl libs/platform-pf -am verify     # -> target/platform-pf-<version>.jar (tests on)
```

Needs PingFederate's two provided jars installed, as `servlets/pf-integration` does (see
[CONTRIBUTING.md](../../CONTRIBUTING.md)). The coverage gate is 100% line and branch per method over the
methods named in `pom.xml`, each package's under its own anchor.
