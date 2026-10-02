# The start-up audit banner

From 0.5.0, every war built from this repository logs one banner to server.log as it finishes starting (plan item
F-2): `pf-runtime.war`, on PingFederate's runtime port, and `gm-api.war` or the demo-only `oidf.war` where they are
deployed. It says what the war runs and how it is configured. Nothing needs configuring. From 0.6.0 it also lists
what the production profile refused ([deployment-profile.md](deployment-profile.md)): the refusing itself happens
earlier, before any filter or servlet starts, and is logged there once, at ERROR under production and at WARN under
development, one line per violation.

It is one INFO event on the logger `com.pingidentity.ps.oidf.platform.pf.lifecycle.LifecycleListener`, logged after
the war's filters and load-on-startup servlets have started, so the component states are the ones they reached.
From PingFederate 13.1.3.0 on the conformance rig (2026-09-28):

```
INFO  [com.pingidentity.ps.oidf.platform.pf.lifecycle.LifecycleListener] Start-up audit for / (ROOT):
  version:        0.5.0-SNAPSHOT
  commit:         unknown (no build records it yet: finding F-0190)
  PingFederate:   13.1.3.0
  Java:           21.0.12.1+1-LTS
  profile:        development (OIDF_DEPLOYMENT_PROFILE is 'development')
  topology:       standalone
  accepted risks: none
  risk refusals:  none
  violations:     none
  code refusals:  none
  profile notes:  none
  legacy values:  none
  insecure TLS:   none
  JDK host names: checked
  components:     ATTESTATION_AUTH DISABLED
                  AUTO_REGISTRATION FAILED_CONFIG: FrontChannelAutoRegistrationFilter: OIDF_FEDERATION_TRUST_ANCHOR_JWKS is unset: ...
                  FAPI READY
                  FEDERATION READY
                  SSF READY
  executors:      ssf-push-delivery
  metrics MXBean: com.pingidentity.ps.oidf:type=Metrics,copy="com.pingidentity.ps.oidf.platform.metrics from file:/opt/out/.../WEB-INF/lib/platform-0.5.0-SNAPSHOT.jar"
  platform:       file:/opt/out/instance/work/jetty-0_0_0_0-9031-pf-runtime_war-_-any-/webapp/WEB-INF/lib/platform-0.5.0-SNAPSHOT.jar
```

## What each line means

| Line | Meaning | What to look for |
|---|---|---|
| `version` | this repository's release, from the jars | the release you meant to deploy |
| `commit` | the commit it was built from | `unknown` for now: no build records it where PingFederate can read it ([F-0190](../findings/F-0190.yaml)) |
| `PingFederate` | PingFederate's version, from `pf-commons.jar` | the version the release supports (13.1.3) |
| `Java` | the JVM PingFederate runs on | |
| `profile` | `development` or `production`, and what `OIDF_DEPLOYMENT_PROFILE` said | `production` everywhere but a rig or a demo; unset, blank or misspelt reads as production |
| `topology` | `standalone` | always `standalone` until 0.7.0 tells a cluster from one node |
| `accepted risks` | each risk `OIDF_ACCEPTED_RISKS` accepts, its expiry and what it lets happen | anything you did not mean to accept |
| `risk refusals` | how many `OIDF_ACCEPTED_RISKS` entries were not accepted - unknown, expired, undated where a date is needed, with a date that is not a real YYYY-MM-DD date, empty, or named twice | anything but `none`: each is also logged at WARN on the same logger, naming the entry |
| `violations` | each violation of the production profile the start-up sweep found, labelled `REFUSED:`, `not refused (development):`, `not refused (switched off):` when every component it names is switched off, `not refused (names no component):`, or `not refused (not switched on):` for a required setting of a component not switched on | anything `REFUSED`: that component answers 503 until the setting is fixed or its risk accepted |
| `code refusals` | each component a package refused in code, for a condition that is not a setting (a store in memory without the `in-memory-state` risk) | anything at all in production |
| `profile notes` | the sweep's warnings: an `OIDF_*` name under no catalogue's family, a refused `OIDF_ACCEPTED_RISKS` entry, a legacy spelling | a misspelt name |
| `legacy values` | each setting read so far from a spelling only the reader before 0.6.0 took (development only), and what it was read as | the strict spelling to write instead |
| `insecure TLS` | each setting that turned certificate or host-name checking off in this war, and since when | anything at all in production |
| `JDK host names` | whether `jdk.internal.httpclient.disableHostnameVerification` switches host name checking off for every Java HTTP client in the JVM | `checked` in production; from 0.6.0 production refuses every component while the property is set, with any value, even `false`, which the JDK reads as checked |
| `components` | each feature's state and, when it is not serving, why | the same states `/agentic-identity/health` reports ([health.md](health.md)) |
| `executors` | the background jobs this war runs | |
| `metrics MXBean` | the JMX name of this war's metrics | |
| `platform` | where this war's copy of the shared library was loaded from | a path inside the war's own `WEB-INF/lib` |

Each value is one line of at most 256 characters; control and line-separator characters are shown as `?`, because
two of the lines quote what an operator set.

## Once per war, once per start

The banner appears once each time a war starts. `pf-runtime.war` and `gm-api.war` each log their own, because each
has its own copy of the library, with its own components; the copy PingFederate's OGNL expressions use, in
`server/default/deploy`, logs none. If a war's listener finds it was handed a copy its own classloader did not load,
it logs a WARN saying so and does nothing else - no mark, no banner, no shutdown.

## At shutdown

When a war stops, the listener closes what that war opened - background jobs, its metrics MXBean, its Redis
connections - within five seconds, and logs `Lifecycle listener: <war> stopped; closed <n>: ...`. You see that line
when a war is undeployed. You do not see it when PingFederate itself stops: PingFederate stops its logging before it
destroys its webapps ([F-0210](../findings/F-0210.yaml)). It still calls their listeners - a probe listener on the rig
wrote a file from its `contextDestroyed` at `docker stop -t 30` - but that the close finishes before the JVM exits has
not been seen ([U-0220](../findings/U-0220.yaml)).

Give PingFederate time to stop. On the rig (Docker Compose 5.1.3) the container was created with a one-second stop
timeout, so a plain `docker stop` killed PingFederate after one second (exit 137), while `docker stop -t 30` let it
stop cleanly in about five seconds (exit 0) ([F-0211](../findings/F-0211.yaml)). Set a grace period of ten seconds or
more wherever PingFederate runs.
