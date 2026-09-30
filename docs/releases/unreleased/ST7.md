# oidf-preflight.jar: the production profile's check on an env file, with every catalogue in one jar

## Changelog

- New release asset `oidf-preflight.jar` (plan item ST-7, under F-0025): platform's `Preflight` with platform's classes
  and all 28 settings catalogues of the reactor in one jar, built by a new module, `tools/preflight`.
  `java -jar oidf-preflight.jar --env-file FILE [--profile production|development] [--accepted-risks IDS]` judges an
  env file as the release's start-up sweep would and exits 0 when nothing would be refused, 1 when a component would
  be, and 2 when it cannot read its arguments or the file. `--accepted-risks` judges with that list in place of the
  file's `OIDF_ACCEPTED_RISKS`; `--list` prints every catalogue it holds with its module and entry counts. Its
  manifest names the version, the commit and the catalogues.
- The build fails when a reactor module's catalogue is not in the jar, or differs from the jar's copy: a module that
  gains a catalogue is held until `tools/preflight/pom.xml` takes it in.
- CI runs the jar on java 17, java 21 and the java in PingFederate's image against two fixtures, a clean env file and
  one with a line of each violation kind; the release copies it into its assets and `SHA256SUMS`, and publishes it to
  GitHub Packages as `com.pingidentity.ps.oidf:oidf-preflight`.
- [docs/operator/preflight.md](../../operator/preflight.md) says how to run it on a Docker env file, a Kubernetes
  ConfigMap and PingFederate's `run.properties`, what each exit status and each line means, and what it cannot check.

## Before you deploy

1. **Run `oidf-preflight.jar` against your environment before upgrading.** What to do: take `oidf-preflight.jar` from
   the assets of the release you are moving to, check it against that release's `SHA256SUMS`, and run
   `java -jar oidf-preflight.jar --env-file <your env file>` (Java 17 or later) on each environment's settings before
   you deploy, with the JVM's `-D` options and PingFederate's `run.properties` system properties in one `JAVA_OPTS`
   line ([docs/operator/preflight.md](../../operator/preflight.md) gives the lines for a Docker env file, a Kubernetes
   ConfigMap and `run.properties`). It supersedes the class-path command in "Run the preflight against your
   environment before you upgrade": that command sees only the catalogues of the jars you put on the class path, and
   a module left out has its rules left out without a word. Why: from 0.6.0 an unset `OIDF_DEPLOYMENT_PROFILE` is
   production, and production refuses components for settings this release checks; the jar shows each refusal before
   the node starts. How to tell: exit 1, and each `REFUSED:` line names the setting, the fix and the components it
   refuses; exit 0 means nothing the start-up sweep judges would be refused - a setting the server refuses only when it
   reads it (a removed name, a value that does not parse where the profile governs nothing, a name set beside its
   `_FILE` variant) is not judged, so check those by hand (F-0427); exit 2 means the file could not be read, naming the line. What to
   change: fix each `REFUSED:` line, accept its risk in `OIDF_ACCEPTED_RISKS` (try it first with
   `--accepted-risks`), or switch the component off with `OIDF_<COMPONENT>_ENABLED=false`. In a Docker env file,
   write values without quotes, or run the file through the `sed` line in the guide: Docker passes quotes to the
   process and the preflight removes them (F-0426). Development-profile escape: none is needed - the jar changes
   nothing in a deployment; on a file with `OIDF_DEPLOYMENT_PROFILE=development` it lists what production would
   refuse as `not refused (development)`, and refuses only a switch that does not parse.

## Notes

- What it cannot check: it judges settings, not what only a running node knows - whether a database, Redis, a
  decision point, a key store or a trust anchor answers; PingFederate's own configuration (data stores, OAuth clients
  and their extended properties, plugin fields, the licence); certificates; the stores refused in code
  (`in-memory-state`); and anything the file leaves out, such as an image's own `ENV` lines or a Secret not exported.
  It holds every catalogue of the release, where each process loads its own: `OIDF_CIBA_SIM_ENABLED=true` is refused
  here though a production image stages no simulator, and a device-enrolment name in PingFederate's file draws no
  warning (F-0425, low, open for 0.7.0).
- F-0427 (medium, open for 0.7.0): the jar, like PR5's `Preflight`, runs the profile audit and not the refusals a
  server makes when a component reads a setting. A removed name still set (`OIDF_BRIDGE_PRIVATE_JWK`), a value the
  strict parser refuses on a setting the profile does not govern (`OIDF_AUTO_REGISTRATION_FRONT_CHANNEL=yes`,
  `OIDF_REGISTRATION_MAX_TTL_SECONDS=abc`) and a secret set beside its `_FILE` variant all exit 0 here and are refused
  on the component's first read (checked 2026-10-01). The fix is in PR5's `ProfileAudit`, which ST7 was not to change.
- F-0426 (low, open for 0.7.0): PR5's reader removes one pair of quotes around a value, and `docker run --env-file`
  does not (Docker 29.4.1, checked 2026-10-01), so `OIDF_FETCH_ALLOW_HTTP="false"` in a Docker env file is clean here
  and refused by the server. The guide's `sed` line makes the preflight see what Docker passes.
- Verified 2026-10-01 on this branch: `mvn verify` of `tools/preflight` on JDK 17.0.11 and 20.0.2, with
  PreflightJarCheck running the packed jar on both; the fixtures by hand on the PingFederate 13.1.3 image's java
  21.0.12.1 (clean exit 0, violations exit 1 with 8 refusing lines, output identical to JDK 20's); the rig's
  `conformance/vars.env` exits 0 under its own `development` profile and 1 with `--profile production` (4 refusing
  lines). Taking `services/gm-api/servlet` out of the module's dependencies failed the build naming
  `gm-api.json`. Two builds of the jar on JDK 17 were byte-identical, which the release's rebuild comparison needs.
- PingFederate puts every `run.properties` line into the JVM's system properties at start: 13.1.3's
  `org.pingidentity.RunPF.main` loads the file named by `-Drun.properties` and calls `System.getProperties().putAll`
  with it (`javap -c` of `bin/pf-startup.jar` in the image, read 2026-10-01). So `oidf.mock.attesters` or the JVM-wide
  hostname flag in `run.properties` counts as it does in `JAVA_OPTS`, and the guide feeds both to the preflight.
- The jar's entry point, `PreflightJar`, sits in platform's package in the new module, so it calls PR5's
  package-private `Preflight.run`, `report` and file reader rather than a copy: without `--accepted-risks` the check
  is `Preflight.run` itself, and a test holds the two to the same output and status on both fixtures and both
  profiles. `--list` and `--accepted-risks` are the jar's own; PR5's class is unchanged.
- [docs/operator/deployment-profile.md](../../operator/deployment-profile.md)'s "Before you deploy: Preflight" and
  PR5's fragment still give the class-path command and say "a later 0.6.0 package ships it as
  `oidf-preflight.jar`": the release package points both at the jar and puts its command first in the upgrade guide.
