# CI refuses a direct setting read or an outbound client outside platform

## Changelog

- CI refuses a direct setting read outside platform (plan item ST-6): `tools/direct-read-scan.py`, in the Build
  workflow's lint job, fails on `System.getenv`, `System.getProperty`, `System.getProperties`, `Boolean.getBoolean`,
  `Integer.getInteger`, `Long.getLong` and `getInitParameter` - called, statically imported or handed on as a method
  reference such as `System::getenv` - in the main code of any module the root pom lists, outside `libs/platform`
  and platform-pf's `settings` package. Read a setting through `platform.settings` (`Settings`, `Sources`, and
  `InitParams` for a servlet's init-params) instead.
- CI refuses an outbound client outside `platform.http` (plan item ST-6): `tools/outbound-scan.py` fails on
  `java.net.http`, `HttpURLConnection` and `HttpsURLConnection`, `openConnection` and `openStream`, a raw socket, and
  the third-party clients it names (Apache HttpClient, OkHttp, Jetty's client, Netty, Spring's clients, JAX-RS,
  Kafka's and others) - imported, used by name or named in a string for a reflective load. Call through
  `OutboundHttp`, which carries the deadline, the address policy and the TLS trust.
- Each hit is printed as `path:line: what it is, and the allow-list line that would admit it`. The allow-lists,
  `tools/direct-read-allow.txt` and `tools/outbound-allow.txt`, admit a module only if it is never shipped
  (`libs/testkit`, `services/harness`), and anything else by file and line pattern, with a finding id or a reason.
  CI runs both scans with `--check-allow-list`, which also fails a line that admits nothing, so converting a read
  means deleting its line.

## Before you deploy

None.

## Notes

The scans run on the main this package was built from (e377dbae, 2026-10-01) with 61 direct reads and 19 outbound
sites admitted. Of the direct reads, most are the process's environment or system properties handed to platform -
`Sources.of`, `Settings.of`, `DeploymentProfile.of` - through a constructor a test calls with its own map, which is
the seam platform's API asks for; one, the registration sweeper's `oidf.registration.sweeper.owner`, is a JVM-wide
claim rather than a setting. Five findings record the reads the ST-5 packages left: F-0420 (attestation-issuer's
`IssuedTtlCap` and `AttesterResolvers`), F-0421 (pf-integration's `OperatorApi.setting`, whose registered-clients
switch parses with `Boolean.parseBoolean`), F-0422 (platform-pf's audit sink and the operator authenticator's static
bearer), F-0423 (the RAR plugin's `OIDF_RAR_EXTRA_TYPES`) and F-0424 (four servlets that hand `config::getInitParameter`
on where `InitParams.of` exists). Each is open, targeted at 0.7.0, and admitted by id; the scan refuses an id whose
finding is closed, so each line goes when its finding does. The outbound sites are class-path reads in platform and
platform-pf (catalogues, the build facts), platform's Redis connection, `InsecureTls`'s builder hook, and Kafka's
producer, loaded by reflection, which is not HTTP.

What the scans do not see, each in its docstring: a read or a client reached through reflection other than a
client's package named in a string, a lookup handed on under another name and applied later, and anything outside
Java. `services/gm-api/examples` is not a reactor module and is not read. Finding F-0025 is the umbrella; this package
does not close it.
