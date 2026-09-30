# The services read their settings strictly and refuse what production forbids

## Changelog

- device-enrolment reads every setting through its `device-enrolment` catalogue with platform's `Settings` (plan
  item ST-5): a switch is `true` or `false` in any case, a number a whole number in its range, a choice one of its
  choices, and a value that does not parse stops the service naming it (`device-enrolment did not start: ...`, exit
  status 1). `REQUIRE_COMPLIANT_DEVICE` is no longer read leniently (finding F-0024, closed). The old `env(...)`
  helper is gone.
- device-enrolment runs the production profile's start-up audit over its own catalogue before it wires anything
  (plan items PR-3 and PR-5). Under production `REQUIRE_COMPLIANT_DEVICE=false`, `APPLE_ALLOW_DEVELOPMENT=true`,
  `PF_AUTHORITY_INSECURE_TLS=true`, a set `PF_AUTHORITY_ADMIN_TOKEN`, a value of any of those four that does not
  parse, and `REGISTRY=memory` without the `in-memory-state` risk each stop the process with exit status 1, every
  violation listed on stderr at once. Under development each is a warning. A `jdbc:` URL in `IDM_DATABASE_URL` for
  a database other than PostgreSQL is refused in every profile, naming only its scheme.
- gm-api reads `pdpUrl`, `pdpToken`, `audience`, `pdpTimeoutMs`, `issuer` and `grantManagementEndpoint` through its
  `gm-api` catalogue, strictly, init-param first and then the environment as before. The PDP URL must be `https`
  unless `OIDF_DEPLOYMENT_PROFILE=development` (plan item PR-3); an `http` one fails init and leaves `GM_API`
  `FAILED_CONFIG`, the reason naming `pdpUrl`.
- gm-api emits `gm.grant.evaluated` (the PDP's permit or deny, with its reason id), `gm.grant.refused` (the
  authorization server's refusal before the PDP is asked) and `gm.grant.revoked`, from its own `gm` event catalogue
  (plan item O-2): each is audited and counted in `oidf_events_total`, and carries the grant id and client id
  (pseudonymous), never a token, a consent's contents or the PDP's messages.
- ciba-sim refuses under the production profile whatever `OIDF_CIBA_SIM_ENABLED` says - its decision endpoint
  answers 404 and its authenticator fails every request - with one ERROR at the first refusal (plan item PR-3). It
  reads `OIDF_CIBA_SIM_ENABLED` and `OIDF_CIBA_SIM_DIR` strictly through its catalogue.
- The instance-registry data source has a new first field, **PingFederate data store**, the SDK's JDBC data store
  selector: the production way to the registry, through PingFederate's pool and credentials (plan item PR-3). The
  **JDBC URL** field is development only: under the production profile the driver refuses it at configure and
  answers every lookup with the refusal, naming the data store field. A data store that is not PostgreSQL is refused
  under production at the first lookup. A **User verification max age (seconds)** that is not a whole number now
  configures nothing, instead of falling back to 300. libs/platform is shaded into the plugin's jar.
- The attestation flow harness turns the JDK client's host name check off only with `OIDF_HARNESS_INSECURE_TLS=true`,
  read strictly; a live run without it checks the certificate's name as well as its chain (finding F-0162, closed).
- gm-api's example client `GrantManagementClient.java` takes `--cacert FILE` to trust a self-signed or private-CA
  PingFederate; `--insecure` and its trust-all are gone, and so is its exemption from `tools/trust-scan.py` (finding
  F-0163, closed).

## Before you deploy

1. **device-enrolment refuses to start in production on a forbidden setting.** What to do: before upgrading, check
   the service's environment for `REQUIRE_COMPLIANT_DEVICE=false`, `APPLE_ALLOW_DEVELOPMENT=true`,
   `PF_AUTHORITY_INSECURE_TLS=true`, `PF_AUTHORITY_ADMIN_TOKEN` and `REGISTRY=memory`, and every switch and number it
   is given. Why: `OIDF_DEPLOYMENT_PROFILE` unset is production (0.6.0's "secure by default"), and a device-enrolment
   that mints for an unassessed device, accepts development App Attest or trusts any certificate is not a production
   service; it is one component with no PingFederate to keep serving, so it stops rather than serves in part. Every
   setting is read strictly too: a switch is `true` or `false` in any case, and until 0.6.0 anything but `true` was
   quietly `false` (`REQUIRE_COMPLIANT_DEVICE=yes` turned the compliance check off). What now happens: the process
   exits with status 1, and stderr says "device-enrolment refused to start by the production profile
   (OIDF_DEPLOYMENT_PROFILE is unset, which is production), for N setting(s):" and lists each, or "device-enrolment
   did not start:" and names the setting that does not parse. How to tell: run it, or run platform's Preflight over
   the service's env file with the service's jar on the class path, so it reads the same catalogue. What to change: remove the
   forbidden switches or set them to their defaults; for an in-memory registry add `in-memory-state` to
   `OIDF_ACCEPTED_RISKS`, or point `IDM_DATABASE_URL` at the Identity Object Model's PostgreSQL; write every switch
   as `true` or `false`. Development-profile escape: with `OIDF_DEPLOYMENT_PROFILE=development` each forbidden value
   is a warning at start, and a legacy spelling (`yes`, `no`, `1`, `0`, `on`, `off`, a padded number) is read as the
   old reader read it - a switch as `false` - with a warning naming the strict spelling. The device path is still not
   production-usable until Phase 6.
2. **Point the instance-registry data source at a PingFederate data store.** What to do: in PingFederate's Data Stores,
   open the Custom data store "Agent Instance Registry", choose the registry's database in the new **PingFederate data
   store** field - a JDBC data store on the Identity Object Model's PostgreSQL, created under Data Stores first - and
   clear **JDBC URL**. Why: the JDBC URL field carries the database's credentials in the plugin's configuration and
   opens a connection per lookup outside PingFederate's pool; the catalogue classes it `forbidden-in-production`, and
   from 0.6.0 the driver itself refuses it, since a plugin's fields are read at configure and not seen by the start-up
   sweep. What now happens under production with the URL set: every lookup fails with "the agent instance registry data
   source is not configured: JDBC URL is set, which the production profile forbids ... Choose the registry's database in
   'PingFederate data store' instead", logged at ERROR once at configure and then again, with "instance registry lookup
   failed", on every lookup, so an issuance criterion on `instance_active` refuses every token. A data store whose
   database is not PostgreSQL fails every lookup too: the refusal naming `INSTANCE_REGISTRY` is logged at ERROR once,
   and each failed lookup logs its own ERROR. How to tell: the data store's connection test fails, and server.log has
   the ERRORs. What to change: the fields, as above; PingFederate's image carries no PostgreSQL JDBC driver, so the JDBC
   data store needs one in `server/default/lib` (F-0330). A **User verification max age (seconds)** that is not a whole
   number also fails every lookup now, naming the field. Development-profile escape: under development the JDBC URL
   still works when no data store is chosen, and a data store on another database is a warning.
3. **gm-api's PDP must be https in production.** What to do: set `pdpUrl` on both the grants and the mcp servlet in
   gm-api.war's `web.xml` to the PDP's `https` URL. Why: the PDP's answers decide every grant evaluation and the PDP
   bearer token travels with each request, so the call is not made in the clear. What now happens: with an `http`
   URL under production both servlets fail init, as a missing `pdpUrl` always has, and `GM_API` is `FAILED_CONFIG`
   with the reason "pdpUrl (init-param, or AUTHZEN_BASE_URL) is an http URL, and the production profile requires the
   PDP to be reached over https ...". The shipped `web.xml` sets
   `http://host.docker.internal:9099`, a demo value, so a production gm-api.war fails until it is edited; the
   environment variables `AUTHZEN_BASE_URL` and `GM_AUDIENCE` are still read only when the init-param is removed
   (F-0238, which X-C02 fixes). How to tell: server.log has that `ServletException` for the grants and mcp servlets.
   What to change: the init-param, to an `https` URL; `pdpTimeoutMs` must be a whole number and
   `grantManagementEndpoint` an http or https URL, or the servlet fails init naming it. Development-profile escape:
   with `OIDF_DEPLOYMENT_PROFILE=development` an `http` PDP is allowed.
4. **ciba-sim will not run in production.** What to do: if you stage `pf.plugins.ciba-sim.jar` in an image of your
   own, keep it to images that run with `OIDF_DEPLOYMENT_PROFILE=development`, and remove it from any other. Why: the
   simulator approves a CIBA request for anyone who knows its `auth_req_id`; this repository's image stages it only
   for the conformance profile, but a consumer's image can carry it, and `OIDF_CIBA_SIM_ENABLED` being forbidden in
   production refuses nothing unless the plugin itself refuses. What now happens under production, whatever
   `OIDF_CIBA_SIM_ENABLED` says: `POST /ciba-sim/decision` answers 404, every backchannel request through the
   authenticator fails, and server.log has one ERROR, "CIBA simulator refused by the production profile". How to
   tell: that ERROR, at the first request. What to change: remove the jar, or run the rig under development. The
   switch is read strictly now as well: `true` or `false`. Development-profile escape: under development the
   simulator runs as before when the switch is `true` and its directory is safe, and a legacy spelling of the switch
   is read as `false` with a warning.

## Notes

**Verified first** (2026-09-30, javap of the pinned `pingfederate-sdk` and `pf-protocolengine` 13.1.3.0). The SDK's
`org.sourceid.saml20.adapter.gui.JdbcDatastoreFieldDescriptor(String, String)` is a `SelectFieldDescriptor` whose
options come from `SelectFieldDescriptionServiceImpl.getJdbcDataSourceOptionValues()`, each
`new OptionValue(getDescription(), getJndiName())` of a `JdbcDataSource`, whose `getJndiName()` returns `getId()`.
`com.pingidentity.access.DataSourceAccessor` has `public java.sql.Connection getConnection(String jdbcJndiName)
throws SQLException, NamingException`: a JNDI lookup of that name as a `javax.sql.DataSource`, then
`getConnection()`. So the field's value is the data store's id, and the accessor turns it into one of PingFederate's
pooled connections - the same accessor pf-integration's `PfDataSources` and SSF's `PfJdbcStoreFactory` already use.
The descriptor's constructor asks PingFederate's service registry for its data stores and throws outside
PingFederate (a `NoClassDefFoundError` for hivemind's `RegistryBuilder` in a unit test), so the tests build the
driver with a stand-in field. On U-0028's questions as they bear on this: the PingFederate 13.1.3 image this
repository builds has H2 and HSQLDB in `server/default/lib` and no jar holding `org/postgresql/Driver.class` anywhere
under `/opt` (checked 2026-09-30 on `pfai-p3-pr5/pingfederate:local`), which F-0330 already records; the data store
way needs no driver in the plugin. How PingFederate surfaces the driver's `CustomDataSourceDriverException`, and the
selector and accessor from the plugin's own loader on a running PingFederate, are U-0028 and U-0365, not run here.
For ciba-sim: its classes learn the profile on every call from the relocated copy of platform's `DeploymentProfile`,
which reads the environment and needs no lifecycle listener, so nothing has to run before PingFederate calls them.

**Found on the way.** libs/platform's README still describes the harness's switch and the example's `--insecure` as
they were (F-0355; this package may not edit platform). device-enrolment's challenge and `jti` replay stores are in
memory with no risk asked in production (F-0356, for X-A11). The instance-registry data source's README said
PingFederate ships a PostgreSQL driver; it does not, and the README now says so.

**Where this departs from the specification.** gm-api's https rule is a `ServletException` naming `pdpUrl`, so the
part is `FAILED_CONFIG` as the specification says rather than `REFUSED`; `pdpUrl` stays classed `any` in the
catalogue, so `oidf-preflight.jar` does not report an `http` PDP. The datasource's refusals are held by the driver
and answered on every lookup rather than thrown from `configure`, since how PingFederate treats an exception from
`configure` is unverified (U-0028); the data store that is not PostgreSQL is refused through `ProfileRefusals`, the
JDBC URL through the catalogue's own read-time rule. device-enrolment's audit covers its own catalogue only, as the
specification says, so the JVM host name property, which platform's catalogue governs, is not checked there. A third
event, `gm.grant.revoked`, joins the two the specification names. The datasource plugin now shades libs/platform, as
ciba-sim does, with a `ShadedJarCheck`; device-instance is still deployed beside it (X-A20).

**Findings.** Closed: F-0024, F-0162, F-0163. Opened: F-0355, F-0356, U-0365. F-0238 remains X-C02's and is unchanged
(gm-api's variables are still read only without the init-params). F-0025 is the umbrella for strict parsing, named
here and edited only by the release package.

**Tests.** `MainStartupTest` (device-enrolment) runs each forbidden switch through `run` and checks exit status 1 and
the stderr text, reads a governed switch that does not parse, the development warnings and legacy spellings, every
strict read naming its setting, a refused database URL or DSN that never shows its password, and launches `Main` in a
child JVM to see the real exit status and stderr. `GmApiSettingsTest` covers the init-param-then-environment order,
strict values, the https rule in each profile, `GM_API FAILED_CONFIG` from an `http` URL, and each gm event - evaluated,
refused and revoked - emitted and counted. `SimulatorGateTest` refuses under production for every value of the switch
with one ERROR logged, and reads legacy spellings under development; the servlet's and the authenticator's tests refuse
at each entry point. `InstanceRegistryDataSourceConfigTest` covers the field order, the data store way, the JDBC URL
refused under production and used under development, no database, the strict window, and a data store that is not
PostgreSQL refused under production and warned of under development; `ShadedJarCheck` holds both plugins' jars to their
relocated platform and catalogue. `AttestationFlowHarnessInsecureTlsTest` sees the JVM property only with the switch.
New methods are under each module's coverage gate (`Main.prepare`, `Main.audit`, `Main.toJdbcUrl`, `Main.scheme`,
`GrantOperations.revoke`, `ServletConfigs.from`, the datasource's `configure` and its data store's `getConnection`, the
gate's `settings`). Run on JDK 20 and 17, and the five modules' suites on the image's java 21.
