# instance-registry-datasource

> **Part of the [pf-agentic-identity](https://github.com/dphhyland/pf-agentic-identity) monorepo** — build from the repo root with `mvn package`. Written here, no upstream; see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).

A PingFederate **`CustomDataSourceDriver`** over the agent instance registry in
[`libs/device-instance`](../../libs/device-instance). It lets an access token mapping resolve a
pseudonymous instance identifier — the `agent_id` the enrolment service mints — to its owner, status,
device compliance and user-verification recency **at the moment of issuance**.

Why it exists rather than trusting the attestation alone: a device Client Attestation is valid for
fifteen minutes, and inside that window the instance can be revoked, the device can fall out of
compliance, or the user-verification window can lapse. A token minted from a still-valid attestation
would carry none of that. Reading the registry on every issuance is what makes revocation immediate.

## How it loads

A PF SDK plugin: discovered via `PF-INF/custom-drivers` (one line, `…registry.InstanceRegistryDataSource`),
built as `pf.plugins.instance-registry-datasource.jar` — without the `pf.plugins.` prefix PF ignores the jar
silently — and loaded on PF's per-plugin isolated classloader. The package
`com.pingidentity.ps.oidf.registry` is named in the descriptor, so it did not move in the split-package
unwind. libs/platform is shaded into the jar under `com.pingidentity.ps.oidf.registry.shaded.platform`, for the strict
reads of the `instance-registry` settings catalogue, the deployment profile and `ProfileRefusals` (0.6.0);
`ShadedJarCheck` holds the jar to it. `libs/device-instance` is not shaded in yet (X-A20), so it is deployed beside
the jar.

The PostgreSQL driver is `provided` and is **not** in PingFederate 13.1.3's image: no jar under `/opt` in the image
this repository builds holds `org/postgresql/Driver.class` (checked 2026-09-30 on `pfai-p3-pr5/pingfederate:local`,
built from `build/pingfederate/Dockerfile` on 13.1.3, which has H2 and HSQLDB in `server/default/lib` and no
PostgreSQL driver). A PingFederate JDBC data store on PostgreSQL needs the driver in `server/default/lib` anyway,
and the data store way (below) needs nothing more in this plugin; the development JDBC URL way needs the driver
where this plugin's loader can see it.

## Classes

- **`InstanceRegistryDataSource`** — the SDK shell: GUI descriptor, the filter field, `testConnection`
  (looks up an identifier that cannot exist, so it exercises connection + schema without depending on a
  row), and `retrieveValues`. A registry failure — or `retrieveValues` called before `configure` ran —
  throws `CustomDataSourceDriverException` rather than returning partial values, so a criterion never
  passes on a missing field while the registry is down. Unit tested (6 tests, a `setLookup` test seam and
  a fake `InstanceRegistry`) against `org.apache.commons:commons-lang3`, at the version PingFederate
  ships — `pingfederate-sdk`'s descriptor classes need it at construction time, and it is `provided`-scope
  on the SDK's own POM, so this module declares it too rather than relying on transitive resolution that
  Maven does not perform for `provided`.
- **`InstanceLookup`** — the lookup itself, no PF dependency, unit tested (12 tests, in-memory registry).
  Joins instance → device → owner through `InstanceRegistry` and computes the derived booleans.

## PF admin console

Data Stores → Custom → **Agent Instance Registry**. Three fields, read strictly through the `instance-registry`
settings catalogue ([docs/configuration/instance-registry.md](../../docs/configuration/instance-registry.md)):

| Field | Meaning |
|---|---|
| `PingFederate data store` | **the production way** (0.6.0, plan item PR-3): a PingFederate JDBC data store on the Identity Object Model directory holding the registry — the **same** database `services/device-enrolment`'s `IDM_DATABASE_URL` and `proofing-directory` point at — chosen from PingFederate's own list (the SDK's `JdbcDatastoreFieldDescriptor`). Its value is the data store's JNDI name, which PingFederate 13.1.3 sets to the data store's id (`JdbcDataSource.getJndiName()` returns `getId()`), and each connection comes from `DataSourceAccessor.getConnection(jndiName)`: PingFederate's pool and credentials, no URL or password in this driver's configuration. Under the production profile a data store whose database is not PostgreSQL is refused at the first lookup (`INSTANCE_REGISTRY`, one ERROR); under development it is a warning. It wins over the JDBC URL |
| `JDBC URL` | **development only**: a `jdbc:postgresql:` URL of the same directory, credentials included. Under the production profile (`OIDF_DEPLOYMENT_PROFILE` unset or anything but `development`) the driver refuses it at `configure` - a plugin's fields are not seen by the start-up sweep - and answers every lookup with the refusal, which names `PingFederate data store` to use instead. A different database resolves every lookup to "unknown instance" |
| `User verification max age (seconds)` | the window for `uv_fresh`; default 300. **Must match the enrolment service's `UV_MAX_AGE_SECONDS`**, or the two disagree about when an agent stops. Not a whole number: the driver configures nothing and every lookup fails, naming the field (before 0.6.0 it fell back to 300) |

With neither a data store nor (under development) a URL, every lookup fails naming the data store field. A refused
or unconfigured driver never returns values: `retrieveValues` throws `CustomDataSourceDriverException` and
`testConnection` is false, so an issuance criterion on `instance_active` refuses the token.

Filter field: `instance_id` — the instance identifier. That is the attestation's `agent_id` (pf-integration's
`ClientAttestationUtils.attestationClaim(…, "agent_id")` reads it for a mapping), which is right in every mode:
the minter always sets it to the instance id, whereas `sub` becomes the registered client id once the Phase 2.5
flip (`OIDF_ATTESTATION_SUB=client_id`) is on — so map `instance_id=${agent_id}`, not `${sub}`. See
[docs/claim-dictionary.md](../../docs/claim-dictionary.md).

Fields a mapping may request (`InstanceLookup.AVAILABLE_FIELDS`):

| Field | Value |
|---|---|
| `owner_subject` | the human — map to the token's `sub` (RFC 8693: human in `sub`, instance in `act.sub`) |
| `instance_status` / `instance_active` | `ACTIVE` / `SUSPENDED` / `REVOKED`; boolean true only when ACTIVE |
| `device_compliance` / `device_compliant` | `COMPLIANT` / `NOT_COMPLIANT` / `UNKNOWN`; boolean true only when COMPLIANT — unassessed is false |
| `uv_seconds_ago` / `uv_fresh` | seconds since the owner last verified (−1 if never); true only inside the configured window |
| `platform_entity_id`, `agent_build`, `cnf_jkt` | the agent platform's federation entity id, the build, and the RFC 7638 thumbprint of the bound key (cross-check against the attestation `cnf`) |

Gate issuance on `instance_active`, `device_compliant` and `uv_fresh`. An unknown identifier returns the
same fail-closed row as a deleted one (every boolean false, every identifier null) — the two are
deliberately indistinguishable to a mapping. **Device identifier, model and OS version are not exposed at
all**: device data is more sensitive than instance data, and a field that does not exist cannot be mapped
into a token by mistake.

## Build

```bash
mvn -pl plugins/instance-registry-datasource -am package     # → target/pf.plugins.instance-registry-datasource.jar
```

Versions come from the repo BOM (`bom/pom.xml`). The two `provided` PF jars (`pf-protocolengine`,
`pingfederate-sdk` 13.1.3.0) must be in `~/.m2` — see the `install:install-file` lines in
`.github/actions/pf-provided-jars/action.yml`. Built and supported for PingFederate 13.1 only. Not baked
into `build/pingfederate/` (that image is the OIDF-only AS); drop the jar into `server/default/deploy/`
yourself.
