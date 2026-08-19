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
unwind. The PostgreSQL driver is `provided`: PF ships one on its own classpath, and bundling a second
copy risks a `LinkageError`.

## Classes

- **`InstanceRegistryDataSource`** — the SDK shell only: GUI descriptor, the filter field, `testConnection`
  (looks up an identifier that cannot exist, so it exercises connection + schema without depending on a
  row), and `retrieveValues`. A registry failure throws `CustomDataSourceDriverException` rather than
  returning partial values — a criterion must not pass on a missing field while the registry is down.
- **`InstanceLookup`** — the lookup itself, no PF dependency, unit tested (12 tests, in-memory registry).
  Joins instance → device → owner through `InstanceRegistry` and computes the derived booleans.

## PF admin console

Data Stores → Custom → **Agent Instance Registry**. Two fields:

| Field | Meaning |
|---|---|
| `JDBC URL` | the Identity Object Model directory holding the registry — the **same** database `services/device-enrolment`'s `IDM_DATABASE_URL` and `proofing-directory` point at, e.g. `jdbc:postgresql://host:5432/railway`. A different database resolves every lookup to "unknown instance". |
| `User verification max age (seconds)` | the window for `uv_fresh`; default 300. **Must match the enrolment service's `UV_MAX_AGE_SECONDS`**, or the two disagree about when an agent stops |

Filter field: `instance_id` — the instance identifier. That is the attestation's `agent_id` (pf-integration's
`ClientAttestationUtils.attestationClaim(…, "agent_id")` reads it for a mapping); until the staged Phase 2.5
`sub` flip it is also the attestation `sub`, which is what the class javadoc's `instance_id=${sub}` example
assumes — see [docs/claim-dictionary.md](../../docs/claim-dictionary.md).

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
`pingfederate-sdk` 13.0.0.3) must be in `~/.m2` — see the `install:install-file` lines in
`.github/workflows/build.yml`. Not baked into `deploy/pingfederate/` (that image is the OIDF-only AS);
drop the jar into `server/default/deploy/` yourself.
