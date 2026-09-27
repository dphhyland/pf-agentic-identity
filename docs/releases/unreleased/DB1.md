# Postgres-only tests, a database per test class

## Changelog

- The store suites run on PostgreSQL only, each test class in a database of its own: `libs/testkit` (test
  scope, never shipped) creates it on the server `OIDF_TEST_JDBC_URL` names, or in one Testcontainers 1.21.4
  container per JVM, and drops it afterwards; with neither the class is skipped, and under `CI=true` it fails.
  The hosted-entity, Trust Mark, key-history and agent registries run their shipped migrations there instead
  of on H2, and both durable SSF stores are held to the whole `SsfStore` contract on Postgres (DB-1).
- H2 and HSQLDB support is gone: a `jdbc:h2:` or `jdbc:hsqldb:` authority store URL (`OIDF_AUTHORITY_JDBC_URL`)
  or SSF store URL (`OIDF_SSF_JDBC_URL`) is refused at start-up with a message naming PostgreSQL, and H2 leaves
  every module's test classpath.
- `IDM_TEST_JDBC_URL`, `_USER` and `_PASSWORD` are renamed `OIDF_TEST_JDBC_*`; the old names are read in 0.5.x
  with a warning. Testcontainers moves from 1.19.8 to 1.21.4, which finds Docker Desktop 29 (U-0050, closed).

## Before you deploy

1. **Move an H2 or HSQLDB store URL to PostgreSQL.** A deployment whose authority store URL
   (`OIDF_AUTHORITY_JDBC_URL`, the `oidf.authority.jdbc.url` system property or the `jdbcUrl` init parameter)
   or SSF store URL (`OIDF_SSF_JDBC_URL`) begins `jdbc:h2:` or `jdbc:hsqldb:`, in any case, no longer starts
   that store. The SSF transmitter logs an ERROR and retries every 30 s, and stays down. `HostedEntityServlet`
   fails its init; `FederationAdminServlet` logs that hosting could not be configured, and fails its init too
   when the URL comes from the environment or a system property. Where Trust Mark issuing or the key history is enabled as
   well, `OpenIdFederationServlet`'s init fails, and because it loads at start-up that fails the whole
   `pf-runtime.war` (seen on the rig 2026-09-27 for a throwing init, commit 053a264). Point the URL at
   PostgreSQL, or use a PingFederate JDBC data store id (`OIDF_AUTHORITY_DATA_STORE_ID`,
   `OIDF_SSF_DATA_STORE_ID`), which this change does not look into. No README or configuration document ever
   offered either database: `git log -S` over the tracked Markdown, YAML, JSON, properties, env, shell,
   Terraform and Dockerfiles finds no `jdbc:h2` or `jdbc:hsqldb` URL (2026-09-28). The code accepted
   `jdbc:hsqldb:` for the SSF store from commit b00fe2e (2026-07-19) and both prefixes for the authority store
   from commit 01fbc20, and the PingFederate 13.1.3 image ships both drivers in `server/default/lib` (H2
   2.2.224 and HSQLDB 2.7.1, read from their manifests 2026-09-28), so either URL may have worked in a
   deployment that set one.
2. **Name the test database with OIDF_TEST_JDBC_URL.** Developers and any CI that builds this repository set
   `OIDF_TEST_JDBC_URL`, `OIDF_TEST_JDBC_USER` and `OIDF_TEST_JDBC_PASSWORD`, or leave Docker running for
   Testcontainers. The user must be allowed `CREATE DATABASE`, because each test class creates and drops a
   database of its own. `IDM_TEST_JDBC_*` still work in 0.5.x, with a warning, and go after it. A CI job with
   `CI=true` and no Postgres now fails the store suites rather than skipping them. See CONTRIBUTING.md,
   "Tests that need Postgres".

## Notes

`libs/testkit` is a test-support jar: `maven.deploy.skip`, not staged into the image, test scope everywhere. Its
`PostgresDatabase` extension disables a class it cannot give a database to, rather than aborting it in
`beforeAll`, because surefire 3.2.5 drops an aborted class from its counts (0 run, 0 skipped) where a disabled
class shows every test as skipped (seen 2026-09-28). `Migrations` applies a module's `db/migration` scripts in
version order within a family, one transaction a script, and records nothing: running migrations is DB-3's.

U-0050 is closed. On 2026-09-28, on the maintainer's Mac (Docker Desktop 29.4.1, API 1.54), Testcontainers
1.21.4 started `postgres:16-alpine` and `PostgresDatabaseTest` ran 6 of 6; Docker's event log showed the reaper
and the Postgres container created, started and destroyed. The same test with `-Dversion.testcontainers=1.19.8`
found no Docker and skipped all 6.

What moved onto Postgres, all against the shipped migrations: `JdbcHostedEntityRegistryTest`,
`JdbcTrustMarkRegistryTest`, `TrustMarkSupportTest` and `JdbcKeyHistoryStoreTest` (the federation family,
V100-V103), `JdbcAgentRegistryTest` (V200), `IomInstanceRegistryTest` and `SsfStoresOnPostgresTest` (from their
own Postgres lookup onto the extension). New: `SsfStoreContract`, held by `InMemorySsfStoreTest`,
`JdbcSsfStoreOnPostgresTest` and `LdmSsfStoreOnPostgresTest` - streams, owners, subjects, the queue, selection,
retries and eviction - and a real-Postgres test that `JdbcSsfStore.ensureSchema` adds the owner column to an
older `ssf_streams` and is idempotent. `KeyHistoryTest`'s one database test moved to `JdbcKeyHistoryStoreTest`.
The `ldm` store's fixture (the model repo's `0000` and `0001` migrations) was enough for its whole contract.
The contract found one divergence, recorded as F-0150: the `ldm` store reads a stream's `updatedAt` back as the
database's time of its last write, because the model's entry trigger sets `modified_at`; nothing reads it today.

The plan's DB-1 also names lease stores. There are none until C-4 (Phase 4), which is to test its JDBC lease
store through this extension.

Still true after this change: the stores' main-code comments and the federation migrations' header comments
still name H2 as the test target (`JdbcHostedEntityRegistry`, `JdbcAgentRegistry`, `JdbcSsfStore`, `V100`,
`V102`, `V103`). They were left alone: the stores' main code is not this package's, and a comment edit in a
shipped migration changes the checksum DB-3's Flyway will record. DB-2 (Phase 4) rewrites the migration layout.

The bom keeps `version.h2` and its `h2` entry for now: its last user is an unused test line in
`plugins/instance-registry-datasource/pom.xml`, which F3 deletes in this wave, and whichever of F3 and DB1 merges
second removes the two bom lines.
