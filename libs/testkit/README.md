# libs/testkit

Test support for the reactor. Never shipped: `maven.deploy.skip` keeps it out of GitHub Packages,
`build/pingfederate/stage-modules.sh` does not stage it, and modules take it at `test` scope only. No PingFederate
types.

## A database per test class

`PostgresDatabase` is a JUnit 5 extension. Registered as a static field, it creates a PostgreSQL database for the
class before its `@BeforeAll` methods run, named `oidf_test_<class>_<48 random bits>`, and drops it (`WITH (FORCE)`,
so a connection a test left open does not keep it) after the class. Classes, modules and worktrees that share a
server share nothing else.

```java
@RegisterExtension
static final PostgresDatabase POSTGRES = new PostgresDatabase();

@BeforeAll
static void schema() throws Exception {
    Migrations.apply(POSTGRES.dataSource(), 100, 199);   // the federation family
}
```

`resetPublicSchema()` drops and recreates the `public` schema, for a class whose tests each start empty; the
contract suites call it and re-apply their migrations in `newRegistry()`.

Where the server comes from, decided once per JVM (`PostgresServer`):

1. `OIDF_TEST_JDBC_URL`, with `OIDF_TEST_JDBC_USER` and `OIDF_TEST_JDBC_PASSWORD`. It must be a
   `jdbc:postgresql:` URL, and its user must be allowed `CREATE DATABASE`. `IDM_TEST_JDBC_URL`, `_USER` and
   `_PASSWORD`, which device-instance's suite read before, are aliases in 0.5.x and log a warning.
2. Otherwise Testcontainers 1.21.4, when Docker answers: one `postgres:16-alpine` container for the JVM, removed
   by Testcontainers' reaper when the JVM exits.
3. Otherwise none. The class is disabled with a message naming
   [CONTRIBUTING.md's recipe](../../CONTRIBUTING.md#tests-that-need-postgres), so surefire reports each of its
   tests as skipped; a class aborted in `beforeAll` instead vanishes from surefire 3.2.5's counts (seen
   2026-09-28). Under `CI=true` the class fails instead.

On 2026-09-28, on the maintainer's Mac with Docker Desktop 29.4.1 (API 1.54), Testcontainers 1.21.4 started the
container (`PostgresDatabaseTest`, 6 of 6, and Docker's event log showed the reaper and `postgres:16-alpine`
created, started and destroyed); the same test with 1.19.8 found no Docker and skipped all 6 (U-0050).

## Migrations

`Migrations.apply(dataSource, first, last)` runs every `V<version>__<description>.sql` under `db/migration` on the
classpath whose major version is in `[first, last]` - a family, in plan decision 11's ranges - in version order,
comparing versions part by part as numbers, as Flyway does. Each script runs in its own transaction, and two
scripts with one version are refused. Nothing is recorded in the database: there is no history table, because
running migrations is DB-3's `tools/db-migrate` (Phase 4); this puts the shipped DDL under test.
`Migrations.applyResources` runs scripts that are not versioned migrations, such as the Identity Object Model's
vendored `/idm/*.sql`, in the order given.

## What uses it

The JDBC store suites: `JdbcHostedEntityRegistryTest`, `JdbcTrustMarkRegistryTest`, `TrustMarkSupportTest` and
`JdbcKeyHistoryStoreTest` (openid-federation), `JdbcAgentRegistryTest` (agent-registry), `IomInstanceRegistryTest`
(device-instance), and `JdbcSsfStoreOnPostgresTest`, `LdmSsfStoreOnPostgresTest` and `SsfStoresOnPostgresTest`
(ssf). The plan's DB-1 also names lease stores: there are none yet. Leases arrive with C-4 (Phase 4), whose JDBC
lease store is to be tested through this extension.

## Build

```sh
mvn -pl libs/testkit -am verify
```

The coverage gate (100% line and branch, per method) is on the decisions that need no database: where the server
comes from and whether a class without one is skipped or failed (`PostgresServer.resolve`, `setting`), the
database name (`PostgresDatabase.databaseNameFor`), and which scripts run in which order (`Migrations.version`,
`compare`, `order`, `inFamily`). The rest runs in `PostgresDatabaseTest` wherever a Postgres is reachable, and CI
always has one.
