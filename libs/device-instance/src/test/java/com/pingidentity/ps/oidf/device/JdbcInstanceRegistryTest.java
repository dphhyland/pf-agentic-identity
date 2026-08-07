package com.pingidentity.ps.oidf.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;

/**
 * The JDBC registry, held to the same contract as the in-memory one — the properties everything
 * downstream relies on must not differ between them.
 *
 * <p>Runs against H2 in PostgreSQL compatibility mode, executing the <em>real</em> migration from
 * {@code db/migration/V1__instance_registry.sql} rather than a hand-written test schema. That is the
 * point: it verifies the shipped DDL parses and that the queries work against it, so a column rename
 * cannot pass tests while breaking production.
 *
 * <p>What it does not prove is Postgres-specific behaviour — H2's PG mode is a compatibility layer, not
 * Postgres. Concurrency semantics in particular (the revocation write racing an issuance read) need a
 * real Postgres and belong in an integration test.
 */
class JdbcInstanceRegistryTest extends InstanceRegistryContract {

    private static final AtomicInteger DB_COUNTER = new AtomicInteger();

    private DataSource dataSource;

    @Override
    protected InstanceRegistry newRegistry() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        // A fresh in-memory database per test, kept alive for the connection's lifetime.
        h2.setURL("jdbc:h2:mem:registry" + DB_COUNTER.incrementAndGet()
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        this.dataSource = h2;
        applyMigration(h2);
        return new JdbcInstanceRegistry(h2);
    }

    /** Executes the shipped migration verbatim. */
    private static void applyMigration(DataSource dataSource) throws Exception {
        String ddl;
        try (InputStream in = JdbcInstanceRegistryTest.class
                .getResourceAsStream("/db/migration/V1__instance_registry.sql")) {
            assertNotNull(in, "the migration must ship on the classpath");
            ddl = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute(ddl);
        }
    }

    @Test
    void theShippedMigrationCreatesEveryTable() throws Exception {
        newRegistry();
        for (String table : new String[]{
                "owner_user", "device", "agent_instance", "bound_authenticator", "audit_log"}) {
            try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
                assertTrue(s.execute("SELECT count(*) FROM " + table), "missing table: " + table);
            }
        }
    }

    /**
     * The status CHECK constraint is a second line of defence behind the enum: a bad write from some
     * future code path must be refused by the database, not merely by Java.
     */
    @Test
    void theDatabaseRefusesAnInvalidStatus() throws Exception {
        newRegistry();
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("INSERT INTO owner_user (id, pingone_subject, created_at)"
                    + " VALUES ('o1', 'subj', CURRENT_TIMESTAMP)");
            s.execute("INSERT INTO device (id, platform, appattest_key_id, appattest_environment,"
                    + " owner_user_id) VALUES ('d1', 'ios', 'k', 'appattest', 'o1')");
            SQLException e = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class, () ->
                    s.execute("INSERT INTO agent_instance (id, platform_entity_id, cnf_jkt, status,"
                            + " device_id, enrolled_at) VALUES ('i1','p','t','NONSENSE','d1',CURRENT_TIMESTAMP)"));
            assertTrue(e.getMessage().toLowerCase().contains("check")
                    || e.getMessage().toLowerCase().contains("constraint"), e.getMessage());
        }
    }

    /** Likewise for the App Attest environment: only Apple's two values may ever be stored. */
    @Test
    void theDatabaseRefusesAnUnknownAppAttestEnvironment() throws Exception {
        newRegistry();
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("INSERT INTO owner_user (id, pingone_subject, created_at)"
                    + " VALUES ('o1', 'subj', CURRENT_TIMESTAMP)");
            SQLException e = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class, () ->
                    s.execute("INSERT INTO device (id, platform, appattest_key_id, appattest_environment,"
                            + " owner_user_id) VALUES ('d1','ios','k','appattest-pretend','o1')"));
            assertTrue(e.getMessage().toLowerCase().contains("check")
                    || e.getMessage().toLowerCase().contains("constraint"), e.getMessage());
        }
    }

    @Test
    void anInstanceCannotReferenceAMissingDevice() throws Exception {
        newRegistry();
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            SQLException e = org.junit.jupiter.api.Assertions.assertThrows(SQLException.class, () ->
                    s.execute("INSERT INTO agent_instance (id, platform_entity_id, cnf_jkt, status,"
                            + " device_id, enrolled_at) VALUES ('i1','p','t','ACTIVE','ghost',CURRENT_TIMESTAMP)"));
            assertEquals(true, e.getMessage().toLowerCase().contains("referential")
                    || e.getMessage().toLowerCase().contains("foreign"), e.getMessage());
        }
    }
}
