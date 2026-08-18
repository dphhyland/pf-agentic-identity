package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;

/**
 * The JDBC registry, held to the same contract as the in-memory one. Runs against H2 in PostgreSQL
 * compatibility mode, executing the <em>real</em> migration from
 * {@code db/migration/V100__hosted_entity.sql} rather than a hand-written test schema — the point is
 * verifying the shipped DDL parses and the queries work against it. (The instance registry made the
 * opposite call — it moved into the Identity Object Model, whose invariants are Postgres-only, so
 * {@code IomInstanceRegistryTest} needs a real Postgres rather than H2.)
 */
class JdbcHostedEntityRegistryTest extends HostedEntityRegistryContract {

    private static final AtomicInteger DB_COUNTER = new AtomicInteger();

    private DataSource dataSource;

    @Override
    protected HostedEntityRegistry newRegistry() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:authority" + DB_COUNTER.incrementAndGet()
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        this.dataSource = h2;
        applyMigration(h2);
        return new JdbcHostedEntityRegistry(h2);
    }

    private static void applyMigration(DataSource dataSource) throws Exception {
        String ddl;
        try (InputStream in = JdbcHostedEntityRegistryTest.class
                .getResourceAsStream("/db/migration/V100__hosted_entity.sql")) {
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
        for (String table : new String[]{"hosted_entity", "hosted_entity_audit_log"}) {
            try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
                assertTrue(s.execute("SELECT count(*) FROM " + table), "missing table: " + table);
            }
        }
    }

    /** The status CHECK constraint is a second line of defence behind the enum. */
    @Test
    void theDatabaseRefusesAnInvalidStatus() throws Exception {
        newRegistry();
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            SQLException e = assertThrows(SQLException.class, () -> s.execute(
                    "INSERT INTO hosted_entity (entity_id, hosting_mode, hosting_key_ref, metadata,"
                            + " metadata_policy, status, listable, registered_at) VALUES"
                            + " ('e1','AUTHORITY_SIGNED','k1','{}','{}','NONSENSE',FALSE,CURRENT_TIMESTAMP)"));
            assertTrue(e.getMessage().toLowerCase().contains("check")
                    || e.getMessage().toLowerCase().contains("constraint"), e.getMessage());
        }
    }

    /** Mirrors HostedEntity's own compact-constructor rule, enforced a second time at the database. */
    @Test
    void theDatabaseRefusesAnAuthoritySignedEntityWithNoKey() throws Exception {
        newRegistry();
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            SQLException e = assertThrows(SQLException.class, () -> s.execute(
                    "INSERT INTO hosted_entity (entity_id, hosting_mode, hosting_key_ref, metadata,"
                            + " metadata_policy, status, listable, registered_at) VALUES"
                            + " ('e1','AUTHORITY_SIGNED',NULL,'{}','{}','ACTIVE',FALSE,CURRENT_TIMESTAMP)"));
            assertTrue(e.getMessage().toLowerCase().contains("check")
                    || e.getMessage().toLowerCase().contains("constraint"), e.getMessage());
        }
    }

    @Test
    void theDatabaseRefusesASelfSignedEntityWithAKey() throws Exception {
        newRegistry();
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            SQLException e = assertThrows(SQLException.class, () -> s.execute(
                    "INSERT INTO hosted_entity (entity_id, hosting_mode, hosting_key_ref, metadata,"
                            + " metadata_policy, status, listable, registered_at) VALUES"
                            + " ('e1','SELF_SIGNED','should-be-null','{}','{}','ACTIVE',FALSE,CURRENT_TIMESTAMP)"));
            assertTrue(e.getMessage().toLowerCase().contains("check")
                    || e.getMessage().toLowerCase().contains("constraint"), e.getMessage());
        }
    }

    /** A corrupted stored JSON value is a storage fault, not a silently-returned empty map. */
    @Test
    void corruptedStoredMetadataFailsLoudlyRatherThanSilentlyLosingData() throws Exception {
        HostedEntityRegistry registry = newRegistry();
        registry.register(new HostedEntity("https://as.example.com/agents/a1", HostingMode.AUTHORITY_SIGNED,
                "k1", Map.of("oauth_client", Map.of()), Map.of(), EntityStatus.ACTIVE, false, null,
                Instant.now(), null));
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("UPDATE hosted_entity SET metadata = 'not json' WHERE entity_id = 'https://as.example.com/agents/a1'");
        }
        assertThrows(IllegalStateException.class,
                () -> registry.find("https://as.example.com/agents/a1"));
    }
}
