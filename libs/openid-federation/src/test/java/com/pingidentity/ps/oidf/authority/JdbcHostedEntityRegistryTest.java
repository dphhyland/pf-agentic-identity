package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * The JDBC registry, held to the same contract as the in-memory one, on PostgreSQL - a database of this class's
 * own (libs/testkit) - running the federation family's <em>real</em> migrations ({@code V100__hosted_entity.sql}
 * to {@code V103}) rather than a hand-written test schema: the point is that the shipped DDL runs and the queries
 * work against it. Each test starts from an empty schema with the family applied.
 */
class JdbcHostedEntityRegistryTest extends HostedEntityRegistryContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    private DataSource dataSource;

    @Override
    protected HostedEntityRegistry newRegistry() throws Exception {
        this.dataSource = POSTGRES.dataSource();
        POSTGRES.resetPublicSchema();
        assertEquals(List.of("V100__hosted_entity.sql", "V101__hosted_entity_actor.sql", "V102__trust_mark.sql",
                "V103__federation_key_history.sql"), Migrations.apply(this.dataSource, 100, 199));
        return new JdbcHostedEntityRegistry(this.dataSource);
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

    /** A change whose audit line cannot be written is not made: the dispute record never disagrees with the registry. */
    @Test
    void aChangeAndItsAuditLineAreOneTransaction() throws Exception {
        HostedEntityRegistry registry = newRegistry();
        String id = "https://as.example.com/agents/a1";
        registry.register(HostedEntity.hosted(id, "k1", Map.of("oauth_client", Map.of("client_name", "before")), null));
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("DROP TABLE hosted_entity_audit_log");
        }

        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class,
                () -> registry.updateMetadata(id, Map.of("oauth_client", Map.of("client_name", "after")), "admin:1"));

        assertEquals(AuthorityRegistryException.STORAGE_FAILURE, e.reason());
        assertEquals(Map.of("client_name", "before"), registry.find(id).orElseThrow().metadata().get("oauth_client"), "rolled back");
    }
}
