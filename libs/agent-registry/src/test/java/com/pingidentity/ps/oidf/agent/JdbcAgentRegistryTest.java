package com.pingidentity.ps.oidf.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * The JDBC registry, held to the same contract as the in-memory one, on PostgreSQL - a database of this class's
 * own (libs/testkit) - executing the <em>real</em> migration {@code db/migration/V200__agent_identity.sql},
 * including the {@code ON CONFLICT ... DO NOTHING} upsert {@link JdbcAgentRegistry#resolveOrMint} depends on for
 * race-safety: the shipped DDL is the thing under test, not a hand-written stand-in. Each test starts from an
 * empty schema with the agent family (V200-V299) applied.
 */
class JdbcAgentRegistryTest extends AgentRegistryContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @Override
    protected AgentRegistry newRegistry() throws Exception {
        POSTGRES.resetPublicSchema();
        Migrations.apply(POSTGRES.dataSource(), 200, 299);
        return new JdbcAgentRegistry(POSTGRES.dataSource());
    }

    @Test
    void theShippedMigrationCreatesTheTable() throws Exception {
        POSTGRES.resetPublicSchema();
        assertEquals(List.of("V200__agent_identity.sql"), Migrations.apply(POSTGRES.dataSource(), 200, 299));
        try (Connection c = POSTGRES.dataSource().getConnection(); Statement s = c.createStatement()) {
            assertTrue(s.execute("SELECT count(*) FROM agent_identity"));
        }
    }

    /**
     * A genuine storage fault (here: the DataSource cannot hand out a connection at all) must surface
     * as {@link AgentRegistryException} with {@link AgentRegistryException#STORAGE_FAILURE}, not an
     * unchecked {@link SQLException} escaping past the interface's declared contract.
     */
    @Test
    void aStorageFaultSurfacesAsAStorageFailureAgentRegistryException() {
        JdbcAgentRegistry registry = new JdbcAgentRegistry(new UnreachableDataSource());

        AgentRegistryException e = assertThrows(AgentRegistryException.class, () -> registry.resolveOrMint(
                "https://as.example.com", "client-1", "spiffe_id", "spiffe://example.org/agent-1"));
        assertEquals(AgentRegistryException.STORAGE_FAILURE, e.code());
    }

    /** A minimal DataSource whose every connection attempt fails, standing in for a database outage. */
    private static final class UnreachableDataSource implements DataSource {
        @Override public Connection getConnection() throws SQLException {
            throw new SQLException("simulated connection failure");
        }
        @Override public Connection getConnection(String username, String password) throws SQLException {
            throw new SQLException("simulated connection failure");
        }
        @Override public java.io.PrintWriter getLogWriter() {
            return null;
        }
        @Override public void setLogWriter(java.io.PrintWriter out) {
        }
        @Override public void setLoginTimeout(int seconds) {
        }
        @Override public int getLoginTimeout() {
            return 0;
        }
        @Override public java.util.logging.Logger getParentLogger() {
            return null;
        }
        @Override public <T> T unwrap(Class<T> iface) {
            throw new UnsupportedOperationException();
        }
        @Override public boolean isWrapperFor(Class<?> iface) {
            return false;
        }
    }
}
