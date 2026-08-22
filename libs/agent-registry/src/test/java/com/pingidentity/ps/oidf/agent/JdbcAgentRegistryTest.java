package com.pingidentity.ps.oidf.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
 * The JDBC registry, held to the same contract as the in-memory one. Runs against H2 in PostgreSQL
 * compatibility mode, executing the <em>real</em> migration from
 * {@code db/migration/V200__agent_identity.sql} — including its {@code ON CONFLICT ... DO NOTHING}
 * upsert, which is exactly the clause {@link JdbcAgentRegistry#resolveOrMint} depends on for
 * race-safety, so the shipped DDL must be the thing under test, not a hand-written stand-in.
 */
class JdbcAgentRegistryTest extends AgentRegistryContract {

    private static final AtomicInteger DB_COUNTER = new AtomicInteger();

    @Override
    protected AgentRegistry newRegistry() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:agentregistry" + DB_COUNTER.incrementAndGet()
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        applyMigration(h2);
        return new JdbcAgentRegistry(h2);
    }

    private static void applyMigration(DataSource dataSource) throws Exception {
        String ddl;
        try (InputStream in = JdbcAgentRegistryTest.class
                .getResourceAsStream("/db/migration/V200__agent_identity.sql")) {
            assertNotNull(in, "the migration must ship on the classpath");
            ddl = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute(ddl);
        }
    }

    @Test
    void theShippedMigrationCreatesTheTable() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:agentregistry" + DB_COUNTER.incrementAndGet()
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        applyMigration(h2);
        try (Connection c = h2.getConnection(); Statement s = c.createStatement()) {
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
