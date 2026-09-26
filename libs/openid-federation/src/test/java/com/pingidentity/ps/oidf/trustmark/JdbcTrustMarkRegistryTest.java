package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
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
 * The JDBC registry against H2 in PostgreSQL mode, running the shipped {@code V102__trust_mark.sql} - so the DDL
 * that deploys is the DDL tested.
 */
class JdbcTrustMarkRegistryTest extends TrustMarkRegistryContract {
    private static final AtomicInteger DB_COUNTER = new AtomicInteger();
    private DataSource dataSource;

    @Override
    protected TrustMarkRegistry newRegistry() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:trustmark" + DB_COUNTER.incrementAndGet() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        this.dataSource = h2;
        String ddl;
        try (InputStream in = JdbcTrustMarkRegistryTest.class.getResourceAsStream("/db/migration/V102__trust_mark.sql")) {
            assertNotNull(in, "the migration must ship on the classpath");
            ddl = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        this.execute(ddl);
        return new JdbcTrustMarkRegistry(h2, this.clock);
    }

    private void execute(String sql) throws SQLException {
        try (Connection c = this.dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }

    /** A grant whose audit line cannot be written is not granted: the two go in one transaction. */
    @Test
    void aChangeAndItsAuditLineAreOneTransaction() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        this.execute("DROP TABLE trust_mark_audit_log");

        AuthorityRegistryException e = assertThrows(AuthorityRegistryException.class, () -> registry.grant(CERTIFIED, AGENT, null, null));

        assertEquals(AuthorityRegistryException.STORAGE_FAILURE, e.reason());
        assertTrue(registry.find(CERTIFIED, AGENT).isEmpty(), "the grant was rolled back");
    }

    @Test
    void aStoreThatCannotBeReachedIsAStorageFailure() {
        DataSource down = (DataSource) java.lang.reflect.Proxy.newProxyInstance(DataSource.class.getClassLoader(), new Class<?>[]{DataSource.class},
                (proxy, method, args) -> {
                    throw new SQLException("connection refused");
                });
        JdbcTrustMarkRegistry registry = new JdbcTrustMarkRegistry(down, this.clock);

        assertEquals(AuthorityRegistryException.STORAGE_FAILURE,
                assertThrows(AuthorityRegistryException.class, () -> registry.find(CERTIFIED, AGENT)).reason());
    }

    /** The schema itself insists a revoked grant says when, and knows no other status, whatever writes to it. */
    @Test
    void theSchemaRefusesARevokedGrantWithoutItsTime() throws Exception {
        this.newRegistry();

        assertThrows(SQLException.class, () -> this.execute("INSERT INTO trust_mark_grant (trust_mark_type, subject, status, granted_at)"
                + " VALUES ('t', 's', 'REVOKED', CURRENT_TIMESTAMP)"));
        assertThrows(SQLException.class, () -> this.execute("INSERT INTO trust_mark_grant (trust_mark_type, subject, status, granted_at)"
                + " VALUES ('t', 's', 'SUSPENDED', CURRENT_TIMESTAMP)"));
    }
}
