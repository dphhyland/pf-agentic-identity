package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * The JDBC registry on PostgreSQL - a database of this class's own (libs/testkit) - running the federation family's
 * shipped migrations, {@code V102__trust_mark.sql} among them, so the DDL that deploys is the DDL tested. Each test
 * starts from an empty schema with the family applied.
 */
class JdbcTrustMarkRegistryTest extends TrustMarkRegistryContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    private DataSource dataSource;

    @Override
    protected TrustMarkRegistry newRegistry() throws Exception {
        this.dataSource = POSTGRES.dataSource();
        POSTGRES.resetPublicSchema();
        Migrations.apply(this.dataSource, 100, 199);
        return new JdbcTrustMarkRegistry(this.dataSource, this.clock);
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
