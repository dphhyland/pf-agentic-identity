package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.federation.testkit.Racing;
import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.time.Duration;
import java.util.List;
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

    // ---- H-FED-3: two changes to one grant whose transactions overlap -----------------------------------------------

    private JdbcTrustMarkRegistry racing(String sqlPrefix) {
        return new JdbcTrustMarkRegistry(Racing.meetingAt(this.dataSource, sqlPrefix), this.clock);
    }

    /** One change applied and one refused as stale; the audit trail grew by exactly one line, the winner's. */
    private void exactlyOneApplied(List<Object> outcomes, int auditLinesBefore) throws Exception {
        assertEquals(1, outcomes.stream().filter(o -> o instanceof TrustMarkGrant).count(), String.valueOf(outcomes));
        assertEquals(1, outcomes.stream().filter(o -> o instanceof AuthorityRegistryException e
                && AuthorityRegistryException.STALE_UPDATE.equals(e.reason())).count(), String.valueOf(outcomes));
        TrustMarkGrant winner = (TrustMarkGrant) outcomes.stream().filter(o -> o instanceof TrustMarkGrant).findFirst().orElseThrow();
        JdbcTrustMarkRegistry registry = new JdbcTrustMarkRegistry(this.dataSource, this.clock);
        assertEquals(winner, registry.find(CERTIFIED, AGENT).orElseThrow());
        List<TrustMarkAuditEntry> trail = registry.auditTrail(CERTIFIED, AGENT);
        assertEquals(auditLinesBefore + 1, trail.size(), "the refused change wrote no audit line");
        assertEquals(winner.actor(), trail.get(trail.size() - 1).actor());
    }

    @Test
    void twoRevocationsThatOverlapOneIsRefusedAsStale() throws Exception {
        this.newRegistry().grant(CERTIFIED, AGENT, null, "admin:0");
        JdbcTrustMarkRegistry racing = this.racing("UPDATE trust_mark_grant");

        this.exactlyOneApplied(Racing.together(() -> racing.revoke(CERTIFIED, AGENT, "first", "admin:a"),
                () -> racing.revoke(CERTIFIED, AGENT, "second", "admin:b")), 1);
    }

    @Test
    void aRevocationAndAGrantAgainThatOverlapApplyExactlyOne() throws Exception {
        this.newRegistry().grant(CERTIFIED, AGENT, null, "admin:0");
        this.clock.advance(Duration.ofMinutes(1));
        JdbcTrustMarkRegistry racing = this.racing("UPDATE trust_mark_grant");

        this.exactlyOneApplied(Racing.together(() -> racing.revoke(CERTIFIED, AGENT, "first", "admin:a"),
                () -> racing.grant(CERTIFIED, AGENT, null, "admin:b")), 1);
    }

    @Test
    void twoReinstatementsThatOverlapOneIsRefusedAsStale() throws Exception {
        TrustMarkRegistry setup = this.newRegistry();
        setup.grant(CERTIFIED, AGENT, null, "admin:0");
        setup.revoke(CERTIFIED, AGENT, "lapsed", "admin:0");
        this.clock.advance(Duration.ofMinutes(1));
        JdbcTrustMarkRegistry racing = this.racing("UPDATE trust_mark_grant");

        this.exactlyOneApplied(Racing.together(() -> racing.grant(CERTIFIED, AGENT, null, "admin:a"),
                () -> racing.grant(CERTIFIED, AGENT, null, "admin:b")), 2);
    }

    @Test
    void twoFirstGrantsThatOverlapOneIsRefusedAsStale() throws Exception {
        this.newRegistry();
        JdbcTrustMarkRegistry racing = this.racing("INSERT INTO trust_mark_grant");

        this.exactlyOneApplied(Racing.together(() -> racing.grant(CERTIFIED, AGENT, null, "admin:a"),
                () -> racing.grant(CERTIFIED, AGENT, null, "admin:b")), 0);
    }

    /** A first grant the database refuses for any reason but a duplicate is a storage failure, not a stale change. */
    @Test
    void aFirstGrantRefusedForAnotherReasonIsAStorageFailure() throws Exception {
        TrustMarkRegistry registry = this.newRegistry();
        this.execute("ALTER TABLE trust_mark_grant ADD CONSTRAINT no_agent CHECK (subject <> '" + AGENT + "')");

        assertEquals(AuthorityRegistryException.STORAGE_FAILURE,
                assertThrows(AuthorityRegistryException.class, () -> registry.grant(CERTIFIED, AGENT, null, null)).reason());
        assertTrue(registry.auditTrail(CERTIFIED, AGENT).isEmpty());
    }

    /** H-FED-9: the standing grants are one statement, however many grants the type has. */
    @Test
    void theStandingGrantsAreOneStatement() throws Exception {
        TrustMarkRegistry setup = this.newRegistry();
        for (int i = 0; i < 20; i++) {
            setup.grant(CERTIFIED, "https://pf.example.com/federation/agents/n" + i, null, null);
        }
        Racing.Counting counting = Racing.counting(this.dataSource);
        JdbcTrustMarkRegistry registry = new JdbcTrustMarkRegistry(counting.dataSource(), this.clock);

        assertEquals(20, registry.standing(CERTIFIED, null, this.clock.instant()).size());
        assertEquals(1, registry.standing(CERTIFIED, "https://pf.example.com/federation/agents/n7", this.clock.instant()).size());
        assertEquals(2, counting.statements(), counting.sql().toString());
    }

    /** H-FED-9: TrustMarkIssuer.marked answers a type and a subject - or a whole type - in one statement, however many grants. */
    @Test
    void theIssuerAnswersMarkedInOneStatement() throws Exception {
        TrustMarkRegistry setup = this.newRegistry();
        for (int i = 0; i < 20; i++) {
            setup.grant(CERTIFIED, "https://pf.example.com/federation/agents/n" + i, null, null);
        }
        Racing.Counting counting = Racing.counting(this.dataSource);
        TrustMarkIssuer issuer = new TrustMarkIssuer(java.util.Map.of(CERTIFIED, new TrustMarkType(CERTIFIED, 3600, TrustMarkType.Subjects.ANY,
                null, null, null)), new JdbcTrustMarkRegistry(counting.dataSource(), this.clock), id -> false, this.clock);

        assertEquals(List.of("https://pf.example.com/federation/agents/n7"), issuer.marked(CERTIFIED, "https://pf.example.com/federation/agents/n7/"));
        assertEquals(1, counting.statements(), counting.sql().toString());
        counting.reset();
        assertEquals(20, issuer.marked(CERTIFIED, null).size());
        assertEquals(1, counting.statements(), counting.sql().toString());
    }
}
