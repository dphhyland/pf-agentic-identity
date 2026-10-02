package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.util.List;
import javax.sql.DataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** The one grant registry every servlet shares, however they are initialised - the JDBC one on PostgreSQL. */
class TrustMarkSupportTest {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    private static final String TYPE = "https://pf.example.com/marks/certified";
    private static final String SUBJECT = "https://rp.example.com";

    @BeforeEach
    @AfterEach
    void reset() {
        TrustMarkSupport.resetForTests();
    }

    /** An empty schema with the federation family's migrations applied, on this class's own database. */
    private static DataSource database() throws Exception {
        POSTGRES.resetPublicSchema();
        Migrations.apply(POSTGRES.dataSource(), 100, 199);
        return POSTGRES.dataSource();
    }

    @Test
    void withNothingConfiguredTheFirstUseKeepsGrantsInMemoryAndSticksToIt() throws Exception {
        assertFalse(TrustMarkSupport.isConfigured());

        TrustMarkRegistry first = TrustMarkSupport.registry();
        TrustMarkSupport.configureJdbcRegistry(database());

        assertInstanceOf(InMemoryTrustMarkRegistry.class, first);
        assertTrue(TrustMarkSupport.isConfigured());
        assertSame(first, TrustMarkSupport.registry(), "a later configuration is ignored, not swapped in under the servlets");
    }

    @Test
    void theSharedViewReadsAndWritesWhicheverStoreIsConfigured() throws Exception {
        TrustMarkRegistry shared = TrustMarkSupport.shared();
        TrustMarkSupport.configureJdbcRegistry(database());

        shared.grant(TYPE, SUBJECT, null, "admin:1");

        assertInstanceOf(JdbcTrustMarkRegistry.class, TrustMarkSupport.registry());
        assertTrue(TrustMarkSupport.registry().find(TYPE, SUBJECT).isPresent());
        assertEquals(1, shared.grantsTo(SUBJECT).size());
        assertEquals(1, shared.grantsOf(TYPE).size());
        assertTrue(shared.find(TYPE, SUBJECT).isPresent());
        assertEquals(TrustMarkGrant.Status.REVOKED, shared.revoke(TYPE, SUBJECT, "withdrawn", "admin:2").status());
        assertEquals(List.of(TrustMarkAuditEntry.GRANTED, TrustMarkAuditEntry.REVOKED),
                shared.auditTrail(TYPE, SUBJECT).stream().map(TrustMarkAuditEntry::eventCode).toList());
    }
}
