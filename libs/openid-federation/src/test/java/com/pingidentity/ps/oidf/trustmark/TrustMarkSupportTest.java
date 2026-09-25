package com.pingidentity.ps.oidf.trustmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The one grant registry every servlet shares, however they are initialised. */
class TrustMarkSupportTest {
    private static final String TYPE = "https://pf.example.com/marks/certified";
    private static final String SUBJECT = "https://rp.example.com";

    @BeforeEach
    @AfterEach
    void reset() {
        TrustMarkSupport.resetForTests();
    }

    private static JdbcDataSource database() throws Exception {
        JdbcDataSource h2 = new JdbcDataSource();
        h2.setURL("jdbc:h2:mem:trustmark-support-" + System.nanoTime() + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DB_CLOSE_DELAY=-1");
        h2.setUser("sa");
        try (InputStream in = TrustMarkSupportTest.class.getResourceAsStream("/db/migration/V102__trust_mark.sql");
             Connection c = h2.getConnection(); Statement s = c.createStatement()) {
            s.execute(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        return h2;
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
