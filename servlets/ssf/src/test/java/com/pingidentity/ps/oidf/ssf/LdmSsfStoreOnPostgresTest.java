/*
 * The Identity Object Model store's whole contract on PostgreSQL, on the model repo's own migrations.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * {@link LdmSsfStore} held to {@link SsfStoreContract} on PostgreSQL - a database of this class's own
 * (libs/testkit) - on the model repo's {@code 0000} and {@code 0001} migrations, vendored under
 * {@code src/test/resources/idm/}: the schema the store writes to and never creates. Each test starts from an empty
 * {@code idm.entry}. {@code LdmSsfStoreTest} pins the SQL as text with Mockito; this is where it runs.
 */
class LdmSsfStoreOnPostgresTest extends SsfStoreContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @BeforeAll
    static void modelSchema() throws Exception {
        Migrations.applyResources(POSTGRES.dataSource(), LdmSsfStoreOnPostgresTest.class,
                "/idm/0000-base-schema.sql", "/idm/0001-add-shared-signals-ssf.sql");
    }

    @Override
    protected SsfStore newStore() throws SQLException {
        try (Connection c = POSTGRES.dataSource().getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE idm.entry CASCADE");
        }
        return new LdmSsfStore(POSTGRES.dataSource());
    }

    /** The model declares no attribute for the optional members and no class for SCIM records yet (F-0387). */
    @Override
    protected boolean keepsWhatTheModelLacks() {
        return false;
    }

    /**
     * F-0150: the store writes {@code modified_at = to_timestamp(updatedAt)}, and the model's {@code entry_class_check}
     * trigger overwrites it with {@code now()} on every INSERT and UPDATE, so a stream reads back with the database's
     * time of its last write. Nothing reads a stream's {@code updatedAt} today; this pins what it is.
     */
    @Override
    protected void assertUpdatedAt(long written, Stream read) {
        long now = System.currentTimeMillis() / 1000;
        assertTrue(Math.abs(read.updatedAt() - now) <= 60, "the database's clock, not " + written + ": " + read.updatedAt());
    }

    /**
     * On the ldm store a stream answers this transmitter's settings for the two Transmitter-Supplied members, which
     * SSF 1.0 §8.1.1 makes "Transmitter-Supplied, OPTIONAL", and a {@code description} - which SSF lets a transmitter
     * truncate, not drop - is refused with a 400 rather than lost.
     */
    @Test
    @Requirement("SSF §8.1.1")
    void onTheLdmStoreAStreamReportsTheSettingsAndADescriptionIsRefused() throws Exception {
        SsfStore ldm = newStore();
        StreamManagementService svc = new StreamManagementService(ldm, new SetMinter("RS256", new TestSigningKeyProvider("k")),
                new SsfConfiguration.Builder().issuer("https://op.example.com").minVerificationIntervalSeconds(45)
                        .inactivityTimeoutSeconds(86_400).build());
        AuthContext receiver = AuthContext.active("receiver-client", Set.of("ssf.manage"));
        Map<String, Object> body = new HashMap<>();
        body.put("delivery", Map.of("method", DeliveryMethod.POLL.urn()));
        body.put("events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED));
        body.put("description", "Stream for receiver A");
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class, () -> svc.createStream(body, receiver));
        assertTrue(refused.getMessage().contains("description is not supported"), refused.getMessage());
        assertTrue(ldm.listStreams().isEmpty(), "nothing created");

        body.put("description", null);
        Map<String, Object> created = svc.createStream(body, receiver);
        String id = (String) created.get("stream_id");
        assertFalse(created.containsKey("description"));
        assertEquals(45, created.get("min_verification_interval"));
        assertEquals(86_400L, created.get("inactivity_timeout"));
        assertEquals(created, svc.getStream(id, receiver));
        assertThrows(IllegalArgumentException.class,
                () -> svc.updateStream(id, Map.of("stream_id", id, "description", "later"), receiver));
    }
}
