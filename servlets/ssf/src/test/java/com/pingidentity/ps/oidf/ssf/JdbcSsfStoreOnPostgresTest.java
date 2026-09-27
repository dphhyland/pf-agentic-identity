/*
 * The tables store's whole contract on PostgreSQL, with the DDL it applies itself.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * {@link JdbcSsfStore} held to {@link SsfStoreContract} on PostgreSQL - a database of this class's own
 * (libs/testkit) - with the three tables its own {@link JdbcSsfStore#ensureSchema()} creates. Each test starts from
 * an empty schema. {@code JdbcSsfStoreTest} pins the SQL as text with Mockito; this is where it runs.
 */
class JdbcSsfStoreOnPostgresTest extends SsfStoreContract {

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    @Override
    protected SsfStore newStore() throws SQLException {
        POSTGRES.resetPublicSchema();
        JdbcSsfStore store = new JdbcSsfStore(POSTGRES.dataSource());
        store.ensureSchema();
        return store;
    }

    /**
     * A deployment whose {@code ssf_streams} predates stream owners gets the column on boot, keeps its rows (with no
     * owner, for the operator to assign), and a second boot - or a second node - changes nothing.
     */
    @Test
    void ensureSchemaAddsTheOwnerColumnToAnOlderTableAndIsIdempotent() throws SQLException {
        POSTGRES.resetPublicSchema();
        execute("CREATE TABLE ssf_streams (stream_id VARCHAR(64) PRIMARY KEY, audience VARCHAR(1024) NOT NULL, "
                + "delivery_method VARCHAR(64) NOT NULL, push_endpoint_url VARCHAR(2048), push_auth_header VARCHAR(4096), "
                + "events_requested VARCHAR(8192), events_delivered VARCHAR(8192), status VARCHAR(16) NOT NULL, "
                + "status_reason VARCHAR(1024), created_at BIGINT, updated_at BIGINT)");
        String old = newId();
        execute("INSERT INTO ssf_streams (stream_id, audience, delivery_method, status, created_at, updated_at) "
                + "VALUES ('" + old + "', 'https://receiver.example.com', 'POLL', 'enabled', 1, 1)");
        JdbcSsfStore upgraded = new JdbcSsfStore(POSTGRES.dataSource());

        upgraded.ensureSchema();
        upgraded.ensureSchema();

        Stream kept = upgraded.getStream(old).orElseThrow();
        assertEquals(null, kept.ownerClientId(), "a row from before owners has none to give");
        assertEquals(StreamStatus.ENABLED, kept.status());
        String owned = newId();
        upgraded.createStream(pollStream(owned).toBuilder().ownerClientId("receiver-a").build());
        assertEquals("receiver-a", upgraded.getStream(owned).orElseThrow().ownerClientId());
        assertTrue(upgraded.peek(old, 10).isEmpty(), "and the other two tables were created beside it");
        assertEquals(List.of(), upgraded.listSubjects(old));
    }

    private static void execute(String sql) throws SQLException {
        try (Connection c = POSTGRES.dataSource().getConnection(); Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }
}
