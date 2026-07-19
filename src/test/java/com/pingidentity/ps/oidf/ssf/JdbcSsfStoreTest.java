/*
 * JDBC store wiring: DDL execution, ResultSet->Stream mapping, and INSERT parameter binding (Mockito;
 * no embedded DB is available offline, so a real round-trip is a deploy/harness-time concern).
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JdbcSsfStoreTest {

    private DataSource ds;
    private Connection conn;
    private PreparedStatement ps;
    private Statement stmt;
    private JdbcSsfStore store;

    @BeforeEach
    void setUp() throws Exception {
        ds = mock(DataSource.class);
        conn = mock(Connection.class);
        ps = mock(PreparedStatement.class);
        stmt = mock(Statement.class);
        when(ds.getConnection()).thenReturn(conn);
        when(conn.prepareStatement(anyString())).thenReturn(ps);
        when(conn.createStatement()).thenReturn(stmt);
        store = new JdbcSsfStore(ds);
    }

    @Test
    void ensureSchemaAppliesTheThreeTables() throws Exception {
        store.ensureSchema();
        verify(stmt).execute(JdbcSsfStore.DDL_STREAMS);
        verify(stmt).execute(JdbcSsfStore.DDL_SUBJECTS);
        verify(stmt).execute(JdbcSsfStore.DDL_PENDING);
    }

    @Test
    void getStreamMapsARow() throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(rs);
        when(rs.next()).thenReturn(true);
        when(rs.getString("stream_id")).thenReturn("s1");
        when(rs.getString("audience")).thenReturn("https://receiver.example.com");
        when(rs.getString("delivery_method")).thenReturn("POLL");
        when(rs.getString("status")).thenReturn("enabled");
        when(rs.getString("events_requested")).thenReturn(
                SsfEventTypes.CAEP_SESSION_REVOKED + "\n" + SsfEventTypes.RISC_ACCOUNT_DISABLED);
        when(rs.getString("events_delivered")).thenReturn(SsfEventTypes.CAEP_SESSION_REVOKED);
        when(rs.getLong("created_at")).thenReturn(10L);
        when(rs.getLong("updated_at")).thenReturn(20L);

        Optional<Stream> s = store.getStream("s1");
        assertTrue(s.isPresent());
        assertEquals("s1", s.get().id());
        assertEquals(DeliveryMethod.POLL, s.get().deliveryMethod());
        assertEquals(StreamStatus.ENABLED, s.get().status());
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED, SsfEventTypes.RISC_ACCOUNT_DISABLED),
                s.get().eventsRequested());
        verify(ps).setString(1, "s1");
    }

    @Test
    void getStreamAbsentIsEmpty() throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(rs);
        when(rs.next()).thenReturn(false);
        assertTrue(store.getStream("nope").isEmpty());
    }

    @Test
    void createStreamBindsAndExecutes() throws Exception {
        Stream s = Stream.builder().id("s1").audience("https://r").deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED)
                .createdAt(10).updatedAt(20).build();
        store.createStream(s);
        verify(ps).setString(1, "s1");
        verify(ps).setString(2, "https://r");
        verify(ps).setString(3, "POLL");
        verify(ps).setString(8, "enabled");
        verify(ps).setLong(10, 10L);
        verify(ps).executeUpdate();
    }

    @Test
    void ackCountsDeletedRows() throws Exception {
        when(ps.executeUpdate()).thenReturn(1);
        assertEquals(1, store.ack("s1", List.of("j1")));
        verify(ps).setString(2, "j1");
    }
}
