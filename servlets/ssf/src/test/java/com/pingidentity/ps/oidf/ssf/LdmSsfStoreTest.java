/*
 * LDM store wiring: entry INSERT binding (object_classes/attrs/containment), row->Stream mapping,
 * subject membership predicates, pending mapping. Mockito — a real Postgres round-trip is the model
 * repo's test_migration / deploy-time concern.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.Optional;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class LdmSsfStoreTest {

    private static final String SID = "3f2b6a1e-0000-4000-8000-000000000001";

    private DataSource ds;
    private Connection conn;
    private PreparedStatement ps;
    private LdmSsfStore store;

    @BeforeEach
    void setUp() throws Exception {
        ds = mock(DataSource.class);
        conn = mock(Connection.class);
        ps = mock(PreparedStatement.class);
        when(ds.getConnection()).thenReturn(conn);
        when(conn.prepareStatement(anyString())).thenReturn(ps);
        store = new LdmSsfStore(ds);
    }

    @Test
    void createStreamInsertsAnSsfStreamEntryWithStreamIdAsEntryUuid() throws Exception {
        Stream s = Stream.builder().id(SID).audience("https://r").deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED)
                .createdAt(10).updatedAt(20).build();
        store.createStream(s);
        verify(conn).prepareStatement(contains("INSERT INTO idm.entry"));
        verify(ps).setString(1, SID);                       // entry_uuid = stream id
        verify(ps).setString(2, "{ssfStream}");             // object_classes text[] literal
        verify(ps).setString(org.mockito.ArgumentMatchers.eq(3),
                org.mockito.ArgumentMatchers.argThat(json -> json.contains("\"audience\":\"https:\\/\\/r\"")
                        || json.contains("\"audience\":\"https://r\"")));
        verify(ps).executeUpdate();
    }

    @Test
    void getStreamMapsEntryRow() throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(rs);
        when(rs.next()).thenReturn(true);
        when(rs.getString("id")).thenReturn(SID);
        when(rs.getString("attrs")).thenReturn("{\"audience\":\"https://r\",\"deliveryMethod\":\"urn:ietf:rfc:8936\","
                + "\"streamStatus\":\"paused\",\"statusReason\":\"dead-letter\","
                + "\"eventsRequested\":[\"" + SsfEventTypes.CAEP_SESSION_REVOKED + "\"],"
                + "\"eventsDelivered\":[\"" + SsfEventTypes.CAEP_SESSION_REVOKED + "\"]}");
        when(rs.getLong("created_epoch")).thenReturn(10L);
        when(rs.getLong("modified_epoch")).thenReturn(20L);

        Optional<Stream> s = store.getStream(SID);
        assertTrue(s.isPresent());
        assertEquals(SID, s.get().id());
        assertEquals(DeliveryMethod.POLL, s.get().deliveryMethod());
        assertEquals(StreamStatus.PAUSED, s.get().status());
        assertEquals("dead-letter", s.get().statusReason());
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), s.get().eventsRequested());
        assertEquals(10L, s.get().createdAt());
    }

    @Test
    void addSubjectUsesContainmentAndCanonicalKey() throws Exception {
        // getStream + hasSubject both return "present"/"absent" via the same mocked ps
        ResultSet streamRs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(streamRs);
        when(streamRs.next()).thenReturn(true).thenReturn(false); // stream exists; subject absent
        when(streamRs.getString("id")).thenReturn(SID);
        when(streamRs.getString("attrs")).thenReturn("{\"audience\":\"a\",\"deliveryMethod\":\"urn:ietf:rfc:8936\","
                + "\"streamStatus\":\"enabled\",\"eventsRequested\":[],\"eventsDelivered\":[]}");

        SubjectId alice = SubjectId.email("alice@example.com");
        assertTrue(store.addSubject(SID, alice));
        verify(ps).setString(1, "{ssfStreamSubject}");
        verify(ps).setString(2, SID);                        // parent_id = the stream entry
        verify(ps).setString(3, "email:alice@example.com");  // subject_id = canonical key
    }

    @Test
    void pendingRowMapsBackToPendingSet() throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(rs);
        when(rs.next()).thenReturn(true).thenReturn(false);
        when(rs.getString("stream_id")).thenReturn(SID);
        when(rs.getString("attrs")).thenReturn("{\"jti\":\"j1\",\"eventType\":\"e\",\"subjectKey\":\"k\","
                + "\"setJws\":\"jws\",\"issuedAt\":100,\"deliveryAttempts\":2,\"nextAttemptAt\":300}");
        when(rs.getLong("expires_epoch")).thenReturn(900L);

        List<PendingSet> due = store.dueForPush(500, 10);
        assertEquals(1, due.size());
        PendingSet p = due.get(0);
        assertEquals("j1", p.jti());
        assertEquals(SID, p.streamId());
        assertEquals(2, p.deliveryAttempts());
        assertEquals(300L, p.nextAttemptAt());
        assertEquals(900L, p.expiresAt());
    }

    @Test
    void ackDeletesByStreamAndJti() throws Exception {
        when(ps.executeUpdate()).thenReturn(1);
        assertEquals(1, store.ack(SID, List.of("j1")));
        verify(conn).prepareStatement(contains("attrs->>'jti'"));
        verify(ps).setString(2, "j1");
    }
}
