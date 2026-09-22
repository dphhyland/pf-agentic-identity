/*
 * LDM store wiring: entry INSERT binding (object_classes/attrs/containment), row->Stream mapping,
 * subject membership predicates, pending mapping. Mockito — a real Postgres round-trip is the model
 * repo's test_migration / deploy-time concern.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.sql.DataSource;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

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

    // ─────────────────────────────── owner ───────────────────────────────

    private static Stream pollStream(String owner) {
        return Stream.builder().id(SID).audience("https://r").ownerClientId(owner).deliveryMethod(DeliveryMethod.POLL)
                .status(StreamStatus.ENABLED).createdAt(10).updatedAt(20).build();
    }

    /**
     * {@code idm.entry} generates its indexed {@code client_id} column from {@code attrs->>'clientId'}. A
     * stream that wrote its owner under that key would turn up in every client-keyed lookup in the model.
     */
    @Test
    void theOwnerIsAnAttributeOfItsOwnAndNotTheModelsClientId() throws Exception {
        store.createStream(pollStream("receiver-a"));

        ArgumentCaptor<String> attrs = ArgumentCaptor.forClass(String.class);
        verify(ps).setString(eq(3), attrs.capture());
        Map<String, Object> written = JsonUtil.parseJson(attrs.getValue());
        assertEquals("receiver-a", written.get("ownerClientId"));
        assertFalse(written.containsKey("clientId"));
    }

    @Test
    void aStreamWithNoOwnerWritesNoOwnerAttribute() throws Exception {
        store.createStream(pollStream(null));

        ArgumentCaptor<String> attrs = ArgumentCaptor.forClass(String.class);
        verify(ps).setString(eq(3), attrs.capture());
        assertFalse(JsonUtil.parseJson(attrs.getValue()).containsKey("ownerClientId"), "absent, not an explicit null");
    }

    @Test
    void anEntrysOwnerIsReadBackAndAnEntryWithoutOneHasNone() throws Exception {
        ResultSet rs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(rs);
        when(rs.next()).thenReturn(true);
        when(rs.getString("id")).thenReturn(SID);
        String rest = "\"audience\":\"a\",\"deliveryMethod\":\"urn:ietf:rfc:8936\",\"streamStatus\":\"enabled\"}";

        when(rs.getString("attrs")).thenReturn("{\"ownerClientId\":\"receiver-a\"," + rest);
        assertEquals("receiver-a", store.getStream(SID).orElseThrow().ownerClientId());

        when(rs.getString("attrs")).thenReturn("{" + rest); // an entry from before streams had owners
        assertEquals(null, store.getStream(SID).orElseThrow().ownerClientId());

        when(rs.getString("attrs")).thenReturn("{\"ownerClientId\":42," + rest); // not a client id, so not an owner
        assertEquals(null, store.getStream(SID).orElseThrow().ownerClientId());
    }

    /**
     * SsfStore#updateStream. attrs is replaced whole, so the statement has to carry the stored owner over
     * itself: strip the one it was sent, restore the one on the row. That the SQL does what it says was
     * checked against Postgres with the model's own trigger; this pins that nobody simplifies it away.
     */
    @Test
    void anUpdateCarriesOverTheStoredOwnerRatherThanTheOneItWasGiven() throws Exception {
        when(ps.executeUpdate()).thenReturn(1);

        store.updateStream(pollStream("receiver-b"));

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(conn).prepareStatement(sql.capture());
        assertTrue(sql.getValue().contains("?::jsonb - 'ownerClientId'"), sql.getValue());
        assertTrue(sql.getValue().contains("jsonb_build_object('ownerClientId', attrs->'ownerClientId')"), sql.getValue());
        assertTrue(sql.getValue().contains("jsonb_strip_nulls("), "or an unowned entry gains \"ownerClientId\": null");
    }

    /** The schema is the model repo's. Whatever this store is asked to do about owners, it is never DDL. */
    @Test
    void recordingOwnersNeverCreatesOrAltersAnything() throws Exception {
        when(ps.executeUpdate()).thenReturn(1);
        ResultSet rs = mock(ResultSet.class);
        when(ps.executeQuery()).thenReturn(rs);

        store.createStream(pollStream("receiver-a"));
        store.updateStream(pollStream("receiver-a"));
        store.getStream(SID);
        store.listStreams();

        ArgumentCaptor<String> sql = ArgumentCaptor.forClass(String.class);
        verify(conn, atLeastOnce()).prepareStatement(sql.capture());
        verify(conn, never()).createStatement();
        for (String statement : sql.getAllValues()) {
            String upper = statement.toUpperCase();
            assertFalse(upper.contains("CREATE ") || upper.contains("ALTER ") || upper.contains("DROP "), statement);
        }
        assertEquals(4, sql.getAllValues().size(), "control: the four statements did run, and were looked at");
    }

    /**
     * As for the JDBC store, the guard is in the SQL. Here a SET with no expiry has a NULL {@code expires_at}
     * (the INSERT's {@code CASE WHEN ? > 0}), and {@code idm.entry} holds every other object class in the
     * model - an eviction not pinned to {@code ssfPendingSet} would delete whatever else carries an expiry.
     */
    @Test
    void evictExpiredDeletesOnlyPendingSetsWithAnExpiryAtOrBeforeNow() throws Exception {
        when(ps.executeUpdate()).thenReturn(2);

        assertEquals(2, store.evictExpired(300));

        verify(conn).prepareStatement("DELETE FROM idm.entry WHERE ? = ANY (object_classes) "
                + "AND expires_at IS NOT NULL AND expires_at <= to_timestamp(?)");
        verify(ps).setString(1, "ssfPendingSet");
        verify(ps).setLong(2, 300L);
    }
}
