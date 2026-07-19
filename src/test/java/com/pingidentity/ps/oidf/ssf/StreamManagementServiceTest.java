/*
 * Stream CRUD state machine, subjects, verification, and poll/ack semantics.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StreamManagementServiceTest {

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("test-set-key");
    private InMemorySsfStore store;
    private StreamManagementService svc;
    private SsfConfiguration cfg;

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        svc = new StreamManagementService(store, new SetMinter("RS256", keys), cfg);
    }

    private Map<String, Object> pollBody() {
        return Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.POLL.urn()),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED, "https://unknown/event"));
    }

    @Test
    void createPollStreamNarrowsEventsAndAdvertisesPollUrl() {
        Map<String, Object> s = svc.createStream(pollBody());
        String id = (String) s.get("stream_id");
        assertNotNull(id);
        assertEquals("enabled", s.get("status"));
        @SuppressWarnings("unchecked")
        List<String> delivered = (List<String>) s.get("events_delivered");
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), delivered, "unknown event types are dropped");
        @SuppressWarnings("unchecked")
        Map<String, Object> delivery = (Map<String, Object>) s.get("delivery");
        assertEquals(DeliveryMethod.POLL.urn(), delivery.get("method"));
        assertEquals("https://op.example.com/ssf/poll?stream_id=" + id, delivery.get("endpoint_url"));
    }

    @Test
    void createPushStreamRequiresEndpoint() {
        assertThrows(IllegalArgumentException.class, () -> svc.createStream(Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn()))));
        Map<String, Object> ok = svc.createStream(Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(), "endpoint_url", "https://receiver.example.com/set")));
        @SuppressWarnings("unchecked")
        Map<String, Object> delivery = (Map<String, Object>) ok.get("delivery");
        assertEquals("https://receiver.example.com/set", delivery.get("endpoint_url"));
    }

    @Test
    void crudAndListing() {
        String id = (String) svc.createStream(pollBody()).get("stream_id");
        assertEquals(id, svc.getStream(id).get("stream_id"));
        assertEquals(1, ((List<?>) svc.listStreams()).size());

        Map<String, Object> updated = svc.updateStream(id, Map.of("events_requested", List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED)));
        @SuppressWarnings("unchecked")
        List<String> req = (List<String>) updated.get("events_requested");
        assertEquals(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED), req);

        svc.deleteStream(id);
        assertThrows(StreamManagementService.NotFoundException.class, () -> svc.getStream(id));
        assertThrows(StreamManagementService.NotFoundException.class, () -> svc.deleteStream(id));
    }

    @Test
    void statusStateMachine() {
        String id = (String) svc.createStream(pollBody()).get("stream_id");
        assertEquals("enabled", svc.getStatus(id).get("status"));
        Map<String, Object> paused = svc.setStatus(id, "paused", "admin paused");
        assertEquals("paused", paused.get("status"));
        assertEquals("admin paused", paused.get("reason"));
        assertEquals("disabled", svc.setStatus(id, "disabled", null).get("status"));
        assertThrows(IllegalArgumentException.class, () -> svc.setStatus(id, "bogus", null));
    }

    @Test
    void subjectManagement() {
        String id = (String) svc.createStream(pollBody()).get("stream_id");
        SubjectId alice = SubjectId.email("alice@example.com");
        svc.addSubject(id, alice);
        assertTrue(store.hasSubject(id, alice));
        svc.removeSubject(id, alice);
        assertFalse(store.hasSubject(id, alice));
        assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.addSubject("no-such-stream", alice));
    }

    @Test
    void verifyMintsSignedSetThatPollReturnsAndAckClears() throws Exception {
        String id = (String) svc.createStream(pollBody()).get("stream_id");
        String jti = svc.verify(id, "state-123");
        assertNotNull(jti);

        // poll returns the verification SET
        Map<String, Object> polled = svc.poll(id, null, 10, true);
        @SuppressWarnings("unchecked")
        Map<String, Object> sets = (Map<String, Object>) polled.get("sets");
        assertEquals(1, sets.size());
        assertTrue(sets.containsKey(jti));
        assertEquals(Boolean.FALSE, polled.get("moreAvailable"));

        // the SET is a valid signed verification event with the echoed state
        String jws = (String) sets.get(jti);
        JsonWebSignature v = new JsonWebSignature();
        v.setCompactSerialization(jws);
        assertEquals("secevent+jwt", v.getHeader("typ"));
        v.setKey(keys.publicKey());
        assertTrue(v.verifySignature());
        Map<String, Object> claims = JsonUtil.parseJson(v.getPayload());
        @SuppressWarnings("unchecked")
        Map<String, Object> events = (Map<String, Object>) claims.get("events");
        @SuppressWarnings("unchecked")
        Map<String, Object> verEvent = (Map<String, Object>) events.get(SsfEventTypes.VERIFICATION);
        assertEquals("state-123", verEvent.get("state"));
        assertFalse(claims.containsKey("sub_id"), "verification SETs carry no sub_id");

        // ack clears it; next poll is empty
        Map<String, Object> after = svc.poll(id, List.of(jti), 10, true);
        assertEquals(0, ((Map<?, ?>) after.get("sets")).size());
    }

    @Test
    void pollHonoursMaxEventsAndReportsMore() throws Exception {
        String id = (String) svc.createStream(pollBody()).get("stream_id");
        svc.verify(id, "a");
        svc.verify(id, "b");
        svc.verify(id, "c");
        Map<String, Object> polled = svc.poll(id, null, 2, true);
        assertEquals(2, ((Map<?, ?>) polled.get("sets")).size());
        assertEquals(Boolean.TRUE, polled.get("moreAvailable"));
    }
}
