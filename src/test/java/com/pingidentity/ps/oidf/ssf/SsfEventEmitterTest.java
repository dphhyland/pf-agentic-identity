/*
 * Event fan-out: only ENABLED streams that deliver the event type AND hold the subject get a SET.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfEventEmitterTest {

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("k");
    private InMemorySsfStore store;
    private SsfEventEmitter emitter;
    private final SubjectId alice = SubjectId.email("alice@example.com");

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").build();
        emitter = new SsfEventEmitter(store, new SetMinter("RS256", keys), cfg);
    }

    private Stream stream(String id, StreamStatus status, String event, boolean withAlice) {
        Stream s = Stream.builder().id(id).audience("https://r/" + id).deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(event)).eventsDelivered(List.of(event)).status(status).build();
        store.createStream(s);
        if (withAlice) {
            store.addSubject(id, alice);
        }
        return s;
    }

    @Test
    void fansOutOnlyToMatchingStreams() throws Exception {
        stream("match", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, true);       // gets it
        stream("wrong-event", StreamStatus.ENABLED, SsfEventTypes.RISC_ACCOUNT_DISABLED, true); // wrong event
        stream("no-subject", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, false);  // subject absent
        stream("paused", StreamStatus.PAUSED, SsfEventTypes.CAEP_SESSION_REVOKED, true);        // not enabled

        List<SsfEventEmitter.Emitted> emitted = emitter.sessionRevoked(alice, "logout");
        assertEquals(1, emitted.size());
        assertEquals("match", emitted.get(0).streamId());

        // only the matching stream has a queued SET, and it targets alice with the right event
        assertEquals(1, store.peek("match", 10).size());
        assertEquals(0, store.peek("wrong-event", 10).size());
        assertEquals(0, store.peek("no-subject", 10).size());
        assertEquals(0, store.peek("paused", 10).size());

        String jws = store.peek("match", 1).get(0).setJws();
        JsonWebSignature v = new JsonWebSignature();
        v.setCompactSerialization(jws);
        v.setKey(keys.publicKey());
        assertTrue(v.verifySignature());
        Map<String, Object> claims = JsonUtil.parseJson(v.getPayload());
        @SuppressWarnings("unchecked")
        Map<String, Object> subId = (Map<String, Object>) claims.get("sub_id");
        assertEquals("alice@example.com", subId.get("email"));
        @SuppressWarnings("unchecked")
        Map<String, Object> events = (Map<String, Object>) claims.get("events");
        assertTrue(events.containsKey(SsfEventTypes.CAEP_SESSION_REVOKED));
    }

    @Test
    void noMatchEmitsNothing() throws Exception {
        stream("s", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, false);
        assertEquals(0, emitter.accountDisabled(alice, "hijacking").size());
    }
}
