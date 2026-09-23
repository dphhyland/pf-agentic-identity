/*
 * Event fan-out: only ENABLED streams that deliver the event type AND hold the subject get a SET.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
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
        // each stream is its own receiver's, so a fan-out that reaches two of them has crossed receivers
        Stream s = Stream.builder().id(id).audience("https://r/" + id).ownerClientId("receiver-of-" + id)
                .deliveryMethod(DeliveryMethod.POLL)
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

    /**
     * The one rule, conjunct by conjunct: enabled, delivers the type, and hears about the subject - by
     * membership, or because default_subjects is ALL. Each row flips one thing.
     */
    @Test
    @Requirement({"SSF §7.1.1", "CAEPIOP §2.4.4"})
    void subscribesIsEnabledAndDeliversAndEitherMemberOrDefaultSubjectsAll() {
        Stream enabledMember = stream("a", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, true);
        Stream enabledStranger = stream("b", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, false);
        Stream pausedMember = stream("c", StreamStatus.PAUSED, SsfEventTypes.CAEP_SESSION_REVOKED, true);
        Stream wrongEvent = stream("d", StreamStatus.ENABLED, SsfEventTypes.RISC_ACCOUNT_DISABLED, true);

        assertTrue(emitter.subscribes(enabledMember, SsfEventTypes.CAEP_SESSION_REVOKED, alice));
        assertFalse(emitter.subscribes(enabledStranger, SsfEventTypes.CAEP_SESSION_REVOKED, alice), "not a member, NONE");
        assertFalse(emitter.subscribes(pausedMember, SsfEventTypes.CAEP_SESSION_REVOKED, alice), "paused");
        assertFalse(emitter.subscribes(wrongEvent, SsfEventTypes.CAEP_SESSION_REVOKED, alice), "does not deliver the type");

        SsfEventEmitter all = new SsfEventEmitter(store, new SetMinter("RS256", keys),
                new SsfConfiguration.Builder().issuer("https://op.example.com").defaultSubjects("ALL").build());
        assertTrue(all.subscribes(enabledStranger, SsfEventTypes.CAEP_SESSION_REVOKED, alice), "ALL: membership not needed");
        assertFalse(all.subscribes(pausedMember, SsfEventTypes.CAEP_SESSION_REVOKED, alice), "ALL does not enable a paused stream");
        assertFalse(all.subscribes(wrongEvent, SsfEventTypes.CAEP_SESSION_REVOKED, alice), "ALL does not widen the events");
    }

    @Test
    @Requirement("CAEPIOP §2.4.4")
    void withDefaultSubjectsAllAStreamNoSubjectWasAddedToStillHears() throws Exception {
        SsfEventEmitter all = new SsfEventEmitter(store, new SetMinter("RS256", keys),
                new SsfConfiguration.Builder().issuer("https://op.example.com").defaultSubjects("ALL").build());
        stream("no-subject", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, false);

        assertEquals(1, all.sessionRevoked(alice, "logout").size());
        assertEquals(1, store.peek("no-subject", 10).size());
    }

    @Test
    void namingAStreamOnlyNarrowsTheFanOut() throws Exception {
        stream("one", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, true);
        stream("two", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, true);
        stream("no-subject", StreamStatus.ENABLED, SsfEventTypes.CAEP_SESSION_REVOKED, false);

        List<SsfEventEmitter.Emitted> only = emitter.emit(SsfEventTypes.CAEP_SESSION_REVOKED, alice,
                CaepRiscEvents.sessionRevoked(1L, "x"), "two");
        assertEquals(List.of("two"), only.stream().map(SsfEventEmitter.Emitted::streamId).toList());
        assertEquals(0, store.peek("one", 10).size());

        assertEquals(0, emitter.emit(SsfEventTypes.CAEP_SESSION_REVOKED, alice,
                CaepRiscEvents.sessionRevoked(1L, "x"), "no-subject").size(), "named, but it still has to subscribe");
    }

    @Test
    @Requirement("CAEP §3.5")
    void deviceComplianceChangeIsAnEventThisTransmitterCanEmit() throws Exception {
        stream("s", StreamStatus.ENABLED, SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, true);

        assertEquals(1, emitter.deviceComplianceChange(alice, "compliant", "not-compliant", Map.of("en", "jailbroken")).size());
        JsonWebSignature v = new JsonWebSignature();
        v.setCompactSerialization(store.peek("s", 1).get(0).setJws());
        v.setKey(keys.publicKey());
        assertTrue(v.verifySignature());
        @SuppressWarnings("unchecked")
        Map<String, Object> events = (Map<String, Object>) JsonUtil.parseJson(v.getPayload()).get("events");
        @SuppressWarnings("unchecked")
        Map<String, Object> event = (Map<String, Object>) events.get(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE);
        assertEquals("not-compliant", event.get("current_status"));
        assertEquals(Map.of("en", "jailbroken"), event.get("reason_admin"));
    }

    /** The transmitter's events are not any one receiver's: every receiver that subscribed hears. */
    @Test
    void anEventTheTransmitterObservedForItselfStillGoesToEveryReceiver() throws Exception {
        stream("mine", StreamStatus.ENABLED, SsfEventTypes.RISC_ACCOUNT_DISABLED, true);
        stream("theirs", StreamStatus.ENABLED, SsfEventTypes.RISC_ACCOUNT_DISABLED, true);

        assertEquals(2, emitter.accountDisabled(alice, "hijacking").size());
        assertEquals(1, store.peek("theirs", 10).size());
    }
}
