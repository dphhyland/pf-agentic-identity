/*
 * Who may have the transmitter raise an event, and what the SETs it then signs look like.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

/**
 * The end-to-end shape a CAEP Interop receiver sees: a stream created with no subject ever added, the
 * three profiled events raised by an operator, three SETs that verify and carry what the profile asks.
 */
class SsfEmitServiceTest {

    private static final long NOW = 1_700_000_000L;
    private static final AuthContext RECEIVER = AuthContext.active("receiver-a", Set.of("ssf.manage"));
    private static final AuthContext PROVISIONER = AuthContext.active("operator", Set.of("ssf.provision"));
    private static final Map<String, Object> ALICE = Map.of("format", "email", "email", "alice@example.com");

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("k");
    private final InMemorySsfStore store = new InMemorySsfStore();

    private SsfEmitService service(String defaultSubjects) {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .provisionerScope("ssf.provision").defaultSubjects(defaultSubjects).build();
        return new SsfEmitService(store, new SsfEventEmitter(store, new SetMinter("RS256", keys), cfg), cfg);
    }

    private void stream(String id, List<String> events) {
        store.createStream(Stream.builder().id(id).audience("https://receiver/" + id).ownerClientId("receiver-a")
                .deliveryMethod(DeliveryMethod.POLL).eventsRequested(events).eventsDelivered(events)
                .status(StreamStatus.ENABLED).build());
    }

    private static EmitRequest request(String type, Map<String, Object> event, String streamId) {
        Map<String, Object> body = new java.util.LinkedHashMap<>();
        body.put("event_type", type);
        body.put("subject", ALICE);
        body.put("event", event);
        body.put("stream_id", streamId);
        return EmitRequest.parse(body, NOW);
    }

    @Test
    void aReceiverIsRefusedBeforeAnythingIsSignedAndAProvisionerIsNot() throws Exception {
        SsfEmitService svc = service("ALL");
        stream("s1", SsfEventTypes.CAEP_INTEROP);

        assertThrows(StreamManagementService.ForbiddenException.class,
                () -> svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, null), RECEIVER));
        assertEquals(0, store.peek("s1", 10).size(), "refused before anything was enqueued");

        assertEquals(1, svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, null), PROVISIONER).size());
        assertEquals(1, store.peek("s1", 10).size());
    }

    @Test
    void withNoProvisionerScopeConfiguredNobodyMayRaiseAnEvent() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").defaultSubjects("ALL").build();
        SsfEmitService svc = new SsfEmitService(store, new SsfEventEmitter(store, new SetMinter("RS256", keys), cfg), cfg);
        stream("s1", SsfEventTypes.CAEP_INTEROP);

        assertThrows(StreamManagementService.ForbiddenException.class,
                () -> svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, null), PROVISIONER));
    }

    @Test
    void namingAStreamNarrowsTheFanOutAndAnUnknownOneIsNotFound() throws Exception {
        SsfEmitService svc = service("ALL");
        stream("s1", SsfEventTypes.CAEP_INTEROP);
        stream("s2", SsfEventTypes.CAEP_INTEROP);

        List<SsfEventEmitter.Emitted> emitted = svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, "s2"), PROVISIONER);
        assertEquals(List.of("s2"), emitted.stream().map(SsfEventEmitter.Emitted::streamId).toList());
        assertEquals(0, store.peek("s1", 10).size());

        assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, "absent"), PROVISIONER));
    }

    /** A fan-out of nothing is an answer: with default_subjects NONE and no subject added, nobody hears. */
    @Test
    void noSubscriberIsAnEmptyResultNotAnError() throws Exception {
        SsfEmitService svc = service("NONE");
        stream("s1", SsfEventTypes.CAEP_INTEROP);

        assertEquals(0, svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, null), PROVISIONER).size());
        Map<String, Object> json = SsfEmitService.toJson(SsfEventTypes.CAEP_SESSION_REVOKED, List.of());
        assertEquals(0, json.get("count"));
        assertEquals(List.of(), json.get("emitted"));
    }

    @Test
    @Requirement({"CAEPIOP §2.4.4", "CAEPIOP §2.6", "CAEPIOP §2.8.1", "CAEPIOP §3.1", "CAEPIOP §3.2", "CAEPIOP §3.3"})
    void theThreeInteropEventsReachAStreamNoSubjectWasEverAddedToAsOneEventPerVerifiableSet() throws Exception {
        SsfEmitService svc = service("ALL");
        stream("s1", SsfEventTypes.CAEP_INTEROP);
        assertFalse(store.hasSubject("s1", SubjectId.email("alice@example.com")));

        svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, null), PROVISIONER);
        svc.emit(request(SsfEventTypes.CAEP_CREDENTIAL_CHANGE,
                Map.of("credential_type", "password", "change_type", "update"), null), PROVISIONER);
        svc.emit(request(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE,
                Map.of("previous_status", "compliant", "current_status", "not-compliant"), null), PROVISIONER);

        List<PendingSet> sets = store.peek("s1", 10);
        assertEquals(3, sets.size());
        for (PendingSet pending : sets) {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(pending.setJws());
            jws.setKey(keys.publicKey());
            assertTrue(jws.verifySignature());
            assertEquals("RS256", jws.getAlgorithmHeaderValue());
            assertEquals("secevent+jwt", jws.getHeader("typ"));
            Map<String, Object> claims = JsonUtil.parseJson(jws.getPayload());
            assertEquals("https://op.example.com", claims.get("iss"));
            assertEquals("https://receiver/s1", claims.get("aud"));
            assertFalse(claims.containsKey("sub"));
            assertFalse(claims.containsKey("exp"));
            @SuppressWarnings("unchecked")
            Map<String, Object> events = (Map<String, Object>) claims.get("events");
            assertEquals(1, events.size(), "one event per SET");
            @SuppressWarnings("unchecked")
            Map<String, Object> event = (Map<String, Object>) events.values().iterator().next();
            assertTrue(event.get("reason_admin") instanceof Map);
            assertFalse(((Map<?, ?>) event.get("reason_admin")).isEmpty());
            assertTrue(event.get("event_timestamp") instanceof Number);
            @SuppressWarnings("unchecked")
            Map<String, Object> subId = (Map<String, Object>) claims.get("sub_id");
            assertEquals("email", subId.get("format"));
        }
        assertEquals(Set.of(SsfEventTypes.CAEP_INTEROP.toArray(new String[0])),
                sets.stream().map(PendingSet::eventType).collect(java.util.stream.Collectors.toSet()));
    }

    @Test
    void theResponseNamesEachStreamAndItsDelivery() throws Exception {
        SsfEmitService svc = service("ALL");
        stream("s1", SsfEventTypes.CAEP_INTEROP);

        Map<String, Object> json = SsfEmitService.toJson(SsfEventTypes.CAEP_SESSION_REVOKED,
                svc.emit(request(SsfEventTypes.CAEP_SESSION_REVOKED, null, null), PROVISIONER));
        assertEquals(SsfEventTypes.CAEP_SESSION_REVOKED, json.get("event_type"));
        assertEquals(1, json.get("count"));
        @SuppressWarnings("unchecked")
        Map<String, Object> item = ((List<Map<String, Object>>) json.get("emitted")).get(0);
        assertEquals("s1", item.get("stream_id"));
        assertEquals(DeliveryMethod.POLL.urn(), item.get("delivery"));
        assertTrue(item.get("jti") instanceof String);
    }
}
