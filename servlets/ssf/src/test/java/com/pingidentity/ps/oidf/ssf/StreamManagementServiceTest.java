/*
 * Stream CRUD state machine, subjects, verification, and poll/ack semantics.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import java.net.InetAddress;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class StreamManagementServiceTest {

    /** What each stream below is created and managed by. Who else may touch them is {@link StreamOwnershipTest}. */
    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("test-set-key");
    private InMemorySsfStore store;
    private StreamManagementService svc;
    private SsfConfiguration cfg;

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        // the audience these bodies name is one the operator has agreed for this client
        cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .allowedAudiences("receiver-client=https://receiver.example.com").build();
        svc = new StreamManagementService(store, new SetMinter("RS256", keys), cfg, SetPublisher.NOOP, testPolicy());
    }

    /**
     * Push endpoints are screened by {@link OutboundUrlPolicy} before they are stored, and the policy
     * resolves the host. A stubbed resolver keeps these tests hermetic: without it every case using
     * {@code receiver.example.com} depends on DNS, and the suite fails offline (as it did the moment
     * the screening went in — "cannot resolve it"). Everything resolves public except the hosts named.
     */
    private static OutboundUrlPolicy testPolicy() {
        return OutboundUrlPolicy.from(Map.<String, String>of()::get).withResolver(host -> {
            try {
                String ip = "metadata.internal".equals(host) ? "169.254.169.254" : "93.184.216.34";
                return new InetAddress[] { InetAddress.getByName(ip) };
            }
            catch (Exception e) {
                throw new IllegalArgumentException(e);
            }
        });
    }

    private Map<String, Object> pollBody() {
        return Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.POLL.urn()),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED, "https://unknown/event"));
    }

    @Test
    @Requirement("SSF §8.1.1.1")
    void createPollStreamNarrowsEventsAndAdvertisesPollUrl() {
        Map<String, Object> s = svc.createStream(pollBody(), RECEIVER);
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
    @Requirement("SSF §8.1.1.1")
    void createPushStreamRequiresEndpoint() {
        assertThrows(IllegalArgumentException.class, () -> svc.createStream(Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn())), RECEIVER));
        Map<String, Object> ok = svc.createStream(Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(), "endpoint_url", "https://receiver.example.com/set")), RECEIVER);
        @SuppressWarnings("unchecked")
        Map<String, Object> delivery = (Map<String, Object>) ok.get("delivery");
        assertEquals("https://receiver.example.com/set", delivery.get("endpoint_url"));
    }

    @Test
    @Requirement({"SSF §8.1.1.2", "SSF §8.1.1.3", "SSF §8.1.1.5"})
    void crudAndListing() {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        assertEquals(id, svc.getStream(id, RECEIVER).get("stream_id"));
        assertEquals(1, ((List<?>) svc.listStreams(RECEIVER)).size());

        Map<String, Object> updated = svc.updateStream(id, Map.of("events_requested", List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED)), RECEIVER);
        @SuppressWarnings("unchecked")
        List<String> req = (List<String>) updated.get("events_requested");
        assertEquals(List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED), req);

        svc.deleteStream(id, RECEIVER);
        assertThrows(StreamManagementService.NotFoundException.class, () -> svc.getStream(id, RECEIVER));
        assertThrows(StreamManagementService.NotFoundException.class, () -> svc.deleteStream(id, RECEIVER));
    }

    @Test
    @Requirement({"SSF §8.1.2.1", "SSF §8.1.2.2"})
    void statusStateMachine() {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        assertEquals("enabled", svc.getStatus(id, RECEIVER).get("status"));
        Map<String, Object> paused = svc.setStatus(id, "paused", "admin paused", RECEIVER);
        assertEquals("paused", paused.get("status"));
        assertEquals("admin paused", paused.get("reason"));
        assertEquals("disabled", svc.setStatus(id, "disabled", null, RECEIVER).get("status"));
        assertThrows(IllegalArgumentException.class, () -> svc.setStatus(id, "bogus", null, RECEIVER));
    }

    @Test
    @Requirement({"SSF §8.1.3.2", "SSF §8.1.3.3"})
    void subjectManagement() {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        SubjectId alice = SubjectId.email("alice@example.com");
        svc.addSubject(id, alice, RECEIVER);
        assertTrue(store.hasSubject(id, alice));
        svc.removeSubject(id, alice, RECEIVER);
        assertFalse(store.hasSubject(id, alice));
        assertThrows(StreamManagementService.NotFoundException.class,
                () -> svc.addSubject("no-such-stream", alice, RECEIVER));
    }

    @Test
    @Requirement({"SSF §8.1.4.1", "RFC8936 §2.2", "RFC8936 §2.3"})
    void verifyMintsSignedSetThatPollReturnsAndAckClears() throws Exception {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        String jti = svc.verify(id, "state-123", RECEIVER);
        assertNotNull(jti);

        // poll returns the verification SET
        Map<String, Object> polled = svc.poll(id, null, 10, true, RECEIVER);
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
        // This asserted the opposite until 2026-09, under the same clause: "verification SETs carry no
        // sub_id". SSF 1.0 Final §8.1.4.1 makes it REQUIRED, opaque, and the stream's own id.
        assertEquals(Map.of("format", "opaque", "id", id), claims.get("sub_id"));

        // ack clears it; next poll is empty
        Map<String, Object> after = svc.poll(id, List.of(jti), 10, true, RECEIVER);
        assertEquals(0, ((Map<?, ?>) after.get("sets")).size());
    }

    @Test
    @Requirement({"RFC8936 §2.2", "RFC8936 §2.3"})
    void pollHonoursMaxEventsAndReportsMore() throws Exception {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        svc.verify(id, "a", RECEIVER);
        svc.verify(id, "b", RECEIVER);
        svc.verify(id, "c", RECEIVER);
        Map<String, Object> polled = svc.poll(id, null, 2, true, RECEIVER);
        assertEquals(2, ((Map<?, ?>) polled.get("sets")).size());
        assertEquals(Boolean.TRUE, polled.get("moreAvailable"));
    }

    @Test
    @Requirement("RFC8936 §2.2")
    void maxEventsZeroAcknowledgesAndReturnsNothing() throws Exception {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        String first = svc.verify(id, "a", RECEIVER);
        svc.verify(id, "b", RECEIVER);

        Map<String, Object> polled = svc.poll(id, List.of(first), 0, true, RECEIVER);

        assertEquals(0, ((Map<?, ?>) polled.get("sets")).size(), "0 used to fall back to the configured cap");
        assertEquals(Boolean.TRUE, polled.get("moreAvailable"), "the unacknowledged SET is still waiting");
        assertEquals(1, ((Map<?, ?>) svc.poll(id, null, 10, true, RECEIVER).get("sets")).size(), "and the ack was applied");
    }

    // ─────────────────────────────── setTtlSeconds on the read side ───────────────────────────────

    private static PendingSet queuedSet(String jti, String streamId, long issuedAt, long expiresAt) {
        return PendingSet.fresh(jti, streamId, "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-" + jti, issuedAt,
                expiresAt);
    }

    /**
     * Deliberately untagged. Nothing in RFC 8936 or SSF obliges a transmitter to withhold an old SET: RFC
     * 8936 §2 permits the discard ("Transmitters may also discard undelivered SETs under
     * deployment-specific conditions") and a SET carries no expiry of its own to be held to - SSF §4.1.7,
     * "The "exp" claim MUST NOT be used in SETs". {@code setTtlSeconds} is this transmitter's retention
     * setting; that a poll enforces it without waiting for the background loop is this transmitter's too.
     *
     * <p>The expired SETs are the oldest, so they head the queue. A poll that skipped them in the page it
     * read, instead of evicting, would fail both assertions on {@code max_events = 1}: it would return
     * nothing, and report more available.
     */
    @Test
    void pollNeverReturnsASetPastItsTtlEvenIfNoLoopHasEvictedIt() {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        long now = SetMinter.nowSeconds();
        store.enqueue(queuedSet("dead-1", id, 10, now - 3600));
        store.enqueue(queuedSet("dead-2", id, 20, now - 1));
        store.enqueue(queuedSet("live", id, 30, now + 3600));

        Map<String, Object> polled = svc.poll(id, null, 1, true, RECEIVER);

        assertEquals(Set.of("live"), ((Map<?, ?>) polled.get("sets")).keySet(), "the unexpired SET behind them is returned");
        assertEquals(Boolean.FALSE, polled.get("moreAvailable"), "expired SETs are not counted as waiting");
        assertEquals(List.of("live"), store.peek(id, 10).stream().map(PendingSet::jti).toList(),
                "and they are gone from the store, not merely hidden from this poll");
    }

    /** Deliberately untagged: {@code setTtlSeconds <= 0} meaning "no expiry" is a repo default, not a clause. */
    @Test
    void aSetMintedWithNoTtlIsNeverEvictedByAPoll() throws Exception {
        cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").setTtlSeconds(0)
                .allowedAudiences("receiver-client=https://receiver.example.com").build();
        svc = new StreamManagementService(store, new SetMinter("RS256", keys), cfg, SetPublisher.NOOP, testPolicy());
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");
        String kept = svc.verify(id, "no-ttl", RECEIVER);
        store.enqueue(queuedSet("dead", id, 10, SetMinter.nowSeconds() - 1));

        Map<String, Object> polled = svc.poll(id, null, 10, true, RECEIVER);

        assertEquals(0, store.peek(id, 10).get(0).expiresAt(), "minted with no expiry");
        assertEquals(Set.of(kept), ((Map<?, ?>) polled.get("sets")).keySet(),
                "the expired SET beside it is dropped; the one with no expiry is delivered");
    }

    // ─────────────────────────────── aud is the transmitter's to assign ───────────────────────────────

    private Map<String, Object> pollBodyWithoutAudience() {
        return Map.of(
                "delivery", Map.of("method", DeliveryMethod.POLL.urn()),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED));
    }

    @Test
    @Requirement("SSF §8.1.1")
    void aReceiverThatSendsNoAudienceIsAssignedItsOwnClientId() throws Exception {
        Map<String, Object> s = svc.createStream(pollBodyWithoutAudience(), RECEIVER);

        assertEquals("receiver-client", s.get("aud"));
        // and it is the audience of what the stream then delivers, not only of what the API reports
        String id = (String) s.get("stream_id");
        String jti = svc.verify(id, null, RECEIVER);
        JsonWebSignature set = new JsonWebSignature();
        set.setCompactSerialization((String) ((Map<?, ?>) svc.poll(id, null, 1, true, RECEIVER).get("sets")).get(jti));
        assertEquals("receiver-client", JsonUtil.parseJson(set.getUnverifiedPayload()).get("aud"));
    }

    /**
     * {@code aud} is the transmitter's to supply. A receiver that names one gets it only where the
     * transmitter would have supplied it anyway: its own client id, or an audience the operator agreed for
     * that client out of band. Anything else would have SETs signed to an audience of the receiver's choosing.
     */
    @Test
    @Requirement("SSF §8.1.1")
    void aReceiverCannotChooseItsAudience() {
        AuthContext other = AuthContext.active("receiver-b", Set.of("ssf.manage"));
        for (Object chosen : new Object[] {"https://victim.example.com", other.clientId(), "Receiver-Client",
                List.of("https://receiver.example.com"), "", 7}) {
            Map<String, Object> body = new HashMap<>(pollBodyWithoutAudience());
            body.put("aud", chosen);
            assertThrows(IllegalArgumentException.class, () -> svc.createStream(body, RECEIVER), "aud " + chosen);
        }
        // an audience agreed for one client is not agreed for another
        assertThrows(IllegalArgumentException.class, () -> svc.createStream(pollBody(), other));
        assertTrue(store.listStreams().isEmpty(), "a refused create leaves nothing behind");

        // controls: the same body is accepted once aud is one this caller may use, so the refusals above were about aud
        assertEquals("https://receiver.example.com", svc.createStream(pollBody(), RECEIVER).get("aud"));
        Map<String, Object> own = new HashMap<>(pollBodyWithoutAudience());
        own.put("aud", RECEIVER.clientId());
        assertEquals(RECEIVER.clientId(), svc.createStream(own, RECEIVER).get("aud"));
    }

    @Test
    void aTokenThatNamesNoClientMayAddressNoAudience() {
        StreamAccess access = new StreamAccess(cfg);
        assertFalse(access.mayAddress(AuthContext.active(null, Set.of("ssf.manage")), "https://receiver.example.com"));
        assertFalse(access.mayAddress(null, "https://receiver.example.com"));
        assertTrue(access.mayAddress(RECEIVER, "https://receiver.example.com")); // control
    }

    @Test
    @Requirement("SSF §8.1.1")
    void aStreamReportsTheEventsItCouldDeliver() {
        Map<String, Object> s = svc.createStream(pollBody(), RECEIVER);

        @SuppressWarnings("unchecked")
        List<String> supported = (List<String>) s.get("events_supported");
        assertNotNull(supported, "absent, a receiver cannot tell an unsupported event from a refused one");
        assertTrue(supported.containsAll((List<?>) s.get("events_delivered")));
        assertFalse(supported.contains("https://unknown/event"));
    }

    // ─────────────────────────────── PATCH and PUT ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.1.3")
    void anUpdateCannotMoveTheAudienceAndChangesNothingWhenItTries() {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");

        assertThrows(IllegalArgumentException.class, () -> svc.updateStream(id, Map.of(
                "aud", "https://someone-else.example.com",
                "events_requested", List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE)), RECEIVER));

        Map<String, Object> after = svc.getStream(id, RECEIVER);
        assertEquals("https://receiver.example.com", after.get("aud"));
        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), after.get("events_delivered"),
                "the refused request's other properties were not applied");
    }

    @Test
    @Requirement("SSF §8.1.1.3")
    void anUpdateMayEchoTransmitterSuppliedPropertiesAsTheyStand() {
        Map<String, Object> created = svc.createStream(pollBody(), RECEIVER);
        String id = (String) created.get("stream_id");

        Map<String, Object> updated = svc.updateStream(id, Map.of(
                "iss", "https://op.example.com",
                "aud", "https://receiver.example.com",
                "events_delivered", created.get("events_delivered"),
                "events_requested", List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE)), RECEIVER);

        assertEquals(List.of(SsfEventTypes.CAEP_CREDENTIAL_CHANGE), updated.get("events_delivered"));
        assertThrows(IllegalArgumentException.class,
                () -> svc.updateStream(id, Map.of("iss", "https://another-issuer.example.com"), RECEIVER));
        assertThrows(IllegalArgumentException.class,
                () -> svc.updateStream(id, Map.of("events_delivered", List.of(SsfEventTypes.RISC_ACCOUNT_DISABLED)), RECEIVER));
    }

    @Test
    @Requirement("SSF §8.1.1.4")
    void aReplacementDeletesTheReceiverSuppliedPropertiesItLeavesOut() {
        String id = (String) svc.createStream(Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(),
                        "endpoint_url", "https://receiver.example.com/events",
                        "authorization_header", "Bearer old"),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED)), RECEIVER).get("stream_id");

        Map<String, Object> replaced = svc.replaceStream(id, Map.of(
                "stream_id", id,
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(),
                        "endpoint_url", "https://receiver.example.com/events-v2")), RECEIVER);

        assertEquals(List.of(), replaced.get("events_requested"), "an update would have left these alone");
        assertEquals(List.of(), replaced.get("events_delivered"));
        Stream stored = store.getStream(id).orElseThrow();
        assertEquals("https://receiver.example.com/events-v2", stored.pushEndpointUrl());
        assertEquals(null, stored.pushAuthorizationHeader(), "the old header must not outlive the replacement");
        assertEquals("https://receiver.example.com", replaced.get("aud"), "Transmitter-Supplied, so untouched");
    }

    @Test
    @Requirement("SSF §8.1.1.4")
    void aReplacementIsRefusedWithoutDeliveryOrForAnotherMethodOrAnUnscreenedEndpoint() {
        String id = (String) svc.createStream(pollBody(), RECEIVER).get("stream_id");

        assertThrows(IllegalArgumentException.class, () -> svc.replaceStream(id, Map.of("stream_id", id), RECEIVER));
        assertThrows(IllegalArgumentException.class, () -> svc.replaceStream(id, Map.of(
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(), "endpoint_url", "https://receiver.example.com/e")), RECEIVER));
        assertThrows(IllegalArgumentException.class, () -> svc.replaceStream(id, Map.of(
                "aud", "https://someone-else.example.com",
                "delivery", Map.of("method", DeliveryMethod.POLL.urn())), RECEIVER));
        assertThrows(StreamManagementService.NotFoundException.class, () -> svc.replaceStream("no-such-stream",
                Map.of("delivery", Map.of("method", DeliveryMethod.POLL.urn())), RECEIVER));

        assertEquals(List.of(SsfEventTypes.CAEP_SESSION_REVOKED), svc.getStream(id, RECEIVER).get("events_delivered"),
                "none of the refused replacements was applied");
    }

    /** PUT is a second door onto the push endpoint, so it is screened like CREATE and PATCH. */
    @Test
    void aReplacementCannotPointAPushStreamAtAnInternalAddress() {
        String id = (String) svc.createStream(Map.of(
                "aud", "https://receiver.example.com",
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(), "endpoint_url", "https://receiver.example.com/events"),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED)), RECEIVER).get("stream_id");

        assertThrows(IllegalArgumentException.class, () -> svc.replaceStream(id, Map.of(
                "delivery", Map.of("method", DeliveryMethod.PUSH.urn(), "endpoint_url", "https://metadata.internal/latest")), RECEIVER));
        assertEquals("https://receiver.example.com/events", store.getStream(id).orElseThrow().pushEndpointUrl());
    }
}
