/*
 * The optional stream members of SSF 1.0 §8.1.1, the verification interval, and the cap on streams per receiver.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.signals.SetMinter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Plan item H-SSF-3. SSF 1.0 §8.1.1 (final, 29 August 2025) defines three optional members of a stream's
 * configuration: {@code min_verification_interval} ("Transmitter-Supplied, OPTIONAL. An integer indicating the minimum
 * amount of time in seconds that must pass in between verification requests"), {@code description}
 * ("Receiver-Supplied, OPTIONAL. A string that describes the properties of the stream") and
 * {@code inactivity_timeout} ("Transmitter-Supplied, OPTIONAL. The refreshable inactivity timeout of the stream in
 * seconds").
 */
class StreamOptionalMembersTest {

    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));
    private static final AuthContext OTHER = AuthContext.active("receiver-b", Set.of("ssf.manage"));

    private InMemorySsfStore store;
    private final AtomicLong clock = new AtomicLong(1_000_000L);

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
    }

    private StreamManagementService service(SsfConfiguration cfg) {
        return new StreamManagementService(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), cfg, SetPublisher.NOOP,
                OutboundUrlPolicy.from(Map.<String, String>of()::get), clock::get);
    }

    private static SsfConfiguration.Builder config() {
        return new SsfConfiguration.Builder().issuer("https://op.example.com");
    }

    private static Map<String, Object> pollBody(Object description) {
        Map<String, Object> body = new HashMap<>();
        body.put("delivery", Map.of("method", DeliveryMethod.POLL.urn()));
        body.put("events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED));
        if (description != null) {
            body.put("description", description);
        }
        return body;
    }

    // ─────────────────────────────── the members ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.1")
    void aStreamCarriesItsDescriptionAndTheTransmittersIntervalAndTimeout() {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(45).inactivityTimeoutSeconds(86400).build());
        Map<String, Object> created = svc.createStream(pollBody("Stream for receiver A"), RECEIVER);
        String id = (String) created.get("stream_id");
        assertEquals("Stream for receiver A", created.get("description"));
        assertEquals(45, created.get("min_verification_interval"));
        assertEquals(86400L, created.get("inactivity_timeout"));

        Stream stored = store.getStream(id).orElseThrow();
        assertEquals("Stream for receiver A", stored.description());
        assertEquals(45, stored.minVerificationInterval());
        assertEquals(86400L, stored.inactivityTimeout());
        assertEquals(created, svc.getStream(id, RECEIVER));
        assertEquals(List.of(created), svc.listStreams(RECEIVER));
    }

    /** They are Transmitter-Supplied: a receiver that sends them at creation does not choose them. */
    @Test
    @Requirement("SSF §8.1.1")
    void aReceiverDoesNotSetTheTransmitterSuppliedMembers() {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(30).build());
        Map<String, Object> body = pollBody(null);
        body.put("min_verification_interval", 0);
        body.put("inactivity_timeout", 5);
        Map<String, Object> created = svc.createStream(body, RECEIVER);
        assertEquals(30, created.get("min_verification_interval"));
        assertFalse(created.containsKey("inactivity_timeout"), "this transmitter gives none");
        assertFalse(created.containsKey("description"));
    }

    @Test
    void aTransmitterWithNeitherSettingGivesNeitherMember() {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(0).inactivityTimeoutSeconds(0).build());
        Map<String, Object> created = svc.createStream(pollBody(null), RECEIVER);
        assertFalse(created.containsKey("min_verification_interval") || created.containsKey("inactivity_timeout"));
        Stream stored = store.getStream((String) created.get("stream_id")).orElseThrow();
        assertEquals(null, stored.minVerificationInterval());
        assertEquals(null, stored.inactivityTimeout());
    }

    /** A stream stored before 0.6.0 has neither member; it is reported, and held to, the transmitter's current settings. */
    @Test
    void aStreamStoredWithoutTheMembersReportsTheCurrentSettings() {
        store.createStream(Stream.builder().id("old").audience("receiver-client").ownerClientId(RECEIVER.clientId())
                .deliveryMethod(DeliveryMethod.POLL).build());
        Map<String, Object> read = service(config().minVerificationIntervalSeconds(10).inactivityTimeoutSeconds(600).build())
                .getStream("old", RECEIVER);
        assertEquals(10, read.get("min_verification_interval"));
        assertEquals(600L, read.get("inactivity_timeout"));
    }

    /** SSF §8.1.1: "The transmitter MAY truncate the string beyond an allowed max length." */
    @Test
    @Requirement("SSF §8.1.1")
    void aLongDescriptionIsTruncatedAndOneThatIsNotAStringRefused() {
        StreamManagementService svc = service(config().build());
        String longer = "d".repeat(StreamManagementService.DESCRIPTION_MAX + 10);
        assertEquals(StreamManagementService.DESCRIPTION_MAX,
                ((String) svc.createStream(pollBody(longer), RECEIVER).get("description")).length());
        String straddling = "d".repeat(StreamManagementService.DESCRIPTION_MAX - 1) + "😀";
        assertEquals(StreamManagementService.DESCRIPTION_MAX - 1,
                ((String) svc.createStream(pollBody(straddling), RECEIVER).get("description")).length(),
                "a pair that straddles the limit is dropped whole, not split");
        assertThrows(IllegalArgumentException.class, () -> svc.createStream(pollBody(42), RECEIVER));
    }

    /**
     * SSF §8.1.1.3: "Any properties missing in the request MUST NOT be changed"; §8.1.1.4: "Missing Receiver-Supplied
     * properties MUST be interpreted as requested to be deleted."
     */
    @Test
    @Requirement({"SSF §8.1.1.3", "SSF §8.1.1.4"})
    void patchChangesTheDescriptionAndPutWithoutOneDeletesIt() {
        StreamManagementService svc = service(config().build());
        String id = (String) svc.createStream(pollBody("first"), RECEIVER).get("stream_id");
        assertEquals("first", svc.updateStream(id, Map.of("events_requested", List.of()), RECEIVER).get("description"));
        assertEquals("second", svc.updateStream(id, Map.of("description", "second"), RECEIVER).get("description"));
        Map<String, Object> nulled = new HashMap<>();
        nulled.put("description", null);
        assertFalse(svc.updateStream(id, nulled, RECEIVER).containsKey("description"));

        svc.updateStream(id, Map.of("description", "third"), RECEIVER);
        Map<String, Object> put = pollBody(null);
        assertFalse(svc.replaceStream(id, put, RECEIVER).containsKey("description"));
        put.put("description", "fourth");
        assertEquals("fourth", svc.replaceStream(id, put, RECEIVER).get("description"));
        assertEquals("fourth", store.getStream(id).orElseThrow().description());
    }

    /** SSF §8.1.1.3: Transmitter-Supplied properties "MAY be present, but they MUST match the expected value." */
    @Test
    @Requirement({"SSF §8.1.1.3", "SSF §8.1.1.4"})
    void theTransmitterSuppliedMembersMayBeEchoedOnlyAsTheyStand() {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(30).build());
        String id = (String) svc.createStream(pollBody(null), RECEIVER).get("stream_id");
        Map<String, Object> echo = new HashMap<>(Map.of("min_verification_interval", 30));
        echo.put("inactivity_timeout", null);
        assertEquals(30, svc.updateStream(id, echo, RECEIVER).get("min_verification_interval"));
        Map<String, Object> put = pollBody(null);
        put.put("min_verification_interval", 30.0);
        svc.replaceStream(id, put, RECEIVER);

        for (Map<String, Object> moved : List.<Map<String, Object>>of(Map.of("min_verification_interval", 0),
                Map.of("min_verification_interval", "30"), Map.of("inactivity_timeout", 60))) {
            assertThrows(IllegalArgumentException.class, () -> svc.updateStream(id, moved, RECEIVER), moved.toString());
        }
        Map<String, Object> nulled = new HashMap<>();
        nulled.put("min_verification_interval", null);
        assertThrows(IllegalArgumentException.class, () -> svc.updateStream(id, nulled, RECEIVER));
    }

    /** SSF §8.1.1.1: "If the request does not contain the delivery property, then the Transmitter MUST assume that the method is "urn:ietf:rfc:8936" (poll)." */
    @Test
    @Requirement("SSF §8.1.1.1")
    void aCreateWithNoDeliveryIsAPollStreamAtTheServletsPath() {
        Map<String, Object> created = service(config().build()).createStream(Map.of("events_requested",
                List.of(SsfEventTypes.CAEP_SESSION_REVOKED)), RECEIVER);
        assertEquals(Map.of("method", DeliveryMethod.POLL.urn(),
                "endpoint_url", "https://op.example.com" + SsfPaths.POLL + "?stream_id=" + created.get("stream_id")),
                created.get("delivery"));
    }

    // ─────────────────────────────── min_verification_interval ───────────────────────────────

    /**
     * SSF §8.1.1: "If an Event Receiver submits verification requests more frequently than this, the Event Transmitter
     * MAY respond with a 429 status code. An Event Transmitter SHOULD NOT respond with a 429 status code if an Event
     * Receiver is not exceeding this frequency."
     */
    @Test
    @Requirement({"SSF §8.1.1", "SSF §8.1.4.2"})
    void aVerificationInsideTheIntervalIsRefusedWithHowLongToWait() throws Exception {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(30).build());
        String id = (String) svc.createStream(pollBody(null), RECEIVER).get("stream_id");
        assertNotNull(svc.verify(id, "one", RECEIVER));

        clock.addAndGet(10_500);
        StreamManagementService.TooManyRequestsException e = assertThrows(StreamManagementService.TooManyRequestsException.class,
                () -> svc.verify(id, "two", RECEIVER));
        assertEquals(20, e.retryAfterSeconds(), "19.5 seconds left, rounded up");
        assertEquals(1, store.peek(id, 10).size(), "nothing minted for the refused request");

        clock.addAndGet(19_499);
        assertEquals(1, assertThrows(StreamManagementService.TooManyRequestsException.class,
                () -> svc.verify(id, "three", RECEIVER)).retryAfterSeconds(), "a millisecond left is still a second");

        clock.addAndGet(1);
        assertNotNull(svc.verify(id, "four", RECEIVER), "exactly the interval after the last accepted one: not exceeding it");
        assertEquals(2, store.peek(id, 10).size());
        assertThrows(StreamManagementService.TooManyRequestsException.class, () -> svc.verify(id, "five", RECEIVER),
                "the interval runs from the last accepted request, not the refused ones");
    }

    @Test
    void theIntervalIsPerStreamAndGoesWithTheStream() throws Exception {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(30).build());
        String a = (String) svc.createStream(pollBody(null), RECEIVER).get("stream_id");
        String b = (String) svc.createStream(pollBody(null), RECEIVER).get("stream_id");
        svc.verify(a, null, RECEIVER);
        assertNotNull(svc.verify(b, null, RECEIVER), "another stream has its own interval");
        svc.deleteStream(a, RECEIVER);
        assertThrows(StreamManagementService.NotFoundException.class, () -> svc.verify(a, null, RECEIVER));
    }

    @Test
    void aStreamWithNoIntervalIsNeverRefused() throws Exception {
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(0).build());
        String id = (String) svc.createStream(pollBody(null), RECEIVER).get("stream_id");
        for (int i = 0; i < 5; i++) {
            svc.verify(id, "s" + i, RECEIVER);
        }
        assertEquals(5, store.peek(id, 10).size());
    }

    /** The stream's own interval is the one held, not the transmitter's current setting. */
    @Test
    void theIntervalAStreamWasGivenIsTheOneItIsHeldTo() throws Exception {
        store.createStream(Stream.builder().id("given-5").audience("receiver-client").ownerClientId(RECEIVER.clientId())
                .deliveryMethod(DeliveryMethod.POLL).minVerificationInterval(5).build());
        StreamManagementService svc = service(config().minVerificationIntervalSeconds(3600).build());
        svc.verify("given-5", null, RECEIVER);
        clock.addAndGet(5_000);
        assertNotNull(svc.verify("given-5", null, RECEIVER));
    }

    // ─────────────────────────────── streams per receiver ───────────────────────────────

    @Test
    @Requirement("SSF §8.1.1.1")
    void aReceiverAtTheCapIsRefusedAnotherStreamAndOthersAreNot() {
        StreamManagementService svc = service(config().maxStreamsPerClient(2).build());
        store.createStream(Stream.builder().id("unowned").audience("x").deliveryMethod(DeliveryMethod.POLL).build());
        String first = (String) svc.createStream(pollBody(null), RECEIVER).get("stream_id");
        svc.createStream(pollBody(null), RECEIVER);

        StreamManagementService.StreamLimitException e = assertThrows(StreamManagementService.StreamLimitException.class,
                () -> svc.createStream(pollBody(null), RECEIVER));
        assertTrue(e.getMessage().contains("(2)"), e.getMessage());
        assertEquals(3, store.listStreams().size(), "nothing stored for the refused create");

        assertNotNull(svc.createStream(pollBody(null), OTHER).get("stream_id"), "the cap is per receiver");
        svc.deleteStream(first, RECEIVER);
        assertNotNull(svc.createStream(pollBody(null), RECEIVER).get("stream_id"), "a deleted stream makes room");
    }
}
