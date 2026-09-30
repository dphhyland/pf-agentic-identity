/*
 * H-SSF-2: the poll endpoint caps maxEvents, records setErrs, and respects the stream's status.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.signals.SetMinter;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PollDeliveryTest {

    private static final AuthContext RECEIVER = AuthContext.active("receiver-client", Set.of("ssf.manage"));

    private final List<Event> events = new CopyOnWriteArrayList<>();
    private InMemorySsfStore store;
    private StreamManagementService svc;
    private String id;

    private void service(SsfConfiguration.Builder b) {
        store = new InMemorySsfStore();
        svc = new StreamManagementService(store, new SetMinter("RS256", new TestSigningKeyProvider("k")), b.build(),
                SetPublisher.NOOP, OutboundUrlPolicy.from(Map.<String, String>of()::get));
        id = (String) svc.createStream(Map.of("delivery", Map.of("method", DeliveryMethod.POLL.urn()),
                "events_requested", List.of(SsfEventTypes.CAEP_SESSION_REVOKED)), RECEIVER).get("stream_id");
    }

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(events::add);
        service(new SsfConfiguration.Builder().issuer("https://op.example.com"));
    }

    @AfterEach
    void release() {
        Events.reset();
    }

    private void enqueue(int n) {
        long now = SetMinter.nowSeconds();
        for (int i = 0; i < n; i++) {
            store.enqueue(PendingSet.fresh(String.format("j-%03d", i), id, null, SsfEventTypes.CAEP_SESSION_REVOKED, "jws-" + i,
                    now, 0));
        }
    }

    private StreamManagementService.Polled poll(Integer maxEvents, List<String> acks, Map<String, Map<String, Object>> errs) {
        return svc.poll(id, new StreamManagementService.PollRequest(acks, errs, maxEvents, false), RECEIVER);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> sets(StreamManagementService.Polled polled) {
        return (Map<String, Object>) polled.body().get("sets");
    }

    /** RFC 8936 §2.2: the transmitter "SHOULD NOT send more SETs than the specified maximum"; more are signalled. */
    @Test
    @Requirement("RFC8936 §2.2")
    void maxEventsIsCappedAndTheRestAreMoreAvailable() {
        service(new SsfConfiguration.Builder().issuer("https://op.example.com").pollMaxEventsCap(5).pollMaxEvents(3));
        enqueue(8);
        StreamManagementService.Polled asked = poll(1000, null, null);
        assertEquals(5, sets(asked).size(), "capped at OIDF_SSF_POLL_MAX_EVENTS_CAP");
        assertEquals(true, asked.body().get("moreAvailable"));
        assertEquals(Duration.ZERO, asked.hold(), "SETs were returned: nothing to wait for");
        assertEquals(3, sets(poll(null, null, null)).size(), "none asked for: OIDF_SSF_POLL_MAX_EVENTS");
        assertEquals(2, sets(poll(2, null, null)).size(), "fewer than the cap: as asked");
        assertEquals(3, sets(poll(-1, null, null)).size(), "negative: as none asked for");
    }

    @Test
    void aZeroOrNegativeDefaultIsAHundredUnderTheCap() {
        service(new SsfConfiguration.Builder().issuer("https://op.example.com").pollMaxEvents(0).pollMaxEventsCap(1000));
        enqueue(120);
        assertEquals(100, sets(poll(null, null, null)).size());
    }

    /** RFC 8936 §2.2: maxEvents 0 is acknowledge-only; nothing is returned and nothing is waited for. */
    @Test
    @Requirement("RFC8936 §2.2")
    void anAcknowledgeOnlyPollIsNeverHeld() {
        StreamManagementService.Polled polled = poll(0, List.of(), Map.of());
        assertTrue(sets(polled).isEmpty());
        assertEquals(Duration.ZERO, polled.hold());
    }

    @Test
    void anEmptyPollOfAnEnabledStreamMayBeHeldForTheConfiguredWait() {
        assertEquals(Duration.ofSeconds(10), poll(null, null, null).hold(), "the default wait");
        service(new SsfConfiguration.Builder().issuer("https://op.example.com").pollLongPollWaitSeconds(0));
        assertEquals(Duration.ZERO, poll(null, null, null).hold(), "0 answers at once");
    }

    /** RFC 8936 §2.2 setErrs: recorded per SET, counted under its error code, and released. */
    @Test
    @Requirement("RFC8936 §2.2")
    void setErrsAreRecordedCountedAndReleased() {
        enqueue(4);
        Map<String, Map<String, Object>> errs = new LinkedHashMap<>();
        errs.put("j-000", Map.of("err", "invalid_key", "description", "Key ID 12345 has been revoked.\nforged line"));
        errs.put("j-001", Map.of("err", "made_up"));
        errs.put("j-002", Map.of("description", 7));
        StreamManagementService.Polled polled = poll(10, List.of("j-003"), errs);
        assertTrue(sets(polled).isEmpty(), "every SET acknowledged or reported: none left");
        List<String> reasons = new ArrayList<>();
        for (Event e : events) {
            if (StreamManagementService.SET_ERROR.equals(e.code())) {
                assertTrue(e.isFailure());
                reasons.add(e.reason());
            }
        }
        assertEquals(List.of("invalid_key", "other", "other"), reasons);
    }

    /**
     * SSF 1.0 §8.1.2.1: paused - "The Transmitter MUST NOT transmit events over the stream" and SHOULD hold them;
     * disabled - it MUST NOT transmit them either. The poll acknowledges and returns nothing; the held SETs return when
     * the stream is enabled again.
     */
    @Test
    @Requirement("SSF §8.1.2.1")
    void aPausedOrDisabledStreamReturnsNothingButStillAcknowledges() {
        enqueue(3);
        for (String status : List.of("paused", "disabled")) {
            svc.setStatus(id, status, null, RECEIVER);
            StreamManagementService.Polled polled = poll(10, List.of("j-000"), null);
            assertTrue(sets(polled).isEmpty(), status);
            assertEquals(false, polled.body().get("moreAvailable"), status);
            assertEquals(Duration.ZERO, polled.hold(), status + ": never held");
        }
        svc.setStatus(id, "enabled", null, RECEIVER);
        assertEquals(List.of("j-001", "j-002"), new ArrayList<>(sets(poll(10, null, null)).keySet()), "j-000 was acknowledged");
    }

    @Test
    void aStreamHasPendingWhileASetIsQueuedAndAnExpiredOneIsEvictedByThePollItTriggers() {
        assertFalse(svc.hasPending(id));
        long now = SetMinter.nowSeconds();
        store.enqueue(PendingSet.fresh("old", id, null, SsfEventTypes.CAEP_SESSION_REVOKED, "jws", now - 10, now - 1));
        assertTrue(svc.hasPending(id));
        StreamManagementService.Polled polled = poll(10, null, null);
        assertTrue(sets(polled).isEmpty());
        assertEquals(Duration.ofSeconds(10), polled.hold(), "still worth waiting for");
        assertFalse(svc.hasPending(id), "evicted");
    }

    @Test
    void theOldOverloadIsAPollWithNoSetErrs() {
        enqueue(2);
        assertEquals(2, ((Map<?, ?>) svc.poll(id, List.of(), 10, true, RECEIVER).get("sets")).size());
    }
}
