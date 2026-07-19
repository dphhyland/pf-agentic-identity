/*
 * Push delivery: success acks, retryable backs off, dead-letter pauses the stream, permanent drops the SET.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PushDeliveryServiceTest {

    private InMemorySsfStore store;
    private SsfConfiguration cfg;

    @BeforeEach
    void setUp() {
        store = new InMemorySsfStore();
        cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .pushRetryMaxAttempts(2).pushRetryBackoffSeconds(5).build();
    }

    private void pushStream(String id, StreamStatus status) {
        store.createStream(Stream.builder().id(id).audience("https://r").deliveryMethod(DeliveryMethod.PUSH)
                .pushEndpointUrl("https://r/set").eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .status(status).build());
    }

    private PushDeliveryService svc(PushDeliveryService.SetDeliveryClient client) {
        return new PushDeliveryService(store, cfg, client);
    }

    @Test
    void successfulDeliveryAcksTheSet() {
        pushStream("s1", StreamStatus.ENABLED);
        store.enqueue(PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0));
        int delivered = svc((u, a, j) -> PushDeliveryService.DeliveryResult.delivered()).runOnce(100);
        assertEquals(1, delivered);
        assertEquals(0, store.peek("s1", 10).size(), "delivered SET is removed");
    }

    @Test
    void retryableFailureRecordsAttemptAndBacksOff() {
        pushStream("s1", StreamStatus.ENABLED);
        store.enqueue(PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0));
        int delivered = svc((u, a, j) -> PushDeliveryService.DeliveryResult.retryable(503, "down")).runOnce(100);
        assertEquals(0, delivered);
        PendingSet after = store.peek("s1", 1).get(0);
        assertEquals(1, after.deliveryAttempts());
        assertEquals(105, after.nextAttemptAt(), "next attempt = now + base backoff (5s)");
        assertEquals(StreamStatus.ENABLED, store.getStream("s1").orElseThrow().status(), "not yet paused");
    }

    @Test
    void deadLetterPausesStreamAtMaxAttempts() {
        pushStream("s1", StreamStatus.ENABLED);
        // SET already failed once (attempts=1); max is 2, so this attempt trips the dead-letter
        store.enqueue(new PendingSet("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0, 1, 100));
        svc((u, a, j) -> PushDeliveryService.DeliveryResult.retryable(503, "down")).runOnce(100);
        Stream s = store.getStream("s1").orElseThrow();
        assertEquals(StreamStatus.PAUSED, s.status());
        assertTrue(s.statusReason().contains("dead-letter"), "records the dead-letter reason");
    }

    @Test
    void permanentFailureDropsSetWithoutPausing() {
        pushStream("s1", StreamStatus.ENABLED);
        store.enqueue(PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0));
        svc((u, a, j) -> PushDeliveryService.DeliveryResult.permanent(400, "bad SET")).runOnce(100);
        assertEquals(0, store.peek("s1", 10).size(), "permanent-failure SET is dropped");
        assertEquals(StreamStatus.ENABLED, store.getStream("s1").orElseThrow().status(), "stream stays enabled");
    }

    @Test
    void pausedStreamIsNotDelivered() {
        pushStream("s1", StreamStatus.PAUSED);
        store.enqueue(PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0));
        int delivered = svc((u, a, j) -> {
            throw new AssertionError("must not attempt delivery on a paused stream");
        }).runOnce(100);
        assertEquals(0, delivered);
        assertEquals(1, store.peek("s1", 10).size(), "SET is retained while paused");
    }
}
