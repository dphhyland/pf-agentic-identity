/*
 * Push delivery: success acks, retryable backs off, dead-letter pauses the stream, permanent drops the SET;
 * and the same tick expires undelivered SETs, push or poll.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;

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

    // ─────────────────────────────── setTtlSeconds ───────────────────────────────

    private void pollStream(String id) {
        store.createStream(Stream.builder().id(id).audience("https://r").deliveryMethod(DeliveryMethod.POLL)
                .eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED)).status(StreamStatus.ENABLED).build());
    }

    private static PendingSet expiring(String jti, String streamId, long expiresAt) {
        return PendingSet.fresh(jti, streamId, "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-" + jti, 100, expiresAt);
    }

    private List<String> queued(String streamId) {
        return store.peek(streamId, 10).stream().map(PendingSet::jti).toList();
    }

    /**
     * Deliberately untagged. RFC 8936 §2 lets a transmitter do this - "Transmitters may also discard
     * undelivered SETs under deployment-specific conditions, such as if they have not been polled for over
     * too long a period of time" - and requires nothing. That the condition is {@code setTtlSeconds}, and
     * that it is enforced at all, is this transmitter's choice.
     *
     * <p>No push stream exists here. The loop that evicts is the push executor's, and a poll stream nobody
     * drains is exactly the queue that grows without bound if eviction waits for a push SET to come due.
     */
    @Test
    void aTickEvictsExpiredSetsFromAPollStreamWithNoPushStreamAnywhere() {
        pollStream("p1");
        store.enqueue(expiring("dead", "p1", 200));
        store.enqueue(expiring("dead-on-the-second", "p1", 300));
        store.enqueue(expiring("live", "p1", 301));
        store.enqueue(expiring("never-expires", "p1", 0));

        int delivered = svc((u, a, j) -> {
            throw new AssertionError("nothing here is a push SET");
        }).runOnce(300);

        assertEquals(0, delivered);
        assertEquals(List.of("live", "never-expires"), queued("p1"),
                "a SET one second short of its expiry stays, and so does one stamped with none (setTtlSeconds <= 0)");
    }

    /** Deliberately untagged, as above: RFC 8935 has no clause on how long an undelivered SET is kept. */
    @Test
    void anExpiredPushSetIsEvictedBeforeItIsReadForDelivery() {
        pushStream("s1", StreamStatus.ENABLED);
        store.enqueue(expiring("dead", "s1", 200));
        store.enqueue(expiring("live", "s1", 1000));
        List<String> posted = new ArrayList<>();

        int delivered = svc((u, a, j) -> {
            posted.add(j);
            return PushDeliveryService.DeliveryResult.retryable(503, "down");
        }).runOnce(300);

        assertEquals(0, delivered);
        assertEquals(List.of("jws-live"), posted, "the expired SET was due for push, and was never posted");
        assertEquals(List.of("live"), queued("s1"), "the unexpired SET is still queued for its retry");
    }

    /**
     * Deliberately untagged: the order is this transmitter's. Eviction is not caught, so a tick that cannot
     * evict stops before it reads the queue - the alternative is to deliver a SET the operator configured
     * the transmitter to have discarded, on exactly the ticks where the store is misbehaving.
     */
    @Test
    void aTickThatCannotEvictDeliversNothing() {
        SsfStore failing = mock(SsfStore.class);
        when(failing.evictExpired(300)).thenThrow(new IllegalStateException("connection refused"));
        PushDeliveryService.SetDeliveryClient client = mock(PushDeliveryService.SetDeliveryClient.class);

        assertThrows(IllegalStateException.class, () -> new PushDeliveryService(failing, cfg, client).runOnce(300));

        verify(failing, never()).dueForPush(anyLong(), anyInt());
        verifyNoInteractions(client);
    }

    /** The control for the test above: the same mocks, an eviction that succeeds, and the queue is read. */
    @Test
    void aTickThatEvictsGoesOnToReadTheQueue() {
        SsfStore working = mock(SsfStore.class);
        when(working.evictExpired(300)).thenReturn(2);

        assertEquals(0, new PushDeliveryService(working, cfg, (u, a, j) -> null).runOnce(300));

        InOrder order = inOrder(working);
        order.verify(working).evictExpired(300);
        order.verify(working).dueForPush(eq(300L), anyInt());
    }
}
