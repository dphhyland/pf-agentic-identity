/*
 * Push delivery: success acks, retryable backs off, dead-letter pauses the stream, permanent drops the SET;
 * and the same tick expires undelivered SETs, push or poll.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

    // ─────────────────────────────── one stream cannot starve another (B5) ───────────────────────────────

    private void enqueueMany(String streamId, int count, long firstIssuedAt) {
        for (int i = 0; i < count; i++) {
            store.enqueue(PendingSet.fresh(streamId + "-" + i, streamId, "k", SsfEventTypes.CAEP_SESSION_REVOKED,
                    "jws-" + streamId + "-" + i, firstIssuedAt + i, 0));
        }
    }

    /**
     * SSF 1.0 §8.1.2.1, on a paused stream: "The Transmitter MUST NOT transmit events over the stream. The
     * Transmitter SHOULD hold any events it would have transmitted while paused"; and on an enabled one:
     * "The Transmitter MUST transmit events over the stream, according to the stream's configured delivery
     * method". Both at once: the paused stream's held SETs are older than the enabled stream's and outnumber
     * the batch (500), so before the store selected by stream state they were the whole batch, every tick,
     * and the enabled stream was never read.
     */
    @Test
    @Requirement("SSF §8.1.2.1")
    void aPausedStreamsBacklogDoesNotKeepAnEnabledStreamFromDelivering() {
        pushStream("paused", StreamStatus.PAUSED);
        pushStream("live", StreamStatus.ENABLED);
        enqueueMany("paused", 600, 100);
        store.enqueue(PendingSet.fresh("j-live", "live", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-live", 900, 0));
        List<String> posted = new ArrayList<>();

        int delivered = svc((u, a, j) -> {
            posted.add(j);
            return PushDeliveryService.DeliveryResult.delivered();
        }).runOnce(1000);

        assertEquals(1, delivered);
        assertEquals(List.of("jws-live"), posted, "the paused stream's 600 held SETs were not in the batch");
        assertEquals(600, store.peek("paused", 1000).size(), "held, as §8.1.2.1 says, for when the stream is enabled");
    }

    /** §8.1.2.1 on a disabled stream: "The Transmitter MUST NOT transmit events over the stream". */
    @Test
    @Requirement("SSF §8.1.2.1")
    void aDisabledStreamsBacklogDoesNotKeepAnEnabledStreamFromDelivering() {
        pushStream("disabled", StreamStatus.DISABLED);
        pushStream("live", StreamStatus.ENABLED);
        enqueueMany("disabled", 600, 100);
        store.enqueue(PendingSet.fresh("j-live", "live", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-live", 900, 0));

        int delivered = svc((u, a, j) -> "jws-live".equals(j)
                ? PushDeliveryService.DeliveryResult.delivered()
                : PushDeliveryService.DeliveryResult.permanent(0, "must not be attempted")).runOnce(1000);

        assertEquals(1, delivered);
        assertEquals(600, store.peek("disabled", 1000).size());
    }

    /**
     * Deliberately untagged: RFC 8935 says nothing about how a transmitter shares one loop between streams.
     * A receiver that is down costs one attempt, not one per queued SET, and the stream after it in the
     * batch is still delivered to in the same tick.
     */
    @Test
    void aStreamThatFailsGetsNoSecondAttemptInTheSameTick() {
        pushStream("down", StreamStatus.ENABLED);
        pushStream("up", StreamStatus.ENABLED);
        enqueueMany("down", 3, 100);
        store.enqueue(PendingSet.fresh("j-up", "up", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-up", 500, 0));
        List<String> posted = new ArrayList<>();

        int delivered = svc((u, a, j) -> {
            posted.add(j);
            return j.startsWith("jws-down") ? PushDeliveryService.DeliveryResult.retryable(503, "down")
                    : PushDeliveryService.DeliveryResult.delivered();
        }).runOnce(1000);

        assertEquals(1, delivered);
        assertEquals(List.of("jws-down-0", "jws-up"), posted, "one attempt on the failing stream, then the next stream");
        List<PendingSet> down = store.peek("down", 10);
        assertEquals(3, down.size(), "nothing of the failing stream's is lost");
        assertEquals(1, down.get(0).deliveryAttempts(), "the SET that was tried is the one that counts an attempt");
        assertEquals(0, down.get(1).deliveryAttempts());
        assertEquals(0, down.get(2).deliveryAttempts());
        assertEquals(StreamStatus.ENABLED, store.getStream("down").orElseThrow().status());
    }

    /**
     * Deliberately untagged, as above. The failed SET waits out its backoff and the stream waits with it: in
     * the ticks before it is due again nothing of the stream is posted, although its later SETs are due,
     * because posting them would put them in front of the one that failed. When the receiver is back the
     * failed SET goes first and the rest follow in the order they were issued.
     */
    @Test
    void aFailedStreamWaitsOutItsOldestSetsBackoffAndThenDeliversInOrder() {
        pushStream("s1", StreamStatus.ENABLED);
        enqueueMany("s1", 3, 100);
        List<String> posted = new ArrayList<>();
        boolean[] receiverUp = {false};
        PushDeliveryService service = svc((u, a, j) -> {
            posted.add(j);
            return receiverUp[0] ? PushDeliveryService.DeliveryResult.delivered()
                    : PushDeliveryService.DeliveryResult.retryable(503, "down");
        });

        assertEquals(0, service.runOnce(1000));
        assertEquals(List.of("jws-s1-0"), posted);
        assertEquals(1005, store.peek("s1", 1).get(0).nextAttemptAt(), "the failed SET backs off 5 s");

        receiverUp[0] = true;
        assertEquals(0, service.runOnce(1004), "s1-1 and s1-2 are due, and wait behind s1-0");
        assertEquals(List.of("jws-s1-0"), posted, "nothing was posted while the oldest SET was backing off");

        assertEquals(3, service.runOnce(1005));
        assertEquals(List.of("jws-s1-0", "jws-s1-0", "jws-s1-1", "jws-s1-2"), posted, "oldest first, the retried SET leading");
        assertTrue(store.peek("s1", 10).isEmpty());
    }

    /** A SET issued to the stream while it waits queues behind the one that failed, not in front of it. */
    @Test
    void aSetIssuedDuringTheBackoffQueuesBehindTheOneThatFailed() {
        pushStream("s1", StreamStatus.ENABLED);
        store.enqueue(PendingSet.fresh("old", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-old", 100, 0));
        List<String> posted = new ArrayList<>();
        boolean[] receiverUp = {false};
        PushDeliveryService service = svc((u, a, j) -> {
            posted.add(j);
            return receiverUp[0] ? PushDeliveryService.DeliveryResult.delivered()
                    : PushDeliveryService.DeliveryResult.retryable(0, "connect timed out");
        });

        service.runOnce(1000);
        store.enqueue(PendingSet.fresh("new", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-new", 1002, 0));
        receiverUp[0] = true;
        service.runOnce(1003);
        service.runOnce(1005);

        assertEquals(List.of("jws-old", "jws-old", "jws-new"), posted);
    }

    /**
     * Deliberately untagged: this asserts the divergence F-0095 records, and a divergence is never tagged with
     * the clause it departs from. SSF 1.0 §8.1.2.1 has a transmitter that holds successive events for one
     * Subject Principal transmit them "in the order of time that they were generated"; {@code issuedAt} is in
     * seconds, so a burst - a logout, a deprovision - goes in {@code jti} order within its second. What the
     * loop does keep for a burst: the SET that failed is the one retried, the stream waits behind it, and it
     * goes first. Generated b, c, a in one second; tried a, and a again; then a, b, c.
     */
    @Test
    void aBurstIssuedInOneSecondIsRetriedFromOneSetAndDeliveredInJtiOrder() {
        pushStream("s1", StreamStatus.ENABLED);
        for (String jti : List.of("b", "c", "a")) {
            store.enqueue(PendingSet.fresh(jti, "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-" + jti, 100, 0));
        }
        cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
                .pushRetryMaxAttempts(5).pushRetryBackoffSeconds(5).build();
        List<String> posted = new ArrayList<>();
        boolean[] receiverUp = {false};
        PushDeliveryService service = svc((u, a, j) -> {
            posted.add(j);
            return receiverUp[0] ? PushDeliveryService.DeliveryResult.delivered()
                    : PushDeliveryService.DeliveryResult.retryable(503, "down");
        });

        assertEquals(0, service.runOnce(1000));
        assertEquals(0, service.runOnce(1005));
        assertEquals(List.of("jws-a", "jws-a"), posted, "the SET that failed is the one retried");
        assertEquals(List.of(2, 0, 0), store.peek("s1", 10).stream().map(PendingSet::deliveryAttempts).toList());

        receiverUp[0] = true;
        assertEquals(0, service.runOnce(1010), "b and c are due, and wait behind a");
        assertEquals(3, service.runOnce(1015));
        assertEquals(List.of("jws-a", "jws-a", "jws-a", "jws-b", "jws-c"), posted);
    }

    /**
     * The oldest SET is read after the batch, so it can be gone by then - delivered by another node, or
     * acknowledged by a poll. A stream with nothing older queued is not held.
     */
    @Test
    void aStreamWhoseOldestSetHasGoneSinceTheBatchWasReadIsNotHeld() {
        SsfStore racing = mock(SsfStore.class);
        PendingSet p = PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0);
        when(racing.dueForPush(300, 500)).thenReturn(List.of(p));
        when(racing.getStream("s1")).thenReturn(Optional.of(Stream.builder().id("s1").audience("https://r")
                .deliveryMethod(DeliveryMethod.PUSH).pushEndpointUrl("https://r/set")
                .status(StreamStatus.ENABLED).build()));
        when(racing.peek("s1", 1)).thenReturn(List.of());

        assertEquals(1, new PushDeliveryService(racing, cfg,
                (u, a, j) -> PushDeliveryService.DeliveryResult.delivered()).runOnce(300));

        verify(racing).ack("s1", List.of("j1"));
    }

    /**
     * A tick whose thread is interrupted - {@code stop()}, which shuts the scheduler down - posts nothing after
     * the attempt that was in flight, so a stopped loop does not go on to count failures against every other
     * stream in the batch.
     */
    @Test
    void anInterruptedTickPostsNothingMore() {
        pushStream("a", StreamStatus.ENABLED);
        pushStream("b", StreamStatus.ENABLED);
        store.enqueue(PendingSet.fresh("j-a", "a", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-a", 100, 0));
        store.enqueue(PendingSet.fresh("j-b", "b", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws-b", 200, 0));
        List<String> posted = new ArrayList<>();
        try {
            svc((u, a, j) -> {
                posted.add(j);
                Thread.currentThread().interrupt(); // as send() leaves it when the wait is interrupted
                return PushDeliveryService.DeliveryResult.retryable(0, "interrupted");
            }).runOnce(1000);
        } finally {
            assertTrue(Thread.interrupted(), "the interrupt is left for the scheduler to see");
        }

        assertEquals(List.of("jws-a"), posted);
        assertEquals(0, store.peek("b", 1).get(0).deliveryAttempts(), "b was not tried, and not counted");
    }

    /**
     * The store selects by the stream's state, and the executor reads the stream again before it posts: a
     * stream paused between the two (a receiver's status update, another node's dead-letter) is not posted
     * to, and its SET is held.
     */
    @Test
    @Requirement("SSF §8.1.2.1")
    void aStreamPausedAfterItsSetWasSelectedIsNotDeliveredTo() {
        SsfStore racing = mock(SsfStore.class);
        PendingSet p = PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0);
        when(racing.dueForPush(300, 500)).thenReturn(List.of(p));
        when(racing.getStream("s1")).thenReturn(Optional.of(Stream.builder().id("s1").audience("https://r")
                .deliveryMethod(DeliveryMethod.PUSH).pushEndpointUrl("https://r/set")
                .status(StreamStatus.PAUSED).build()));
        PushDeliveryService.SetDeliveryClient client = mock(PushDeliveryService.SetDeliveryClient.class);

        assertEquals(0, new PushDeliveryService(racing, cfg, client).runOnce(300));

        verifyNoInteractions(client);
        verify(racing, never()).ack(eq("s1"), org.mockito.ArgumentMatchers.any());
        verify(racing, never()).recordAttempt(org.mockito.ArgumentMatchers.any(), anyLong());
    }

    /** A SET whose stream has been deleted from under it is acknowledged away, not posted and not retried. */
    @Test
    void aSetWhoseStreamIsGoneIsDropped() {
        SsfStore orphaning = mock(SsfStore.class);
        PendingSet p = PendingSet.fresh("j1", "gone", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", 100, 0);
        when(orphaning.dueForPush(300, 500)).thenReturn(List.of(p));
        when(orphaning.getStream("gone")).thenReturn(Optional.empty());
        PushDeliveryService.SetDeliveryClient client = mock(PushDeliveryService.SetDeliveryClient.class);

        assertEquals(0, new PushDeliveryService(orphaning, cfg, client).runOnce(300));

        verify(orphaning).ack("gone", List.of("j1"));
        verifyNoInteractions(client);
    }

    @Test
    void startIsIdempotentAndStopEndsIt() {
        PushDeliveryService service = svc((u, a, j) -> PushDeliveryService.DeliveryResult.delivered());
        assertFalse(service.isRunning());
        service.start();
        service.start();
        assertTrue(service.isRunning());
        service.stop();
        assertFalse(service.isRunning());
    }
}
