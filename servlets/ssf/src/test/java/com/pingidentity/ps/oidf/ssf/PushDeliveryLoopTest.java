/*
 * The push loop on its managed executor: its thread, its tick, a tick that throws, one loop in the JVM, and a stop
 * that ends a delivery in flight.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class PushDeliveryLoopTest {

    private final SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com")
            .pushRetryMaxAttempts(2).pushRetryBackoffSeconds(1).build();

    @AfterEach
    void tearDown() {
        ManagedExecutors.live(PushDeliveryService.EXECUTOR_NAME).ifPresent(ManagedExecutor::close);
    }

    private static ManagedExecutor loop() {
        return ManagedExecutors.live(PushDeliveryService.EXECUTOR_NAME).orElseThrow();
    }

    private static void awaitRuns(ManagedExecutor executor, long runs) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
        while (executor.runs() < runs) {
            assertTrue(System.nanoTime() < deadline, "timed out waiting for " + runs + " tick(s)");
            Thread.sleep(20);
        }
    }

    @Test
    void aTickThatThrowsIsLoggedAndTheNextTickRuns() throws Exception {
        SsfStore store = mock(SsfStore.class);
        when(store.evictExpired(anyLong())).thenThrow(new IllegalStateException("store down")).thenReturn(0);
        when(store.dueForPush(anyLong(), anyInt())).thenReturn(List.of());
        PushDeliveryService service = new PushDeliveryService(store, this.cfg, (u, a, j) -> PushDeliveryService.DeliveryResult.delivered());
        service.start();
        try {
            ManagedExecutor executor = loop();
            assertEquals("oidf-ssf-push-delivery", executor.threadNamePrefix());
            assertEquals(0, executor.runs(), "the first tick is one tick away");
            awaitRuns(executor, 2);
            assertEquals(0, executor.failures(), "the loop's own catch logs the failed tick");
        } finally {
            service.stop();
        }
    }

    @Test
    void oneLoopRunsInTheJvm() {
        PushDeliveryService first = new PushDeliveryService(new InMemorySsfStore(), this.cfg, (u, a, j) -> null);
        PushDeliveryService second = new PushDeliveryService(new InMemorySsfStore(), this.cfg, (u, a, j) -> null);
        first.start();
        try {
            second.start();
            assertTrue(first.isRunning());
            assertFalse(second.isRunning(), "another loop runs in this JVM: this one starts nothing");
        } finally {
            first.stop();
        }
        second.start();
        assertTrue(second.isRunning(), "and starts once the first has stopped");
        second.stop();
        assertEquals(Optional.empty(), ManagedExecutors.live(PushDeliveryService.EXECUTOR_NAME));
    }

    @Test
    void stopInterruptsADeliveryInFlightAndTheTickEndsCleanly() throws Exception {
        InMemorySsfStore store = new InMemorySsfStore();
        store.createStream(Stream.builder().id("s1").audience("https://r").deliveryMethod(DeliveryMethod.PUSH)
                .pushEndpointUrl("https://r/set").eventsRequested(List.of(SsfEventTypes.CAEP_SESSION_REVOKED))
                .status(StreamStatus.ENABLED).build());
        store.enqueue(PendingSet.fresh("j1", "s1", "k", SsfEventTypes.CAEP_SESSION_REVOKED, "jws", SetMinter.nowSeconds(), 0));
        CountDownLatch delivering = new CountDownLatch(1);
        AtomicBoolean interrupted = new AtomicBoolean();
        PushDeliveryService service = new PushDeliveryService(store, this.cfg, (u, a, j) -> {
            delivering.countDown();
            try {
                Thread.sleep(30_000);
            } catch (InterruptedException e) {
                interrupted.set(true);
                Thread.currentThread().interrupt();
            }
            return PushDeliveryService.DeliveryResult.retryable(0, "interrupted");
        });
        service.start();
        ManagedExecutor executor = loop();
        assertTrue(delivering.await(20, TimeUnit.SECONDS));
        long started = System.nanoTime();
        service.stop();
        assertTrue(TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - started) < 5, "not the 30 s the receiver would take");
        assertTrue(interrupted.get());
        assertTrue(executor.isClosed());
        assertEquals(0, executor.failures());
    }
}
