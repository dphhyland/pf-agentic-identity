/*
 * One named executor: its thread, its schedule, what a failing run does, and how it stops.
 */
package com.pingidentity.ps.oidf.platform.exec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ManagedExecutorTest {

    /** What the recorder saw: one line per run. */
    private final List<String> recorded = new CopyOnWriteArrayList<>();
    private final AtomicInteger closedCalls = new AtomicInteger();
    private ManagedExecutor executor = newExecutor("test-job");

    private ManagedExecutor newExecutor(String name) {
        return new ManagedExecutor(name, (n, nanos, failed) -> this.recorded.add(n + (failed ? " failed" : " ok")),
                this.closedCalls::incrementAndGet);
    }

    @AfterEach
    void tearDown() {
        this.executor.close(Duration.ofSeconds(5));
    }

    private static void await(CountDownLatch latch) throws InterruptedException {
        assertTrue(latch.await(10, TimeUnit.SECONDS), "timed out");
    }

    @Test
    void itsThreadIsANamedDaemon() throws Exception {
        AtomicReference<Thread> seen = new AtomicReference<>();
        CountDownLatch ran = new CountDownLatch(1);
        assertTrue(this.executor.execute(() -> {
            seen.set(Thread.currentThread());
            ran.countDown();
        }));
        await(ran);
        assertEquals("oidf-test-job-1", seen.get().getName());
        assertTrue(seen.get().isDaemon());
        assertEquals("oidf-test-job", this.executor.threadNamePrefix());
        assertEquals("test-job", this.executor.name());
    }

    @Test
    void everyRunsAgainAndAgainAndEachRunIsRecorded() throws Exception {
        CountDownLatch three = new CountDownLatch(3);
        assertTrue(this.executor.every(Duration.ZERO, Duration.ofMillis(5), three::countDown));
        await(three);
        this.executor.close();
        assertTrue(this.executor.runs() >= 3);
        assertEquals(0, this.executor.failures());
        assertTrue(this.recorded.size() >= 3);
        assertTrue(this.recorded.stream().allMatch("test-job ok"::equals), this.recorded.toString());
    }

    @Test
    void aRunThatThrowsIsAFailureAndTheScheduleCarriesOn() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountDownLatch fourth = new CountDownLatch(4);
        this.executor.every(Duration.ZERO, Duration.ofMillis(5), () -> {
            int call = calls.incrementAndGet();
            fourth.countDown();
            if (call == 1) {
                throw new IllegalStateException("first run fails");
            }
            if (call == 2) {
                throw new NoClassDefFoundError("an Error does not end it either");
            }
        });
        await(fourth);
        this.executor.close();
        assertEquals(2, this.executor.failures());
        assertEquals("test-job failed", this.recorded.get(0));
        assertEquals("test-job failed", this.recorded.get(1));
        assertEquals("test-job ok", this.recorded.get(2));
        ManagedExecutor.Status status = this.executor.status();
        assertEquals("test-job", status.name());
        assertTrue(status.closed());
        assertEquals(2, status.failures());
        assertEquals(this.executor.runs(), status.runs());
    }

    @Test
    void afterRunsOnceAfterItsDelay() throws Exception {
        CountDownLatch ran = new CountDownLatch(1);
        long start = System.nanoTime();
        assertTrue(this.executor.after(Duration.ofMillis(50), ran::countDown));
        await(ran);
        assertTrue(System.nanoTime() - start >= TimeUnit.MILLISECONDS.toNanos(50));
        this.executor.close();
        assertEquals(1, this.executor.runs());
    }

    @Test
    void aLoopInterruptedAtShutdownEndsItsRunCleanly() throws Exception {
        CountDownLatch looping = new CountDownLatch(1);
        AtomicBoolean ended = new AtomicBoolean();
        this.executor.execute(() -> {
            looping.countDown();
            try {
                while (true) {
                    Thread.sleep(10_000);
                }
            } catch (InterruptedException e) {
                ended.set(true);
                Thread.currentThread().interrupt();
            }
        });
        await(looping);
        assertTrue(this.executor.close(Duration.ofSeconds(5)), "the thread ended within the wait");
        assertTrue(ended.get());
        assertEquals(List.of("test-job ok"), this.recorded, "a clean end, not a failure");
        assertEquals(1, this.closedCalls.get());
        assertTrue(this.executor.isClosed());
    }

    @Test
    void aRunThatThrowsBecauseItWasInterruptedByCloseIsNotAFailure() throws Exception {
        CountDownLatch running = new CountDownLatch(1);
        this.executor.execute(() -> {
            running.countDown();
            try {
                Thread.sleep(10_000);
            } catch (InterruptedException e) {
                throw new IllegalStateException("interrupted", e);
            }
        });
        await(running);
        assertTrue(this.executor.close(Duration.ofSeconds(5)));
        assertEquals(0, this.executor.failures());
        assertEquals(List.of("test-job ok"), this.recorded);
    }

    @Test
    void closeWaitsOnlyAsLongAsItWasToldForARunThatIgnoresTheInterrupt() throws Exception {
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        this.executor.execute(() -> {
            running.countDown();
            while (release.getCount() > 0) {
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    // carries on regardless
                }
            }
        });
        await(running);
        assertFalse(this.executor.close(Duration.ofMillis(50)), "still running when the wait ran out");
        assertEquals(1, this.closedCalls.get(), "the name is given back all the same");
        assertTrue(this.executor.close(Duration.ofMillis(50)), "a second close does nothing");
        assertEquals(1, this.closedCalls.get());
        release.countDown();
    }

    @Test
    void closeFromAnInterruptedThreadKeepsTheInterrupt() throws Exception {
        CountDownLatch running = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        this.executor.execute(() -> {
            running.countDown();
            while (release.getCount() > 0) {
                try {
                    release.await(10, TimeUnit.SECONDS);
                } catch (InterruptedException ignored) {
                    // carries on regardless
                }
            }
        });
        await(running);
        Thread.currentThread().interrupt();
        try {
            assertFalse(this.executor.close(Duration.ofSeconds(5)), "an interrupted wait answers at once");
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
            release.countDown();
        }
    }

    @Test
    void aClosedExecutorSchedulesNothing() {
        this.executor.close();
        assertFalse(this.executor.after(Duration.ZERO, () -> { }));
        assertFalse(this.executor.every(Duration.ZERO, Duration.ofSeconds(1), () -> { }));
        assertFalse(this.executor.execute(() -> { }));
    }

    @Test
    void theHookRunsOnceAtCloseAndAtOnceWhenAlreadyClosed() {
        AtomicInteger first = new AtomicInteger();
        AtomicInteger second = new AtomicInteger();
        this.executor.whenClosed(first::incrementAndGet);
        this.executor.whenClosed(second::incrementAndGet);
        this.executor.close();
        this.executor.close();
        assertEquals(0, first.get(), "replaced before the close");
        assertEquals(1, second.get());
        AtomicInteger late = new AtomicInteger();
        this.executor.whenClosed(late::incrementAndGet);
        assertEquals(1, late.get());
    }

    @Test
    void anUncaughtThrowFromTheMachineryIsCounted() {
        this.executor.uncaught(Thread.currentThread(), new IllegalStateException("from the pool"));
        assertEquals(1, this.executor.failures());
    }

    @Test
    void durationsAreChecked() {
        assertThrows(IllegalArgumentException.class, () -> this.executor.after(Duration.ofSeconds(-1), () -> { }));
        assertThrows(IllegalArgumentException.class, () -> this.executor.every(Duration.ZERO, Duration.ZERO, () -> { }));
        assertThrows(NullPointerException.class, () -> this.executor.every(null, Duration.ofSeconds(1), () -> { }));
        assertThrows(NullPointerException.class, () -> this.executor.after(Duration.ZERO, null));
        assertThrows(NullPointerException.class, () -> this.executor.whenClosed(null));
        assertEquals(Long.MAX_VALUE, ManagedExecutor.nonNegativeNanos(Duration.ofSeconds(Long.MAX_VALUE), "x"),
                "too long for nanoseconds is as long as can be");
        assertEquals(0, ManagedExecutor.nonNegativeNanos(Duration.ZERO, "x"));
        assertEquals(1_000, ManagedExecutor.positiveNanos(Duration.ofNanos(1_000), "x"));
    }
}
