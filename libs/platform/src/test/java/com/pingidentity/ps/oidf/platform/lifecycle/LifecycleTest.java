/*
 * Shutdown closes everything once, last first, within a budget, whatever one close does.
 */
package com.pingidentity.ps.oidf.platform.lifecycle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle.Closed;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle.Outcome;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class LifecycleTest {

    private final List<String> closed = new CopyOnWriteArrayList<>();

    private AutoCloseable recording(String name) {
        return () -> this.closed.add(name);
    }

    /** A resource whose close waits until the test lets it go. */
    private static AutoCloseable blocking(CountDownLatch release, CountDownLatch done) {
        return () -> {
            release.await(30, TimeUnit.SECONDS);
            done.countDown();
        };
    }

    @Test
    void closesTheLastRegisteredFirst() {
        Lifecycle lifecycle = new Lifecycle();
        assertTrue(lifecycle.register("pool", recording("pool")));
        assertTrue(lifecycle.register("executor", recording("executor")));
        assertTrue(lifecycle.register("mbean", recording("mbean")));
        List<Closed> report = lifecycle.shutdown();
        assertEquals(List.of("mbean", "executor", "pool"), this.closed);
        assertEquals(List.of(new Closed("mbean", Outcome.CLOSED, ""), new Closed("executor", Outcome.CLOSED, ""),
                new Closed("pool", Outcome.CLOSED, "")), report);
        assertTrue(lifecycle.isShutDown());
    }

    @Test
    void shutdownRunsOnce() {
        Lifecycle lifecycle = new Lifecycle();
        lifecycle.register("pool", recording("pool"));
        assertFalse(lifecycle.isShutDown());
        assertEquals(1, lifecycle.shutdown(Duration.ofSeconds(5)).size());
        assertEquals(List.of(), lifecycle.shutdown(Duration.ofSeconds(5)));
        assertEquals(List.of(), lifecycle.shutdown());
        assertEquals(List.of("pool"), this.closed, "closed once");
    }

    /** A close that throws - an exception or an Error - is reported, and the others are closed all the same. */
    @Test
    void oneFailureDoesNotStopTheRest() {
        Lifecycle lifecycle = new Lifecycle();
        lifecycle.register("first", recording("first"));
        lifecycle.register("throws", () -> {
            throw new IllegalStateException("pool already closed");
        });
        lifecycle.register("errors", () -> {
            throw new NoClassDefFoundError("com/example/Gone");
        });
        lifecycle.register("last", recording("last"));
        List<Closed> report = lifecycle.shutdown();
        assertEquals(List.of("last", "first"), this.closed);
        assertEquals(Outcome.FAILED, report.get(1).outcome());
        assertEquals("java.lang.NoClassDefFoundError: com/example/Gone", report.get(1).detail());
        assertEquals(new Closed("throws", Outcome.FAILED, "java.lang.IllegalStateException: pool already closed"), report.get(2));
        assertEquals(Outcome.CLOSED, report.get(3).outcome());
    }

    /** A close that hangs is waited for only until the budget runs out; it finishes in the background. */
    @Test
    void theWaitIsBounded() throws Exception {
        Lifecycle lifecycle = new Lifecycle();
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(1);
        lifecycle.register("earlier", recording("earlier"));
        lifecycle.register("hangs", blocking(release, done));
        long start = System.nanoTime();
        List<Closed> report = lifecycle.shutdown(Duration.ofMillis(200));
        long tookMillis = (System.nanoTime() - start) / 1_000_000L;
        assertTrue(tookMillis < 5_000, "took " + tookMillis + " ms");
        assertEquals(new Closed("hangs", Outcome.TIMED_OUT, "still closing when the budget ran out"), report.get(0));
        assertEquals("earlier", report.get(1).name(), "the budget is spent, but the next close is still started");
        release.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS), "the hung close finishes in the background");
        for (int i = 0; i < 100 && !this.closed.contains("earlier"); i++) {
            Thread.sleep(50);
        }
        assertEquals(List.of("earlier"), this.closed);
    }

    /** With no budget left nothing is waited for: every close is started and reported as timed out if still running. */
    @Test
    void aSpentBudgetStartsClosesWithoutWaiting() throws Exception {
        Lifecycle lifecycle = new Lifecycle();
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(2);
        lifecycle.register("a", blocking(release, done));
        lifecycle.register("b", blocking(release, done));
        List<Closed> report = lifecycle.shutdown(Duration.ZERO);
        assertEquals(List.of(Outcome.TIMED_OUT, Outcome.TIMED_OUT), report.stream().map(Closed::outcome).toList());
        release.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
        assertEquals(List.of(), lifecycle.shutdown(Duration.ofSeconds(-1)), "a negative budget is no budget, and it has run");
    }

    /** An interrupted shutdown stops waiting, keeps the interrupt for its caller, and still starts every close. */
    @Test
    void anInterruptStopsTheWaitAndIsKept() throws Exception {
        Lifecycle lifecycle = new Lifecycle();
        CountDownLatch release = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(1);
        lifecycle.register("quick", recording("quick"));
        lifecycle.register("hangs", blocking(release, done));
        Thread.currentThread().interrupt();
        List<Closed> report;
        try {
            report = lifecycle.shutdown(Duration.ofSeconds(30));
        } finally {
            assertTrue(Thread.interrupted(), "the interrupt is kept");
        }
        assertEquals(Outcome.TIMED_OUT, report.get(0).outcome());
        assertEquals("quick", report.get(1).name());
        release.countDown();
        assertTrue(done.await(10, TimeUnit.SECONDS));
    }

    @Test
    void aResourceRegisteredAfterShutdownIsClosedAtOnce() {
        Lifecycle lifecycle = new Lifecycle();
        lifecycle.shutdown();
        assertFalse(lifecycle.register("late", recording("late")));
        assertEquals(List.of("late"), this.closed);
        assertEquals(List.of(), lifecycle.shutdown());
    }

    @Test
    void aResourceNeedsANameAndAResource() {
        Lifecycle lifecycle = new Lifecycle();
        assertThrows(NullPointerException.class, () -> lifecycle.register("x", null));
        assertThrows(IllegalArgumentException.class, () -> lifecycle.register(null, recording("x")));
        assertThrows(IllegalArgumentException.class, () -> lifecycle.register(" ", recording("x")));
        assertThrows(NullPointerException.class, () -> lifecycle.shutdown(null));
    }

    /** The webapp's copy is known only once its listener says so; until then, and in every other copy, it is unknown. */
    @Test
    void theLoaderRoleIsUnknownUntilTheListenerMarksIt() {
        Lifecycle lifecycle = new Lifecycle();
        assertEquals(Lifecycle.LoaderRole.UNKNOWN, lifecycle.loaderRole());
        assertFalse(lifecycle.isWebapp());
        lifecycle.markWebapp();
        lifecycle.markWebapp();
        assertEquals(Lifecycle.LoaderRole.WEBAPP, lifecycle.loaderRole());
        assertTrue(lifecycle.isWebapp());
    }

    @Test
    void currentIsOnePerLoader() {
        assertSame(Lifecycle.current(), Lifecycle.current());
        assertEquals(Duration.ofSeconds(10), Lifecycle.DEFAULT_BUDGET);
    }
}
