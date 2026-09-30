/*
 * The supervisor retries with backoff and full jitter, stops when told to, and starts no thread outside the webapp's copy.
 */
package com.pingidentity.ps.oidf.platform.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeFalse;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class SupervisorTest {

    /** A scheduler that runs nothing by itself: the test runs each scheduled task, and reads the waits asked for. */
    private static final class Hand implements Supervisor.Scheduler {
        final List<Duration> waits = new ArrayList<>();
        final Deque<Runnable> due = new ArrayDeque<>();
        boolean allowed = true;

        @Override
        public boolean schedule(Duration delay, Runnable task) {
            if (!this.allowed) {
                return false;
            }
            this.waits.add(delay);
            this.due.add(task);
            return true;
        }

        void runNext() {
            this.due.removeFirst().run();
        }
    }

    private final Hand scheduler = new Hand();
    private final List<String> counted = new ArrayList<>();

    private Supervisor supervisor(double random) {
        return new Supervisor(this.scheduler, () -> random, this.counted::add);
    }

    @Test
    void theCeilingStartsAtFiveSecondsAndDoublesToFiveMinutes() {
        long[] expected = {5, 10, 20, 40, 80, 160, 300, 300};
        for (int failures = 0; failures < expected.length; failures++) {
            assertEquals(Duration.ofSeconds(expected[failures]), Supervisor.ceiling(failures), "after " + failures + " failures");
        }
        assertEquals(Duration.ofSeconds(300), Supervisor.ceiling(Integer.MAX_VALUE));
        assertEquals(Duration.ofSeconds(5), Supervisor.ceiling(-3), "a negative count is no failures yet");
    }

    @Test
    void eachWaitIsUniformBetweenZeroAndItsCeiling() {
        for (int failures = 0; failures < 10; failures++) {
            Duration ceiling = Supervisor.ceiling(failures);
            assertEquals(Duration.ZERO, Supervisor.backoff(failures, 0.0));
            assertEquals(ceiling.dividedBy(2), Supervisor.backoff(failures, 0.5));
            Duration nearTop = Supervisor.backoff(failures, Math.nextDown(1.0));
            assertTrue(nearTop.compareTo(ceiling) < 0 && nearTop.compareTo(ceiling.minusMillis(1)) >= 0, nearTop + " against " + ceiling);
        }
        // A random value outside [0, 1) is clamped, never a wait past the ceiling or below zero.
        assertEquals(Duration.ofSeconds(5), Supervisor.backoff(0, 7.0));
        assertEquals(Duration.ZERO, Supervisor.backoff(0, -1.0));
        assertEquals(Duration.ZERO, Supervisor.backoff(0, Double.NaN));
    }

    @Test
    void aRetryThatKeepsFailingBacksOffWithJitterUntilItIsToldToStop() {
        AtomicInteger attempts = new AtomicInteger();
        Supervisor supervisor = this.supervisor(0.5);
        assertTrue(supervisor.retry("FEDERATION", () -> attempts.incrementAndGet() >= 4));

        for (int i = 0; i < 4; i++) {
            this.scheduler.runNext();
        }
        assertEquals(4, attempts.get());
        assertTrue(this.scheduler.due.isEmpty(), "the fourth attempt said stop, so nothing more is scheduled");
        // Half of each ceiling: 5 s, 10 s, 20 s, 40 s.
        assertEquals(List.of(Duration.ofMillis(2500), Duration.ofMillis(5000), Duration.ofMillis(10_000), Duration.ofMillis(20_000)),
                this.scheduler.waits);
        assertEquals(List.of("FEDERATION", "FEDERATION", "FEDERATION", "FEDERATION"), this.counted, "one count per attempt");
    }

    @Test
    void anAttemptThatThrowsIsRetriedOnTheSameSchedule() {
        AtomicInteger attempts = new AtomicInteger();
        Supervisor supervisor = this.supervisor(0.0);
        supervisor.retry("HOSTING", () -> {
            if (attempts.incrementAndGet() == 1) {
                throw new IllegalStateException("a fault outside the start function");
            }
            return true;
        });
        this.scheduler.runNext();
        this.scheduler.runNext();
        assertEquals(2, attempts.get());
        assertTrue(this.scheduler.due.isEmpty());
    }

    @Test
    void aCopyThatMayNotScheduleSaysSo() {
        this.scheduler.allowed = false;
        assertFalse(this.supervisor(0.3).retry("FAPI", () -> true));
        assertTrue(this.counted.isEmpty());
        assertThrows(NullPointerException.class, () -> this.supervisor(0.3).retry(null, () -> true));
        assertThrows(NullPointerException.class, () -> this.supervisor(0.3).retry("FAPI", null));
        assertThrows(NullPointerException.class, () -> new Supervisor(null, () -> 0, c -> { }));
    }

    @Test
    void noThreadStartsInACopyThatIsNotTheWebapps() {
        Supervisor.WebappScheduler notWebapp = new Supervisor.WebappScheduler(() -> false);
        assertFalse(notWebapp.schedule(Duration.ZERO, () -> { }));
        assertFalse(notWebapp.schedule(Duration.ZERO, () -> { }), "and again, logged once");
        assertEquals(Optional.empty(), ManagedExecutors.live(Supervisor.WebappScheduler.executorName()));
    }

    @Test
    void theSharedSupervisorRetriesNothingInAnUnmarkedCopy() {
        // Nothing in this module's tests marks the loader the webapp's (F-2's listener does, in PingFederate).
        assumeFalse(Lifecycle.current().isWebapp());
        assertSame(Supervisor.shared(), Supervisor.shared());
        assertFalse(Supervisor.shared().retry("SSF", () -> true));
        assertEquals(Optional.empty(), ManagedExecutors.live(Supervisor.WebappScheduler.executorName()));
    }

    @Test
    void theWebappsCopyRetriesOnOneManagedExecutor() throws Exception {
        Supervisor.WebappScheduler webapp = new Supervisor.WebappScheduler(() -> true);
        CountDownLatch ran = new CountDownLatch(2);
        try {
            assertTrue(webapp.schedule(Duration.ZERO, ran::countDown));
            assertTrue(webapp.schedule(Duration.ofMillis(1), ran::countDown), "the same executor, created once");
            assertTrue(ran.await(10, TimeUnit.SECONDS));
            ManagedExecutor executor = ManagedExecutors.live(Supervisor.WebappScheduler.executorName()).orElseThrow();
            assertTrue(executor.name().startsWith("component-supervisor-"), executor.name());

            // Closed (a shutdown), the next retry makes a new one.
            executor.close();
            CountDownLatch again = new CountDownLatch(1);
            assertTrue(webapp.schedule(Duration.ZERO, again::countDown));
            assertTrue(again.await(10, TimeUnit.SECONDS));
        } finally {
            ManagedExecutors.live(Supervisor.WebappScheduler.executorName()).ifPresent(ManagedExecutor::close);
        }
    }

    @Test
    void anAttemptIsCountedInTheRetriesMetric() {
        long before = Supervisor.Retries.RETRIES.get("OPERATOR_API");
        Supervisor supervisor = new Supervisor(this.scheduler, () -> 0.0, Supervisor::count);
        supervisor.retry("OPERATOR_API", () -> true);
        this.scheduler.runNext();
        assertTrue(this.scheduler.due.isEmpty());
        assertEquals(before + 1, Supervisor.Retries.RETRIES.get("OPERATOR_API"));
        assertEquals("oidf_component_retries_total", Supervisor.Retries.RETRIES.name());
    }
}
