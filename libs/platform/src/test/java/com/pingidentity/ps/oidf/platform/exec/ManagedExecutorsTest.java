/*
 * The static entry points of this loader's copy: what they start, what they count, and the closer's threads.
 */
package com.pingidentity.ps.oidf.platform.exec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ManagedExecutorsTest {

    private static final Label EXECUTOR = Label.capped("executor", 64);

    private static void await(CountDownLatch latch) throws InterruptedException {
        assertTrue(latch.await(10, TimeUnit.SECONDS), "timed out");
    }

    @Test
    void everyStartsANamedJobThatIsListedCountedAndTimed() throws Exception {
        CountDownLatch twice = new CountDownLatch(2);
        AtomicReference<String> thread = new AtomicReference<>();
        ManagedExecutor job = ManagedExecutors.every("facade-every", Duration.ZERO, Duration.ofMillis(5), () -> {
            thread.set(Thread.currentThread().getName());
            twice.countDown();
        }).orElseThrow();
        try {
            await(twice);
            assertEquals("oidf-facade-every-1", thread.get());
            assertEquals(Optional.of(job), ManagedExecutors.live("facade-every"));
            assertTrue(ManagedExecutors.snapshot().stream().anyMatch(s -> s.name().equals("facade-every")));
            assertEquals(Optional.empty(), ManagedExecutors.every("facade-every", Duration.ofSeconds(1), () -> { }),
                    "a second start of a running job starts nothing");
        } finally {
            job.close();
        }
        long runs = job.runs();
        assertTrue(runs >= 2);
        assertEquals(runs, Metrics.counter("oidf_executor_runs_total", "Runs of each managed executor's task", EXECUTOR)
                .get("facade-every"));
        assertEquals(runs, Metrics.timer("oidf_executor_run_seconds", "How long each run of a managed executor's task took",
                EXECUTOR).count("facade-every"));
        assertEquals(Optional.empty(), ManagedExecutors.live("facade-every"));
    }

    @Test
    void aFailedRunIsCountedUnderItsExecutor() throws Exception {
        CountDownLatch ran = new CountDownLatch(1);
        ManagedExecutor job = ManagedExecutors.after("facade-failing", Duration.ZERO, () -> {
            ran.countDown();
            throw new IllegalStateException("fails");
        }).orElseThrow();
        await(ran);
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (job.runs() == 0 && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        job.close();
        assertEquals(1, Metrics.counter("oidf_executor_failures_total", "Runs of a managed executor's task that threw", EXECUTOR)
                .get("facade-failing"));
    }

    @Test
    void everyWithOneIntervalWaitsItBeforeTheFirstRun() {
        ManagedExecutor job = ManagedExecutors.every("facade-later", Duration.ofHours(1), () -> { }).orElseThrow();
        job.close();
        assertEquals(0, job.runs());
    }

    @Test
    void singleSchedulesNothingUntilAsked() throws Exception {
        ManagedExecutor job = ManagedExecutors.single("facade-single").orElseThrow();
        try {
            assertEquals(0, job.runs());
            CountDownLatch ran = new CountDownLatch(1);
            job.after(Duration.ZERO, ran::countDown);
            await(ran);
        } finally {
            job.close();
        }
    }

    @Test
    void aBadDurationIsRefusedBeforeTheNameIsClaimed() {
        assertThrows(IllegalArgumentException.class, () -> ManagedExecutors.every("facade-bad", Duration.ZERO, () -> { }));
        assertThrows(IllegalArgumentException.class,
                () -> ManagedExecutors.every("facade-bad", Duration.ofSeconds(-1), Duration.ofSeconds(1), () -> { }));
        assertThrows(IllegalArgumentException.class, () -> ManagedExecutors.after("facade-bad", Duration.ofSeconds(-1), () -> { }));
        assertThrows(NullPointerException.class, () -> ManagedExecutors.every("facade-bad", Duration.ofSeconds(1), null));
        assertThrows(NullPointerException.class, () -> ManagedExecutors.after("facade-bad", Duration.ZERO, null));
        assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + "facade-bad"));
        assertEquals(Optional.empty(), ManagedExecutors.live("facade-bad"));
    }

    @Test
    void startDaemonNamesEachThreadInTurnAndLogsWhatEscapes() throws Exception {
        CountDownLatch done = new CountDownLatch(2);
        Thread first = ManagedExecutors.startDaemon("facade-daemon", done::countDown);
        Thread second = ManagedExecutors.startDaemon("facade-daemon", () -> {
            done.countDown();
            throw new IllegalStateException("escapes, and is logged");
        });
        await(done);
        first.join(5_000);
        second.join(5_000);
        assertEquals("oidf-facade-daemon-1", first.getName());
        assertEquals("oidf-facade-daemon-2", second.getName());
        assertTrue(first.isDaemon());
        assertEquals(List.of(), ManagedExecutors.snapshot().stream().filter(s -> s.name().equals("facade-daemon")).toList(),
                "not an executor: nothing to list");
        assertThrows(IllegalArgumentException.class, () -> ManagedExecutors.startDaemon("Bad Name", () -> { }));
    }
}
