/*
 * The one place the repository's code starts a background thread.
 */
package com.pingidentity.ps.oidf.platform.exec;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.metrics.Timer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Background work for this loaded copy of platform: named daemon threads, one executor per job, each closed by
 * this copy's {@link Lifecycle} at shutdown, with its runs counted and timed in this copy's metrics.
 *
 * <pre>{@code
 * Optional<ManagedExecutor> sweeper = ManagedExecutors.every("registration-sweeper", Duration.ofMinutes(5), this::sweepOnce);
 * }</pre>
 *
 * <p>A job's thread is {@code oidf-<name>-<n>}. A start returns an empty {@link Optional} when this copy may not
 * start the job - a plugin's relocated copy, a copy that has shut down, or a job of that name already running in
 * the JVM (see {@link ExecutorRegistry}); the reason is logged. Statics are per loader
 * (docs/development/classloaders.md), so this is one registry per copy.
 *
 * <p>Metrics, one series per executor name (a capped label, since names are constants):
 * {@code oidf_executor_runs_total}, {@code oidf_executor_failures_total} (runs that threw) and
 * {@code oidf_executor_run_seconds}.
 *
 * <p>A job that must run once per cluster rather than once per node is C-4's {@code leaderEvery} (Phase 4),
 * not this.
 */
public final class ManagedExecutors {

    private static final PlatformLog LOG = PlatformLog.get(ManagedExecutors.class);

    /** The id a claim carries: this copy, as the registration sweeper's owner property identifies its owner. */
    private static final String COPY_ID = Integer.toHexString(System.identityHashCode(ManagedExecutors.class));

    private static final ExecutorRegistry REGISTRY = new ExecutorRegistry(COPY_ID, ManagedExecutors.class.getPackageName(),
            () -> Lifecycle.current().isShutDown(), (name, resource) -> Lifecycle.current().register(name, resource),
            ManagedExecutors::record);

    private static final Map<String, AtomicInteger> DAEMONS = new ConcurrentHashMap<>();

    private ManagedExecutors() {
    }

    /**
     * An executor with one thread and nothing scheduled yet: for a job that schedules its own runs (one retry at
     * a time) or runs a loop until it is interrupted ({@link ManagedExecutor#execute}).
     */
    public static Optional<ManagedExecutor> single(String name) {
        return REGISTRY.create(name);
    }

    /** Runs {@code task} every {@code interval}, the first time one interval from now. */
    public static Optional<ManagedExecutor> every(String name, Duration interval, Runnable task) {
        return every(name, interval, interval, task);
    }

    /** Runs {@code task} first after {@code initialDelay}, then {@code interval} after each run ends. */
    public static Optional<ManagedExecutor> every(String name, Duration initialDelay, Duration interval, Runnable task) {
        ManagedExecutor.nonNegativeNanos(initialDelay, "initialDelay");
        ManagedExecutor.positiveNanos(interval, "interval");
        Objects.requireNonNull(task, "task");
        Optional<ManagedExecutor> executor = REGISTRY.create(name);
        executor.ifPresent(e -> e.every(initialDelay, interval, task));
        return executor;
    }

    /** Runs {@code task} once, after {@code delay}, on an executor of its own. */
    public static Optional<ManagedExecutor> after(String name, Duration delay, Runnable task) {
        ManagedExecutor.nonNegativeNanos(delay, "delay");
        Objects.requireNonNull(task, "task");
        Optional<ManagedExecutor> executor = REGISTRY.create(name);
        executor.ifPresent(e -> e.after(delay, task));
        return executor;
    }

    /** The executor of that name this copy runs, if it runs one. */
    public static Optional<ManagedExecutor> live(String name) {
        return REGISTRY.live(name);
    }

    /** Every executor this copy runs, by name. */
    public static List<ManagedExecutor.Status> snapshot() {
        return REGISTRY.snapshot();
    }

    /**
     * Starts a short-lived daemon thread, named {@code oidf-<name>-<n>}, that the caller owns and waits on - the
     * one kind of thread that is not a managed executor. It is not claimed, not registered with the lifecycle and
     * not refused in any copy, because the caller is the lifecycle: {@link Lifecycle}'s shutdown closes each
     * resource on one of these, so that one close that hangs cannot hold up the rest, and a shutdown cannot
     * depend on an executor that is itself being shut down. What escapes {@code task} is logged.
     */
    public static Thread startDaemon(String name, Runnable task) {
        ExecutorRegistry.checkName(name);
        int n = DAEMONS.computeIfAbsent(name, k -> new AtomicInteger()).incrementAndGet();
        Thread thread = new Thread(task, "oidf-" + name + "-" + n);
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler(ManagedExecutors::uncaught);
        thread.start();
        return thread;
    }

    static void uncaught(Thread thread, Throwable thrown) {
        LOG.error("Thread " + thread.getName() + " ended with an uncaught " + thrown, thrown);
    }

    private static void record(String name, long nanos, boolean failed) {
        Runs.RUNS.inc(name);
        Runs.DURATION.recordNanos(nanos, name);
        if (failed) {
            Runs.FAILURES.inc(name);
        }
    }

    /** The metrics, registered on the first run, so loading this class registers nothing. */
    private static final class Runs {
        private static final Label EXECUTOR = Label.capped("executor", 64);
        static final Counter RUNS = Metrics.counter("oidf_executor_runs_total", "Runs of each managed executor's task", EXECUTOR);
        static final Counter FAILURES = Metrics.counter("oidf_executor_failures_total",
                "Runs of a managed executor's task that threw", EXECUTOR);
        static final Timer DURATION = Metrics.timer("oidf_executor_run_seconds", "How long each run of a managed executor's task took",
                EXECUTOR);
    }
}
