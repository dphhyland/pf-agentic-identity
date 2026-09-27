/*
 * One named background thread: its runs counted and timed, its failures logged, and one way to stop it.
 */
package com.pingidentity.ps.oidf.platform.exec;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

/**
 * A single-thread scheduled executor with a name, made only by {@link ManagedExecutors}. Its thread is a daemon
 * named {@code oidf-<name>-<n>} ({@code n} counts the threads this executor has made, from 1), so a thread dump
 * says which job it is. Every run goes through {@link #run(Runnable)}: it is timed and counted, and anything it
 * throws - an exception the task did not catch, or an {@link Error} - is logged and counted as a failure, and the
 * schedule carries on. (A bare {@code ScheduledExecutorService} drops a periodic task's later runs, silently,
 * after one throws.)
 *
 * <p>{@link #close()} stops it: it interrupts a run in progress, drops what is queued, and waits a bounded time
 * for the thread to end. A run that throws because it was interrupted by that close is not a failure; it is
 * logged at INFO as ended by shutdown. The executor is registered with this copy's
 * {@link com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle}, which closes it at shutdown; a site that stops
 * it earlier calls {@link #close()} itself, and the later close does nothing.
 */
public final class ManagedExecutor implements AutoCloseable {

    /** How long {@link #close()} waits for a run in progress to end once it has been interrupted. */
    public static final Duration CLOSE_WAIT = Duration.ofSeconds(5);

    private static final PlatformLog LOG = PlatformLog.get(ManagedExecutor.class);

    /** What one executor has done, for health and for tests. */
    public record Status(String name, boolean closed, long runs, long failures) {
    }

    /** Where runs are counted: this loader's metrics in production, a recorder in tests. */
    interface RunRecorder {
        void record(String name, long nanos, boolean failed);
    }

    private final String name;
    private final RunRecorder recorder;
    private final Runnable onClosed;
    private final ScheduledThreadPoolExecutor pool;
    private final AtomicInteger threads = new AtomicInteger();
    private final AtomicReference<Runnable> whenClosed = new AtomicReference<>();
    private final LongAdder runs = new LongAdder();
    private final LongAdder failures = new LongAdder();
    private volatile boolean closing;

    ManagedExecutor(String name, RunRecorder recorder, Runnable onClosed) {
        this.name = name;
        this.recorder = recorder;
        this.onClosed = onClosed;
        this.pool = new ScheduledThreadPoolExecutor(1, this::newThread);
        this.pool.setRemoveOnCancelPolicy(true);
    }

    public String name() {
        return this.name;
    }

    /** The name its threads carry, before the count: {@code oidf-<name>}. */
    public String threadNamePrefix() {
        return "oidf-" + this.name;
    }

    private Thread newThread(Runnable runnable) {
        Thread thread = new Thread(runnable, threadNamePrefix() + "-" + this.threads.incrementAndGet());
        thread.setDaemon(true);
        thread.setUncaughtExceptionHandler(this::uncaught);
        return thread;
    }

    /**
     * What escapes a thread. Every task runs inside {@link #run(Runnable)}, which catches everything, so this is
     * reached only by a failure in the executor's own machinery; it is logged and counted all the same.
     */
    void uncaught(Thread thread, Throwable thrown) {
        this.failures.increment();
        LOG.error("Managed executor " + this.name + ": thread " + thread.getName() + " ended with an uncaught " + thrown, thrown);
    }

    /**
     * Runs {@code task} every {@code interval}, first after {@code initialDelay}; each run starts {@code interval}
     * after the previous one ended (fixed delay), so a slow run never overlaps the next.
     *
     * @return whether it was scheduled; {@code false} once the executor is closed
     */
    public boolean every(Duration initialDelay, Duration interval, Runnable task) {
        Objects.requireNonNull(task, "task");
        long first = nonNegativeNanos(initialDelay, "initialDelay");
        long period = positiveNanos(interval, "interval");
        try {
            this.pool.scheduleWithFixedDelay(() -> run(task), first, period, TimeUnit.NANOSECONDS);
            return true;
        } catch (RejectedExecutionException e) {
            return refusedAfterClose();
        }
    }

    /**
     * Runs {@code task} once, after {@code delay}.
     *
     * @return whether it was scheduled; {@code false} once the executor is closed
     */
    public boolean after(Duration delay, Runnable task) {
        Objects.requireNonNull(task, "task");
        long wait = nonNegativeNanos(delay, "delay");
        try {
            this.pool.schedule(() -> run(task), wait, TimeUnit.NANOSECONDS);
            return true;
        } catch (RejectedExecutionException e) {
            return refusedAfterClose();
        }
    }

    /**
     * Runs {@code task} now, on this executor's one thread - for a loop that runs until it is interrupted. Such a
     * loop should end when its thread is interrupted: that is how {@link #close()} stops it.
     *
     * @return whether it was accepted; {@code false} once the executor is closed
     */
    public boolean execute(Runnable task) {
        return after(Duration.ZERO, task);
    }

    private boolean refusedAfterClose() {
        LOG.warn("Managed executor " + this.name + " is closed; a task given to it was not scheduled");
        return false;
    }

    static long positiveNanos(Duration duration, String what) {
        long nanos = nonNegativeNanos(duration, what);
        if (nanos == 0) {
            throw new IllegalArgumentException(what + " must be longer than zero");
        }
        return nanos;
    }

    static long nonNegativeNanos(Duration duration, String what) {
        Objects.requireNonNull(duration, what);
        if (duration.isNegative()) {
            throw new IllegalArgumentException(what + " must not be negative: " + duration);
        }
        try {
            return duration.toNanos();
        } catch (ArithmeticException e) {
            return Long.MAX_VALUE;
        }
    }

    /**
     * One run: timed, counted, and never allowed to throw out of the executor. A throw while the executor is
     * being closed is the interrupt that closes it, not a failure.
     */
    void run(Runnable task) {
        long start = System.nanoTime();
        boolean failed = false;
        try {
            task.run();
        } catch (Throwable thrown) {
            if (this.closing) {
                LOG.info("Managed executor " + this.name + ": a run ended by shutdown (" + thrown + ")");
            } else {
                failed = true;
                LOG.warn("Managed executor " + this.name + ": a run failed and the schedule carries on", thrown);
            }
        } finally {
            this.runs.increment();
            if (failed) {
                this.failures.increment();
            }
            this.recorder.record(this.name, System.nanoTime() - start, failed);
        }
    }

    /**
     * Something to run once this executor is closed - a site's own guard to release, for instance. Replaces an
     * earlier hook; run at once when the executor is already closed.
     */
    public void whenClosed(Runnable hook) {
        Objects.requireNonNull(hook, "hook");
        this.whenClosed.set(hook);
        if (this.closing) {
            runHook();
        }
    }

    private void runHook() {
        Runnable hook = this.whenClosed.getAndSet(null);
        if (hook != null) {
            hook.run();
        }
    }

    public boolean isClosed() {
        return this.closing;
    }

    public long runs() {
        return this.runs.sum();
    }

    public long failures() {
        return this.failures.sum();
    }

    public Status status() {
        return new Status(this.name, this.closing, runs(), failures());
    }

    /** {@link #close(Duration)} within {@link #CLOSE_WAIT}. */
    @Override
    public void close() {
        close(CLOSE_WAIT);
    }

    /**
     * Stops the executor: interrupts a run in progress, drops what is queued, and waits at most {@code wait} for
     * its thread to end. Then gives the name back (another copy, or a later start, may use it) and runs the
     * {@link #whenClosed(Runnable)} hook. Only the first call does anything.
     *
     * @return whether the thread ended within the wait; {@code true} on every call after the first
     */
    public boolean close(Duration wait) {
        long waitNanos = nonNegativeNanos(wait, "wait");
        synchronized (this) {
            if (this.closing) {
                return true;
            }
            this.closing = true;
        }
        this.pool.shutdownNow();
        boolean ended = awaitEnd(waitNanos);
        if (!ended) {
            LOG.warn("Managed executor " + this.name + " still running after " + wait.toMillis() + " ms; not waiting for it");
        }
        this.onClosed.run();
        runHook();
        return ended;
    }

    private boolean awaitEnd(long waitNanos) {
        try {
            return this.pool.awaitTermination(waitNanos, TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return this.pool.isTerminated();
        }
    }
}
