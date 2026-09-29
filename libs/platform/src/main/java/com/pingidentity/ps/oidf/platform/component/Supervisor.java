/*
 * Retries a component part that failed on a dependency, with backoff, on the webapp's managed executor.
 */
package com.pingidentity.ps.oidf.platform.component;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.DoubleSupplier;

/**
 * Plan item S-9's supervisor. A part that ends its start in {@link ComponentState#FAILED_DEPENDENCY} is started
 * again here, after a backoff of {@value #FIRST_SECONDS} s doubling to {@value #CAP_SECONDS} s, with full jitter
 * (each wait is uniform between zero and that ceiling, so a fleet that lost the same dependency does not come back
 * in step). The caller's attempt moves the part to {@code STARTING}, runs its start function and records what
 * happened; it answers whether to stop - the part is ready, or failed in a way a retry does not fix
 * ({@code FAILED_CONFIG}, {@code REFUSED}), or was retired by a later registration. {@code FAILED_CONFIG} and
 * {@code REFUSED} are never handed here: a restart or a configuration change fixes them.
 *
 * <p>Only the webapp's copy of platform starts a thread (docs/development/classloaders.md, rule 2): {@link #shared()}
 * schedules nothing, and says so once, until {@link Lifecycle#loaderRole()} is the webapp's. The engine's copy and a
 * plugin's never retry; a part there keeps the state its start recorded, and ComponentParts' pull probe is still
 * run by health. The executor is created on the first retry, so a copy in which nothing fails starts no thread.
 *
 * <p>Each attempt counts in {@code oidf_component_retries_total{component}}. No event yet: PR-5 adds the
 * {@code platform} event catalogue.
 */
public final class Supervisor {

    /** The first wait's ceiling, in seconds. */
    public static final long FIRST_SECONDS = 5;
    /** The ceiling every later wait is capped at, in seconds. */
    public static final long CAP_SECONDS = 300;

    private static final PlatformLog LOG = PlatformLog.get(Supervisor.class);
    private static final Supervisor SHARED = new Supervisor(new WebappScheduler(), () -> ThreadLocalRandom.current().nextDouble(),
            Supervisor::count);

    /** Where a retry is scheduled: the webapp's managed executor in production, a fake in tests. */
    public interface Scheduler {
        /** Runs {@code task} once after {@code delay}; {@code false} when this copy may not schedule anything. */
        boolean schedule(Duration delay, Runnable task);
    }

    /**
     * One attempt at starting a part again.
     */
    @FunctionalInterface
    public interface Attempt {
        /** Starts the part again and records the outcome; answers whether to stop retrying. */
        boolean stop();
    }

    private final Scheduler scheduler;
    private final DoubleSupplier random;
    private final Consumer<String> counter;

    /**
     * @param scheduler where retries run
     * @param random    a value in [0, 1) per wait: the jitter
     * @param counter   told the component's name once per attempt
     */
    public Supervisor(Scheduler scheduler, DoubleSupplier random, Consumer<String> counter) {
        this.scheduler = Objects.requireNonNull(scheduler, "scheduler");
        this.random = Objects.requireNonNull(random, "random");
        this.counter = Objects.requireNonNull(counter, "counter");
    }

    /** This loader's supervisor, which retries only in the webapp's copy. */
    public static Supervisor shared() {
        return SHARED;
    }

    /**
     * Retries {@code attempt} until it answers {@code true}: the first attempt after {@link #backoff(int, double)}
     * of 0, each later one after the next.
     *
     * @return whether the first attempt was scheduled; {@code false} in a copy that may not start a thread
     */
    public boolean retry(String component, Attempt attempt) {
        Objects.requireNonNull(component, "component");
        Objects.requireNonNull(attempt, "attempt");
        return this.schedule(component, attempt, 0);
    }

    private boolean schedule(String component, Attempt attempt, int failures) {
        Duration wait = backoff(failures, this.random.getAsDouble());
        return this.scheduler.schedule(wait, () -> this.run(component, attempt, failures));
    }

    private void run(String component, Attempt attempt, int failures) {
        this.counter.accept(component);
        boolean stop;
        try {
            stop = attempt.stop();
        } catch (RuntimeException | Error e) {
            // The attempt records its own outcome and catches what its start throws; this is a fault in that
            // machinery. Retrying it on the same schedule is the fail-soft answer: the part stays as it was.
            LOG.warn("Supervisor: a retry of " + component + " failed outside its start function", e);
            stop = false;
        }
        if (!stop) {
            this.schedule(component, attempt, failures + 1);
        }
    }

    /**
     * The wait before the attempt that follows {@code failures} failed retries: uniform in
     * [0, min({@value #CAP_SECONDS}, {@value #FIRST_SECONDS} x 2<sup>failures</sup>)) seconds, full jitter.
     *
     * @param failures retries that have failed so far, 0 before the first
     * @param random   in [0, 1); outside it is clamped
     */
    public static Duration backoff(int failures, double random) {
        long ceilingMillis = ceiling(failures).toMillis();
        double r = Double.isNaN(random) ? 0 : Math.max(0, Math.min(random, 1));
        long millis = (long) Math.floor(ceilingMillis * r);
        return Duration.ofMillis(Math.min(millis, ceilingMillis));
    }

    /** The ceiling of the wait after {@code failures} failed retries: {@value #FIRST_SECONDS} s doubling, capped. */
    public static Duration ceiling(int failures) {
        long seconds = FIRST_SECONDS;
        for (int i = 0; i < Math.max(0, failures) && seconds < CAP_SECONDS; i++) {
            seconds *= 2;
        }
        return Duration.ofSeconds(Math.min(seconds, CAP_SECONDS));
    }

    private static void count(String component) {
        try {
            Retries.RETRIES.inc(component);
        } catch (RuntimeException e) {
            LOG.warn("Supervisor: the retry of " + component + " could not be counted (" + e + ")");
        }
    }

    /** The metric, registered on the first retry, so loading this class registers nothing. */
    private static final class Retries {
        static final Counter RETRIES = Metrics.counter("oidf_component_retries_total",
                "Attempts by the supervisor to start a component part again after it failed on a dependency",
                Label.capped("component", 16));
    }

    /**
     * Schedules on one managed executor per copy, created on the first retry, and only in a copy marked as the
     * webapp's. Its name carries this copy's id, because a name is claimed once per JVM and each war's copy has
     * its own parts to retry.
     */
    static final class WebappScheduler implements Scheduler {
        private final BooleanSupplier webapp;
        private volatile ManagedExecutor executor;
        private volatile boolean refusedLogged;

        WebappScheduler() {
            this(() -> Lifecycle.current().isWebapp());
        }

        WebappScheduler(BooleanSupplier webapp) {
            this.webapp = webapp;
        }

        @Override
        public boolean schedule(Duration delay, Runnable task) {
            Optional<ManagedExecutor> e = this.executor();
            return e.isPresent() && e.get().after(delay, task);
        }

        private synchronized Optional<ManagedExecutor> executor() {
            if (this.executor != null && !this.executor.isClosed()) {
                return Optional.of(this.executor);
            }
            if (!this.webapp.getAsBoolean()) {
                if (!this.refusedLogged) {
                    this.refusedLogged = true;
                    LOG.info("Supervisor: this copy of platform is not the webapp's, so it retries nothing; a part that failed"
                            + " on a dependency here keeps its state until it starts again (docs/development/classloaders.md, rule 2)");
                }
                return Optional.empty();
            }
            Optional<ManagedExecutor> created = ManagedExecutors.single(executorName());
            created.ifPresent(e -> this.executor = e);
            return created;
        }

        static String executorName() {
            return "component-supervisor-" + Integer.toHexString(System.identityHashCode(Supervisor.class));
        }
    }
}
