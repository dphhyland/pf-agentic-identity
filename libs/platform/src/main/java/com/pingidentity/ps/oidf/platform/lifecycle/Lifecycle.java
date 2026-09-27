/*
 * What one loaded copy of platform must close when it shuts down.
 */
package com.pingidentity.ps.oidf.platform.lifecycle;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The resources one classloader's copy of platform holds open - executors, pools, registered MBeans - and the
 * one place they are closed.
 *
 * <p>Statics are per loader (docs/development/classloaders.md), so {@link #current()} is this loader's registry
 * and no other: the webapp's copy in {@code pf-runtime.war}, the engine's in {@code server/default/deploy} and a
 * plugin's relocated copy each have their own, and closing one closes nothing of another's.
 *
 * <p>{@link #shutdown(Duration)} closes in the reverse of registration order, so a resource registered after
 * the ones it uses is closed before them. It runs once: later calls do nothing. A resource whose close throws
 * is logged and the rest are still closed. The wait is bounded: each close runs on a short-lived daemon thread
 * of its own and is waited for only until the budget runs out, so one close that hangs cannot hold up a
 * container's undeploy. A close still running at the end is left to finish in the background and reported. A
 * resource registered after shutdown is closed at once, the same way, and not kept.
 *
 * <p>Whether this loader is the webapp's - the one copy allowed to start background threads - is not something
 * a copy can see for itself. It is {@link LoaderRole#UNKNOWN} until the webapp's lifecycle listener (plan item
 * F-2) calls {@link #markWebapp()}; the engine's and the plugins' copies get no such callback and stay unknown.
 */
public final class Lifecycle {

    /** How long {@link #shutdown()} waits in all for the closes it starts. */
    public static final Duration DEFAULT_BUDGET = Duration.ofSeconds(10);

    private static final PlatformLog LOG = PlatformLog.get(Lifecycle.class);
    private static final Lifecycle CURRENT = new Lifecycle();

    /** Which loader this copy of platform was loaded by, as far as anything has said. */
    public enum LoaderRole {
        /** Nothing has said: the engine's and the plugins' copies, and the webapp's before its listener runs. */
        UNKNOWN,
        /** The webapp's copy, marked by its lifecycle listener. */
        WEBAPP
    }

    /** How one close ended. */
    public enum Outcome {
        CLOSED,
        /** The close threw; the detail is the exception. */
        FAILED,
        /** The budget ran out first; the close carries on in the background. */
        TIMED_OUT
    }

    /** One resource's close, as {@link #shutdown(Duration)} reports it. */
    public record Closed(String name, Outcome outcome, String detail) {
    }

    private record Entry(String name, AutoCloseable resource) {
    }

    private final List<Entry> resources = new ArrayList<>();
    private volatile LoaderRole role = LoaderRole.UNKNOWN;
    private boolean shutDown;

    Lifecycle() {
    }

    /** This loader's registry. */
    public static Lifecycle current() {
        return CURRENT;
    }

    /**
     * Adds a resource to close at shutdown.
     *
     * @param name     what the log calls it
     * @param resource closed once, at shutdown
     * @return {@code true} when it is registered; {@code false} when shutdown has already run, in which case it
     *         has just been closed, within {@link #DEFAULT_BUDGET}
     */
    public boolean register(String name, AutoCloseable resource) {
        Objects.requireNonNull(resource, "resource");
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("a resource needs a name");
        }
        Entry entry = new Entry(name, resource);
        synchronized (this) {
            if (!this.shutDown) {
                this.resources.add(entry);
                return true;
            }
        }
        LOG.warn("Lifecycle: " + name + " was registered after shutdown and is closed at once");
        close(entry, System.nanoTime() + DEFAULT_BUDGET.toNanos());
        return false;
    }

    /** Marks this copy as the webapp's. Called by the webapp's lifecycle listener, and by nothing else. */
    public void markWebapp() {
        if (this.role != LoaderRole.WEBAPP) {
            this.role = LoaderRole.WEBAPP;
            LOG.info("Lifecycle: this copy of platform is the webapp's");
        }
    }

    public LoaderRole loaderRole() {
        return this.role;
    }

    /** Whether this copy is known to be the webapp's; {@code false} while that is unknown. */
    public boolean isWebapp() {
        return this.role == LoaderRole.WEBAPP;
    }

    public synchronized boolean isShutDown() {
        return this.shutDown;
    }

    /** {@link #shutdown(Duration)} within {@link #DEFAULT_BUDGET}. */
    public List<Closed> shutdown() {
        return shutdown(DEFAULT_BUDGET);
    }

    /**
     * Closes every registered resource, the last registered first, waiting at most {@code budget} in all.
     *
     * @return how each close ended, in the order they were started; empty on every call after the first
     */
    public List<Closed> shutdown(Duration budget) {
        Objects.requireNonNull(budget, "budget");
        long deadline = System.nanoTime() + Math.max(0, budget.toNanos());
        List<Entry> toClose;
        synchronized (this) {
            if (this.shutDown) {
                return List.of();
            }
            this.shutDown = true;
            toClose = new ArrayList<>(this.resources);
            this.resources.clear();
        }
        List<Closed> report = new ArrayList<>(toClose.size());
        for (int i = toClose.size() - 1; i >= 0; i--) {
            report.add(close(toClose.get(i), deadline));
        }
        long failed = report.stream().filter(c -> c.outcome() == Outcome.FAILED).count();
        long timedOut = report.stream().filter(c -> c.outcome() == Outcome.TIMED_OUT).count();
        LOG.info("Lifecycle: shut down " + report.size() + " resource(s), " + failed + " failed, " + timedOut + " timed out");
        return List.copyOf(report);
    }

    /**
     * Closes one resource on a thread of its own and waits for it until the deadline. Closes run outside the
     * registry's lock, so a close that registers something or asks whether shutdown has run cannot deadlock.
     */
    private static Closed close(Entry entry, long deadline) {
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread closer = new Thread(() -> {
            try {
                entry.resource().close();
            } catch (Throwable t) {
                failure.set(t);
            }
        }, "oidf-platform-close-" + entry.name());
        closer.setDaemon(true);
        closer.start();
        long remaining = deadline - System.nanoTime();
        try {
            if (remaining > 0) {
                closer.join(remaining / 1_000_000L, (int) Math.max(1, remaining % 1_000_000L));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        if (closer.isAlive()) {
            LOG.warn("Lifecycle: " + entry.name() + " is still closing after the shutdown budget; not waiting for it");
            return new Closed(entry.name(), Outcome.TIMED_OUT, "still closing when the budget ran out");
        }
        Throwable t = failure.get();
        if (t != null) {
            LOG.warn("Lifecycle: " + entry.name() + " failed to close", t);
            return new Closed(entry.name(), Outcome.FAILED, t.toString());
        }
        return new Closed(entry.name(), Outcome.CLOSED, "");
    }
}
