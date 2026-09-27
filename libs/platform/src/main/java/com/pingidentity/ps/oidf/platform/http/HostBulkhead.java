/*
 * At most so many requests to one origin at once (plan item S5a, part 2).
 */
package com.pingidentity.ps.oidf.platform.http;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A {@link Bulkhead} that lets at most {@link #maxPerOrigin()} requests to one origin ({@code scheme://host:port})
 * run at once. A request past that waits for a place until its own deadline and is then refused with
 * {@link OutboundHttpException.Reason#BULKHEAD_FULL}, so a peer that stops answering holds at most that many
 * connections, and a request never waits longer for a place than it would have waited for the peer.
 *
 * <p>What it does not do: a request waiting for a place still holds its caller's thread until its deadline, so the
 * bulkhead limits the sockets and the load on one peer, not the threads waiting to reach it. Each origin counts
 * separately, so it does nothing against many origins at once; the resolution budget (S5b) bounds those.
 *
 * <p>An origin is counted only while a request to it holds or waits for a place: its entry goes when the last one
 * leaves, so caller-supplied origins cannot grow the table past the requests in flight.
 */
public final class HostBulkhead implements Bulkhead {

    /**
     * The default most requests to one origin at once. A federation fetch takes milliseconds when the peer is well,
     * so 32 at once serves hundreds a second to one peer; the limit bites only when the peer is slow.
     */
    public static final int DEFAULT_MAX_PER_ORIGIN = 32;

    private final int maxPerOrigin;
    private final ConcurrentHashMap<String, Slot> slots = new ConcurrentHashMap<>();

    public HostBulkhead(int maxPerOrigin) {
        this.maxPerOrigin = atLeastOne(maxPerOrigin);
    }

    static int atLeastOne(int maxPerOrigin) {
        if (maxPerOrigin < 1) {
            throw new IllegalArgumentException("maxPerOrigin must be at least 1");
        }
        return maxPerOrigin;
    }

    /** A bulkhead of {@link #DEFAULT_MAX_PER_ORIGIN} places for each origin. */
    public static HostBulkhead withDefaults() {
        return new HostBulkhead(DEFAULT_MAX_PER_ORIGIN);
    }

    public int maxPerOrigin() {
        return this.maxPerOrigin;
    }

    /** How many requests to {@code origin} hold or wait for a place now; zero for an origin not in the table. */
    public int inFlight(String origin) {
        Slot slot = this.slots.get(origin);
        return slot == null ? 0 : slot.users.get();
    }

    /** How many origins the table holds: those with a request holding or waiting for a place. */
    int origins() {
        return this.slots.size();
    }

    @Override
    public Permit enter(String origin, Deadline deadline) throws OutboundHttpException {
        Slot slot = this.slots.compute(origin, this::join);
        boolean entered;
        try {
            entered = slot.permits.tryAcquire(deadline.remainingNanos(), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            leave(origin);
            throw new OutboundHttpException(OutboundHttpException.Reason.BULKHEAD_FULL,
                    "interrupted while waiting for one of the " + this.maxPerOrigin + " places for " + origin, e);
        }
        if (!entered) {
            leave(origin);
            throw new OutboundHttpException(OutboundHttpException.Reason.BULKHEAD_FULL, "all " + this.maxPerOrigin
                    + " places for " + origin + " stayed taken until the deadline");
        }
        return new Place(origin, slot);
    }

    /** Counts one more request against {@code origin}'s entry, making it if this is the only one. */
    private Slot join(String origin, Slot existing) {
        Slot slot = existing != null ? existing : new Slot(this.maxPerOrigin);
        slot.users.incrementAndGet();
        return slot;
    }

    /** One request to {@code origin} no longer holds or waits for a place; the entry goes with the last. */
    private void leave(String origin) {
        this.slots.computeIfPresent(origin, HostBulkhead::drop);
    }

    /** {@code slot} with one request fewer, or null - its entry removed - when that was the last. */
    static Slot drop(String origin, Slot slot) {
        return slot.users.decrementAndGet() == 0 ? null : slot;
    }

    @Override
    public String toString() {
        return "HostBulkhead[" + this.maxPerOrigin + " per origin, " + this.slots.size() + " origin(s) in flight]";
    }

    /** A place held for one request: closing it gives the place back once, however often it is closed. */
    private final class Place implements Permit {
        private final String origin;
        private final Slot slot;
        private final AtomicBoolean closed = new AtomicBoolean();

        Place(String origin, Slot slot) {
            this.origin = origin;
            this.slot = slot;
        }

        @Override
        public void close() {
            if (this.closed.compareAndSet(false, true)) {
                this.slot.permits.release();
                leave(this.origin);
            }
        }
    }

    /** One origin's places, and how many requests hold or wait for one (changed only inside the map's compute calls). */
    private static final class Slot {
        final Semaphore permits;
        final AtomicInteger users = new AtomicInteger();

        Slot(int max) {
            this.permits = new Semaphore(max, true);
        }
    }
}
