/*
 * A replay store for one node: a bounded map in this JVM.
 */
package com.pingidentity.ps.oidf.rs;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link ReplayStore} in this JVM, for a resource served by one node. Behind a load balancer each node would keep
 * its own map and accept a proof another node has already accepted: use {@link RedisReplayStore} there.
 *
 * <p>Bounded: at most {@code capacity} keys are remembered. When the map is full it first drops every expired key;
 * if it is still full the store answers as unavailable (an {@link IOException}), so a flood of proofs is refused
 * rather than let through or allowed to grow the heap.
 */
public final class InMemoryReplayStore implements ReplayStore {
    /** The capacity {@link #InMemoryReplayStore()} uses. */
    public static final int DEFAULT_CAPACITY = 100_000;

    private final Map<String, Long> expiries = new HashMap<>();
    private final int capacity;
    private final Clock clock;

    public InMemoryReplayStore() {
        this(DEFAULT_CAPACITY, Clock.systemUTC());
    }

    public InMemoryReplayStore(int capacity, Clock clock) {
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be at least 1, not " + capacity);
        }
        this.capacity = capacity;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public synchronized boolean firstUse(String key, Duration window) throws IOException {
        long now = this.clock.millis();
        Long expiry = this.expiries.get(key);
        if (expiry != null && expiry > now) {
            return false;
        }
        if (expiry == null && this.expiries.size() >= this.capacity) {
            for (Iterator<Long> it = this.expiries.values().iterator(); it.hasNext();) {
                if (it.next() <= now) {
                    it.remove();
                }
            }
            if (this.expiries.size() >= this.capacity) {
                throw new IOException("the in-memory replay store is full (" + this.capacity
                        + " proofs inside their windows)");
            }
        }
        this.expiries.put(key, now + window.toMillis());
        return true;
    }

    /** How many keys the map holds, expired ones included until the next sweep. */
    public synchronized int size() {
        return this.expiries.size();
    }
}
