/*
 * Fixed-window counters in this JVM.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import java.time.Clock;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * A {@link WindowCounter} in this JVM, bounded: at most {@code capacity} keys, the oldest dropped first, so a caller
 * spraying addresses drops its own counters rather than grow the heap (the rule client-attestation's
 * ChallengeRateLimiter follows).
 */
public final class InMemoryWindowCounter implements WindowCounter {
    /** The keys {@link #InMemoryWindowCounter(Clock)} keeps. */
    public static final int DEFAULT_CAPACITY = 16_384;

    private record Window(long startMillis, long endMillis, long count) {
    }

    private final Clock clock;
    private final Map<String, Window> windows;

    public InMemoryWindowCounter(Clock clock) {
        this(clock, DEFAULT_CAPACITY);
    }

    public InMemoryWindowCounter(Clock clock, int capacity) {
        this.clock = Objects.requireNonNull(clock, "clock");
        if (capacity < 1) {
            throw new IllegalArgumentException("capacity must be at least 1, not " + capacity);
        }
        this.windows = new LinkedHashMap<>(16, 0.75f, false) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Window> eldest) {
                return size() > capacity;
            }
        };
    }

    @Override
    public synchronized WindowCount hit(String key, Duration window) {
        long now = this.clock.millis();
        Window w = this.windows.get(key);
        Window next = w == null || w.endMillis() <= now
                ? new Window(now, now + window.toMillis(), 1)
                : new Window(w.startMillis(), w.endMillis(), w.count() + 1);
        this.windows.put(key, next);
        return new WindowCount(next.count(), Duration.ofMillis(next.endMillis() - now));
    }

    @Override
    public synchronized WindowCount peek(String key) {
        long now = this.clock.millis();
        Window w = this.windows.get(key);
        if (w == null || w.endMillis() <= now) {
            return new WindowCount(0, Duration.ZERO);
        }
        return new WindowCount(w.count(), Duration.ofMillis(w.endMillis() - now));
    }

    /** How many keys are held, expired ones included until they are next hit or dropped. */
    public synchronized int size() {
        return this.windows.size();
    }
}
