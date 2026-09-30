/*
 * Per-node in-memory implementation of the attestation jti replay cache.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.time.Clock;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Bounded in-memory {@link AttestationReplayCache}. Each entry holds the absolute time until which its
 * {@code jti} is remembered - the end of the carrying proof's acceptance window, which the caller derives - and is
 * a replay until that second has passed. The map is size-bounded: when it is full, entries whose time has passed
 * go first, and only then the least recently used live one, so a full store forgets a spent proof only when it
 * has nothing expired left to forget.
 *
 * <p>State is per-node. A clustered PingFederate deployment should use {@link RedisAttestationStore}
 * (or another shared store) to make replay detection cluster-wide. Memory never answers
 * {@link Verdict#STORE_UNAVAILABLE}.
 */
public final class InMemoryAttestationReplayCache implements AttestationReplayCache {
    private static final Log LOGGER = LogFactory.getLog(InMemoryAttestationReplayCache.class);

    private final int maxEntries;
    private final Clock clock;
    private final LinkedHashMap<String, Long> seen;

    public InMemoryAttestationReplayCache() {
        this(DEFAULT_MAX_ENTRIES);
    }

    public InMemoryAttestationReplayCache(int maxEntries) {
        this(maxEntries, Clock.systemUTC());
    }

    /** A cache that reads the time from {@code clock}: the one its callers judge proofs by. */
    public InMemoryAttestationReplayCache(int maxEntries, Clock clock) {
        if (maxEntries != UNBOUNDED && maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be > 0 or -1 for unbounded, got " + maxEntries);
        }
        this.maxEntries = maxEntries;
        this.clock = Objects.requireNonNull(clock, "clock");
        this.seen = new LinkedHashMap<String, Long>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                return InMemoryAttestationReplayCache.this.maxEntries != UNBOUNDED
                        && this.size() > InMemoryAttestationReplayCache.this.maxEntries;
            }
        };
    }

    @Override
    public synchronized Verdict recordUntil(String clientId, String jti, long retainUntilEpochSeconds) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti is required for replay protection");
        }
        long now = this.now();
        if (retainUntilEpochSeconds < now) {
            return Verdict.STALE;
        }
        String key = (clientId == null ? "" : clientId) + " " + jti;
        Long retainedUntil = this.seen.get(key);
        if (retainedUntil != null && retainedUntil >= now) {
            LOGGER.debug((Object) ("replay DETECTED for clientId=" + clientId + " jti=" + jti));
            return Verdict.REPLAY;
        }
        if (this.maxEntries != UNBOUNDED && this.seen.size() >= this.maxEntries) {
            this.evictExpired(now);
        }
        this.seen.put(key, retainUntilEpochSeconds);
        return Verdict.FIRST_USE;
    }

    /** The relative form, timed by this cache's clock rather than the system's. Deprecated; removed at 1.0.0. */
    @Override
    @Deprecated
    public Verdict record(String clientId, String jti, long ttlSeconds) {
        return this.recordUntil(clientId, jti, this.now() + Math.max(1L, ttlSeconds));
    }

    private void evictExpired(long now) {
        Iterator<Map.Entry<String, Long>> it = this.seen.entrySet().iterator();
        while (it.hasNext()) {
            if (it.next().getValue() < now) {
                it.remove();
            }
        }
    }

    private long now() {
        return this.clock.millis() / 1000L;
    }

    public synchronized int size() {
        return this.seen.size();
    }
}
