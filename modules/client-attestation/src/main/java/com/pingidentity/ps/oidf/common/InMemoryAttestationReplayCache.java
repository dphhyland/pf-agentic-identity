/*
 * Per-node in-memory implementation of the attestation jti replay cache.
 */
package com.pingidentity.ps.oidf.common;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Bounded, time-bounded in-memory {@link AttestationReplayCache}. Entries expire after a TTL derived
 * from the proof's {@code iat} window and the map is size-bounded with LRU eviction, mirroring
 * {@link SubordinateStatementCache}.
 *
 * <p>State is per-node. A clustered PingFederate deployment should use {@link RedisAttestationStore}
 * (or another shared store) to make replay detection cluster-wide.
 */
public final class InMemoryAttestationReplayCache implements AttestationReplayCache {
    private static final Log LOGGER = LogFactory.getLog(InMemoryAttestationReplayCache.class);

    private final int maxEntries;
    private final LinkedHashMap<String, Long> seen;

    public InMemoryAttestationReplayCache() {
        this(DEFAULT_MAX_ENTRIES);
    }

    public InMemoryAttestationReplayCache(int maxEntries) {
        if (maxEntries != UNBOUNDED && maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be > 0 or -1 for unbounded, got " + maxEntries);
        }
        this.maxEntries = maxEntries;
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
    public synchronized boolean firstSeen(String clientId, String jti, long ttlSeconds) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti is required for replay protection");
        }
        long now = Instant.now().getEpochSecond();
        String key = (clientId == null ? "" : clientId) + " " + jti;
        Long expiry = this.seen.get(key);
        if (expiry != null && expiry > now) {
            LOGGER.debug((Object) ("replay DETECTED for clientId=" + clientId + " jti=" + jti));
            return false;
        }
        long ttl = ttlSeconds > 0L ? ttlSeconds : 1L;
        this.seen.put(key, now + ttl);
        return true;
    }

    public synchronized int size() {
        return this.seen.size();
    }
}
