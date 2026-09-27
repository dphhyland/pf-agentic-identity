/*
 * Per-node in-memory implementation of the evidence binding store.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Bounded in-memory {@link EvidenceBindingStore}: a binding lives until its evidence expires, and the map
 * is size-bounded with LRU eviction like the other in-memory stores. Insert-if-absent, then compare, under
 * one lock - the same outcome as Redis's {@code SET NX} followed by a {@code GET}.
 *
 * <p>State is per-node, so on a cluster a thief can win the binding on a node that has not seen the
 * rightful holder; a clustered deployment uses {@link RedisAttestationStore}.
 */
public final class InMemoryEvidenceBindingStore implements EvidenceBindingStore {
    private final Clock clock;
    private final int maxEntries;
    private final LinkedHashMap<String, Bound> bindings;

    public InMemoryEvidenceBindingStore() {
        this(DEFAULT_MAX_ENTRIES, Clock.systemUTC());
    }

    public InMemoryEvidenceBindingStore(int maxEntries, Clock clock) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be > 0, got " + maxEntries);
        }
        this.maxEntries = maxEntries;
        this.clock = clock;
        this.bindings = new LinkedHashMap<String, Bound>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Bound> eldest) {
                return this.size() > InMemoryEvidenceBindingStore.this.maxEntries;
            }
        };
    }

    @Override
    public synchronized Binding bind(String evidenceDigest, String jkt, String clientId, long evidenceExpEpochSeconds) {
        if (evidenceDigest == null || evidenceDigest.isBlank() || jkt == null || jkt.isBlank()) {
            throw new IllegalArgumentException("evidence digest and jkt are required to bind evidence");
        }
        String client = clientId == null ? "" : clientId;
        long now = this.clock.instant().getEpochSecond();
        Bound existing = this.bindings.get(evidenceDigest);
        if (existing != null && existing.expiresAt > now) {
            return existing.jkt.equals(jkt) && existing.clientId.equals(client) ? Binding.BOUND : Binding.CONFLICT;
        }
        // Absent, or expired with the evidence it described: this presenter takes the binding.
        this.bindings.put(evidenceDigest, new Bound(jkt, client, Math.max(evidenceExpEpochSeconds, now + 1L)));
        return Binding.BOUND;
    }

    public synchronized int size() {
        return this.bindings.size();
    }

    private static final class Bound {
        final String jkt;
        final String clientId;
        final long expiresAt;

        Bound(String jkt, String clientId, long expiresAt) {
            this.jkt = jkt;
            this.clientId = clientId;
            this.expiresAt = expiresAt;
        }
    }
}
