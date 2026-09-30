/*
 * The signed Entity Configurations of authority-signed hosted entities, kept until they are due for renewal.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.federation.EntityId;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Keeps the Entity Configuration {@link HostedEntityConfigurationBuilder} signed for a hosted entity, so a resolver
 * asking for it again is answered without another signature - for an OpenBao-held key, another round trip (plan item
 * H-FED-9).
 *
 * <p>A configuration is served from here while more than {@link #KEEP_WHILE_REMAINING} of its lifetime remains: with
 * the builder's one-hour lifetime, for its first fifteen minutes. After that it is signed afresh, so a resolver never
 * receives one with less than three quarters of its lifetime left. It is kept only for the exact registry record it was
 * built from - a record read on another node after a change there differs, and is built afresh - and dropped at once
 * when this process changes the entity or the Trust Marks it holds ({@link #changed}). What another node changes about
 * the Trust Marks an entity holds is therefore seen here within those fifteen minutes; everything about the entity
 * itself, at once.
 *
 * <p>At most {@link #MAX_ENTRIES} configurations are kept, the least recently served dropped first.
 */
public final class HostedEntityConfigurationCache {

    /** The share of its lifetime a configuration must have left to be served from here. */
    public static final double KEEP_WHILE_REMAINING = 0.75;

    /** How many configurations one process keeps. */
    public static final int MAX_ENTRIES = 10_000;

    private static final HostedEntityConfigurationCache SHARED = new HostedEntityConfigurationCache(Clock.systemUTC(), MAX_ENTRIES);

    private final Clock clock;
    private final Map<String, Kept> entries;

    /** A cache of its own, for a test; the process's is {@link #shared()}. */
    HostedEntityConfigurationCache(Clock clock, int maxEntries) {
        this.clock = Objects.requireNonNull(clock, "clock");
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be at least 1");
        }
        this.entries = new LinkedHashMap<>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Kept> eldest) {
                return this.size() > maxEntries;
            }
        };
    }

    /** The process-wide cache every builder {@link AuthoritySupport} configures shares. */
    public static HostedEntityConfigurationCache shared() {
        return SHARED;
    }

    /**
     * Drops what the process-wide cache holds for {@code entityId}: the registries call it after every change they commit
     * to the entity, and the Trust Mark registries after every grant or revocation to it.
     */
    public static void changed(String entityId) {
        SHARED.invalidate(entityId);
    }

    /** The configuration built from exactly {@code entity}, while it has more than {@link #KEEP_WHILE_REMAINING} of its lifetime left. */
    synchronized String get(HostedEntity entity) {
        String key = EntityId.comparable(entity.entityId());
        Kept entry = this.entries.get(key);
        if (entry == null) {
            return null;
        }
        if (!entry.source().equals(entity) || !this.clock.instant().isBefore(entry.renewAt())) {
            this.entries.remove(key);
            return null;
        }
        return entry.jwt();
    }

    /** Keeps {@code jwt}, signed from {@code entity} at {@code iat} to expire at {@code exp}. */
    synchronized void put(HostedEntity entity, String jwt, Instant iat, Instant exp) {
        long lifetime = exp.getEpochSecond() - iat.getEpochSecond();
        Instant renewAt = iat.plusSeconds((long) Math.floor(lifetime * (1.0 - KEEP_WHILE_REMAINING)));
        this.entries.put(EntityId.comparable(entity.entityId()), new Kept(entity, Objects.requireNonNull(jwt, "jwt"), renewAt));
    }

    /** Drops what is kept for {@code entityId}, in whichever spelling. */
    public synchronized void invalidate(String entityId) {
        if (entityId != null) {
            this.entries.remove(EntityId.comparable(entityId));
        }
    }

    /** Drops everything. */
    public synchronized void clear() {
        this.entries.clear();
    }

    synchronized int size() {
        return this.entries.size();
    }

    private record Kept(HostedEntity source, String jwt, Instant renewAt) {
    }
}
