/*
 * An optional, short-lived cache of PDP decisions for the detail types an operator names - never a payment.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Decisions for the types in "Decision cache types", kept for "Decision cache TTL (s)" (at most
 * {@value #MAX_TTL_SECONDS}) and at most {@value #MAX_ENTRIES} of them, the oldest dropped first. Empty types (the
 * default) is no cache at all.
 *
 * <p>The key is the digest of the whole PDP question - the canonical detail, the principal and how it was
 * established, the client, the attestation context with its attester {@code iss} ({@link PdpDecisions#keyOf}) - with
 * the PDP URL and the RAR models fingerprint in front, so a decision is reused only for exactly the question it
 * answered, from the same PDP, under the same models. Only decisions are kept, never a failure: an unreachable PDP is
 * asked again next time.
 *
 * <p>Some types can never be cached, and a configuration that names one is refused, in the admin console on save and
 * at configure for an archive: {@code payment_initiation} (a payment is decided once, at the moment it is asked for),
 * and every type in "Types requiring an authenticated principal" (a decision about a person is not reused across
 * requests). {@link #refusal} says which.
 *
 * <p>The cache is per processor instance and per node: a node that has not seen a question asks the PDP. That is
 * weaker caching, never a looser decision, so it needs no accepted risk in production.
 */
final class DecisionCache {

    static final int MAX_TTL_SECONDS = 60;
    static final int DEFAULT_TTL_SECONDS = 30;
    static final int MAX_ENTRIES = 1024;
    /** Never cacheable, whatever the principal-types field says. */
    static final Set<String> NEVER = Set.of("payment_initiation");

    private final Set<String> types;
    private final long ttlNanos;
    private final LongSupplier clock;
    private final Map<String, Entry> entries = new LinkedHashMap<>(16, 0.75f, false);

    private record Entry(DecisionResponse decision, long expiresAt) { }

    DecisionCache(Set<String> types, int ttlSeconds, LongSupplier nanoClock) {
        this.types = Collections.unmodifiableSet(new LinkedHashSet<>(types));
        this.ttlNanos = TimeUnit.SECONDS.toNanos(ttlSecondsOf(ttlSeconds));
        this.clock = nanoClock;
    }

    DecisionCache(Set<String> types, int ttlSeconds) {
        this(types, ttlSeconds, System::nanoTime);
    }

    /** The TTL field held to 1-{@value #MAX_TTL_SECONDS}; 0 or less is the default. */
    static int ttlSecondsOf(int configured) {
        if (configured <= 0) {
            return DEFAULT_TTL_SECONDS;
        }
        return Math.min(MAX_TTL_SECONDS, configured);
    }

    Set<String> types() {
        return types;
    }

    long ttlNanos() {
        return ttlNanos;
    }

    boolean covers(String type) {
        return types.contains(type);
    }

    /**
     * The types in {@code cacheTypes} that may never be cached - {@link #NEVER} and every type in
     * {@code principalTypes} - named in the reason; {@code null} when there is none.
     */
    static String refusal(Set<String> cacheTypes, Set<String> principalTypes) {
        Set<String> refused = new TreeSet<>();
        for (String type : cacheTypes) {
            if (NEVER.contains(type) || principalTypes.contains(type)) {
                refused.add(type);
            }
        }
        if (refused.isEmpty()) {
            return null;
        }
        return "Decision cache types may not name " + refused + ": payment_initiation and the types requiring an"
                + " authenticated principal are decided on every request, never from a cache";
    }

    /** A copy of the decision cached for {@code key}, or {@code null} when there is none or it has expired. */
    synchronized DecisionResponse get(String key) {
        Entry entry = entries.get(key);
        if (entry == null) {
            return null;
        }
        if (clock.getAsLong() - entry.expiresAt >= 0) {
            entries.remove(key);
            return null;
        }
        return DecisionMemo.copyOf(entry.decision);
    }

    synchronized void put(String key, DecisionResponse decision) {
        entries.remove(key);
        entries.put(key, new Entry(DecisionMemo.copyOf(decision), clock.getAsLong() + ttlNanos));
        while (entries.size() > MAX_ENTRIES) {
            entries.remove(entries.keySet().iterator().next());
        }
    }

    synchronized int size() {
        return entries.size();
    }
}
