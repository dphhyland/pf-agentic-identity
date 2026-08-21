/*
 * Per-caller rate cap for the unauthenticated attestation challenge endpoint.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A fixed-window request cap keyed by caller, for the attestation challenge endpoint.
 *
 * <p>That endpoint is unauthenticated by design — a client needs a challenge <em>before</em> it can
 * authenticate — and every call writes an entry into a <em>bounded</em> challenge cache
 * ({@link AttestationChallengeService#DEFAULT_MAX_ENTRIES}). So the interesting attack is not resource
 * exhaustion but <b>eviction</b>: a flood of unauthenticated requests pushes legitimate clients'
 * challenges out of the cache before they are redeemed, and those clients fail attestation with a
 * challenge the server has simply forgotten. Cheap to mount, and it presents as intermittent
 * attestation failures rather than as an attack.
 *
 * <p>Fixed-window rather than a token bucket: it is a handful of fields, needs no background sweep, and
 * the burst-at-a-window-boundary imprecision it is criticised for does not matter here — the goal is to
 * keep one caller from evicting everyone else's challenges, not to meter an API precisely.
 *
 * <p>The limiter's own map is bounded and evicts oldest-first, so it cannot itself become the memory
 * exhaustion it exists to prevent. An attacker spraying source addresses evicts their own counters
 * rather than growing the map without limit — which caps the damage at "the limiter stops helping
 * against a distributed flood", the same place a per-IP cap was always going to end up.
 */
public final class ChallengeRateLimiter {

    /** Requests per caller per window. Generous: a legitimate client asks once per token exchange. */
    public static final int DEFAULT_MAX_PER_WINDOW = 60;
    public static final long DEFAULT_WINDOW_SECONDS = 60L;
    /** Distinct callers tracked. Beyond this the oldest counter is dropped. */
    public static final int DEFAULT_MAX_CALLERS = 16384;

    private final int maxPerWindow;
    private final long windowMillis;
    private final LinkedHashMap<String, Window> windows;

    private static final class Window {
        long startMillis;
        int count;
    }

    public ChallengeRateLimiter() {
        this(DEFAULT_MAX_PER_WINDOW, DEFAULT_WINDOW_SECONDS, DEFAULT_MAX_CALLERS);
    }

    public ChallengeRateLimiter(int maxPerWindow, long windowSeconds, int maxCallers) {
        this.maxPerWindow = maxPerWindow > 0 ? maxPerWindow : DEFAULT_MAX_PER_WINDOW;
        this.windowMillis = (windowSeconds > 0 ? windowSeconds : DEFAULT_WINDOW_SECONDS) * 1000L;
        final int cap = maxCallers > 0 ? maxCallers : DEFAULT_MAX_CALLERS;
        this.windows = new LinkedHashMap<String, Window>(16, 0.75f, false) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Window> eldest) {
                return size() > cap;
            }
        };
    }

    /** Requests allowed per window, for {@code Retry-After} and for tests. */
    public int maxPerWindow() {
        return this.maxPerWindow;
    }

    public long windowSeconds() {
        return this.windowMillis / 1000L;
    }

    /**
     * Records a request from {@code caller} and reports whether it is within the cap.
     *
     * @param caller  an opaque key — the remote address. A blank or null caller is treated as one
     *                shared bucket rather than waved through: an unattributable request is exactly the
     *                one not to exempt.
     * @param nowMillis current time; injected so the window boundary is testable without sleeping
     * @return true if the request may proceed
     */
    public synchronized boolean allow(String caller, long nowMillis) {
        String key = caller == null || caller.isBlank() ? "-" : caller;
        Window w = this.windows.get(key);
        if (w == null || nowMillis - w.startMillis >= this.windowMillis) {
            w = new Window();
            w.startMillis = nowMillis;
            w.count = 0;
            this.windows.put(key, w);
        }
        if (w.count >= this.maxPerWindow) {
            return false;
        }
        w.count++;
        return true;
    }

    /** Seconds until {@code caller}'s current window rolls over — the {@code Retry-After} value. */
    public synchronized long retryAfterSeconds(String caller, long nowMillis) {
        Window w = this.windows.get(caller == null || caller.isBlank() ? "-" : caller);
        if (w == null) {
            return 0L;
        }
        long remaining = this.windowMillis - (nowMillis - w.startMillis);
        return remaining <= 0L ? 0L : (remaining + 999L) / 1000L;
    }

    /** Distinct callers currently tracked. For tests and for confirming the bound holds. */
    public synchronized int trackedCallers() {
        return this.windows.size();
    }
}
