package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * The attestation challenge endpoint cannot require authentication — a client needs a challenge before
 * it can authenticate — and every call writes into a bounded challenge cache. So the attack worth
 * stopping is eviction: flood the endpoint and legitimate clients' challenges are dropped before they
 * are redeemed, which surfaces as intermittent attestation failures rather than as an outage.
 */
class ChallengeRateLimiterTest {

    @Test
    void allowsUpToTheCapThenRefuses() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter(3, 60L, 1024);

        assertTrue(limiter.allow("10.0.0.1", 0L));
        assertTrue(limiter.allow("10.0.0.1", 1L));
        assertTrue(limiter.allow("10.0.0.1", 2L));
        assertFalse(limiter.allow("10.0.0.1", 3L), "the fourth request in the window is over the cap");
    }

    @Test
    void oneCallerCannotConsumeAnothersBudget() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter(2, 60L, 1024);
        limiter.allow("10.0.0.1", 0L);
        limiter.allow("10.0.0.1", 0L);

        assertFalse(limiter.allow("10.0.0.1", 0L));
        assertTrue(limiter.allow("10.0.0.2", 0L),
                "the whole point: a flooding caller must not deny service to everyone else");
    }

    @Test
    void theWindowRollsOver() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter(1, 60L, 1024);
        assertTrue(limiter.allow("10.0.0.1", 0L));
        assertFalse(limiter.allow("10.0.0.1", 59_000L));

        assertTrue(limiter.allow("10.0.0.1", 60_000L), "a new window starts exactly at the boundary");
    }

    @Test
    void retryAfterCountsDownWithinTheWindow() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter(1, 60L, 1024);
        limiter.allow("10.0.0.1", 0L);

        assertEquals(60L, limiter.retryAfterSeconds("10.0.0.1", 0L));
        assertEquals(30L, limiter.retryAfterSeconds("10.0.0.1", 30_000L));
        assertEquals(0L, limiter.retryAfterSeconds("10.0.0.1", 60_000L));
    }

    /**
     * The limiter must not become the exhaustion it prevents. Spraying source addresses evicts the
     * attacker's own oldest counters instead of growing the map without bound.
     */
    @Test
    void theLimitersOwnMapIsBounded() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter(10, 60L, 100);
        for (int i = 0; i < 5000; i++) {
            limiter.allow("10.0." + (i / 256) + "." + (i % 256), i);
        }

        assertTrue(limiter.trackedCallers() <= 100,
                "tracked " + limiter.trackedCallers() + " callers with a cap of 100");
    }

    /** An unattributable request is the last one to wave through, so blanks share one bucket. */
    @Test
    void callersWithNoAddressShareABucketRatherThanBypassing() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter(2, 60L, 1024);

        assertTrue(limiter.allow(null, 0L));
        assertTrue(limiter.allow("", 0L));
        assertFalse(limiter.allow(null, 0L), "null and blank must not each get their own budget");
    }

    @Test
    void defaultsAreGenerousEnoughForALegitimateClient() {
        ChallengeRateLimiter limiter = new ChallengeRateLimiter();

        // A real client asks once per token exchange; 60/minute is well clear of that.
        assertEquals(ChallengeRateLimiter.DEFAULT_MAX_PER_WINDOW, limiter.maxPerWindow());
        assertEquals(60L, limiter.windowSeconds());
        for (int i = 0; i < ChallengeRateLimiter.DEFAULT_MAX_PER_WINDOW; i++) {
            assertTrue(limiter.allow("10.0.0.1", i), "request " + i + " should be within the default cap");
        }
    }
}
