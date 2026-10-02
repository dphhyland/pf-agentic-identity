package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AttestationReplayCacheTest {

    @Test
    void firstUseAcceptedReplayRejected() {
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache();
        assertTrue(cache.firstSeen("client-a", "jti-1", 300L));
        assertFalse(cache.firstSeen("client-a", "jti-1", 300L));
    }

    @Test
    void differentJtiAndClientAreIndependent() {
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache();
        assertTrue(cache.firstSeen("client-a", "jti-1", 300L));
        assertTrue(cache.firstSeen("client-a", "jti-2", 300L));
        assertTrue(cache.firstSeen("client-b", "jti-1", 300L));
    }

    @Test
    void blankJtiRejected() {
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache();
        assertThrows(IllegalArgumentException.class, () -> cache.firstSeen("client-a", "  ", 300L));
    }

    @Test
    void boundedCacheEvictsButStaysUsable() {
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(2);
        assertTrue(cache.firstSeen("c", "a", 300L));
        assertTrue(cache.firstSeen("c", "b", 300L));
        assertTrue(cache.firstSeen("c", "c", 300L)); // evicts eldest ("a")
        assertTrue(cache.size() <= 2);
        // "a" was evicted, so it is accepted again (acceptable trade-off documented on the cache)
        assertTrue(cache.firstSeen("c", "a", 300L));
    }

    @Test
    void theVerdictIsFirstUseThenReplayAndNeverUnavailable() {
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache();
        assertTrue(cache.record("c", "j", 300L) == AttestationReplayCache.Verdict.FIRST_USE);
        assertTrue(cache.record("c", "j", 300L) == AttestationReplayCache.Verdict.REPLAY);
        assertTrue(cache.record(null, "j", 0L) == AttestationReplayCache.Verdict.FIRST_USE, "a null client is the empty client");
    }

    @Test
    void aNullJtiIsRefusedLikeABlankOne() {
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache();
        assertThrows(IllegalArgumentException.class, () -> cache.record("c", null, 300L));
    }

    @Test
    void anExpiredEntryIsFirstUseAgain() {
        ReplayRetentionTest.MutableClock clock = new ReplayRetentionTest.MutableClock(java.time.Instant.ofEpochSecond(1000L));
        InMemoryAttestationReplayCache cache = new InMemoryAttestationReplayCache(16, clock);
        assertTrue(cache.recordUntil("c", "j", 1001L) == AttestationReplayCache.Verdict.FIRST_USE);
        clock.set(java.time.Instant.ofEpochSecond(1002L));
        assertTrue(cache.recordUntil("c", "j", 1100L) == AttestationReplayCache.Verdict.FIRST_USE,
                "a jti whose retention has passed is not a replay: the proof it came from can no longer be accepted");
    }
}
