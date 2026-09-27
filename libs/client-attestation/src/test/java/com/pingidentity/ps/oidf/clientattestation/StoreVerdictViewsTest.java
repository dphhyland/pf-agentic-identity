package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache.Verdict;
import org.junit.jupiter.api.Test;

/**
 * The boolean views callers written against the 0.3.0 contract still use: true and false for the two findings
 * about the client, and an exception - never {@code false}, which those callers read as a replay or an unknown
 * challenge - for an outage of the store.
 */
class StoreVerdictViewsTest {

    private static AttestationReplayCache replay(Verdict verdict) {
        return (clientId, jti, ttl) -> verdict;
    }

    private static AttestationChallengeService challenges(Consumption consumption) {
        return new AttestationChallengeService() {
            @Override
            public String issue() {
                return "c";
            }

            @Override
            public Consumption consumeChallenge(String challenge) {
                return consumption;
            }

            @Override
            public long ttlSeconds() {
                return 1L;
            }
        };
    }

    @Test
    void firstSeenIsTrueOnFirstUseFalseOnReplayAndThrowsOnAnOutage() {
        assertTrue(replay(Verdict.FIRST_USE).firstSeen("c", "j", 1L));
        assertFalse(replay(Verdict.REPLAY).firstSeen("c", "j", 1L));
        assertThrows(StoreUnavailableException.class, () -> replay(Verdict.STORE_UNAVAILABLE).firstSeen("c", "j", 1L));
    }

    @Test
    void consumeIsTrueWhenConsumedFalseWhenUnknownAndThrowsOnAnOutage() {
        assertTrue(challenges(Consumption.CONSUMED).consume("c"));
        assertFalse(challenges(Consumption.UNKNOWN).consume("c"));
        assertThrows(StoreUnavailableException.class, () -> challenges(Consumption.STORE_UNAVAILABLE).consume("c"));
    }

    @Test
    void theOutageExceptionIsAnIllegalStateExceptionForOlderCallers() {
        assertTrue(new StoreUnavailableException("x") instanceof IllegalStateException);
        assertTrue(new StoreUnavailableException("x", new java.io.IOException()).getCause() instanceof java.io.IOException);
    }
}
