package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AttestationChallengeServiceTest {

    @Test
    void issuedChallengeCanBeConsumedOnce() {
        InMemoryAttestationChallengeService service = new InMemoryAttestationChallengeService();
        String challenge = service.issue();
        assertNotNull(challenge);
        assertTrue(service.consume(challenge));
        assertFalse(service.consume(challenge), "challenge must be single-use");
    }

    @Test
    void unknownChallengeRejected() {
        InMemoryAttestationChallengeService service = new InMemoryAttestationChallengeService();
        assertFalse(service.consume("not-a-real-challenge"));
        assertFalse(service.consume(null));
        assertFalse(service.consume(""));
    }

    @Test
    void challengesAreUnique() {
        InMemoryAttestationChallengeService service = new InMemoryAttestationChallengeService();
        assertNotEquals(service.issue(), service.issue());
    }

    @Test
    void expiredChallengeRejected() throws Exception {
        InMemoryAttestationChallengeService service = new InMemoryAttestationChallengeService(1024, 1L);
        String challenge = service.issue();
        Thread.sleep(1100L);
        assertFalse(service.consume(challenge), "challenge must expire after its TTL");
    }
}
