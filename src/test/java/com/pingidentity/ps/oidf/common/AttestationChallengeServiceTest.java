package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class AttestationChallengeServiceTest {

    @Test
    void issuedChallengeCanBeConsumedOnce() {
        AttestationChallengeService service = new AttestationChallengeService();
        String challenge = service.issue();
        assertNotNull(challenge);
        assertTrue(service.consume(challenge));
        assertFalse(service.consume(challenge), "challenge must be single-use");
    }

    @Test
    void unknownChallengeRejected() {
        AttestationChallengeService service = new AttestationChallengeService();
        assertFalse(service.consume("not-a-real-challenge"));
        assertFalse(service.consume(null));
        assertFalse(service.consume(""));
    }

    @Test
    void challengesAreUnique() {
        AttestationChallengeService service = new AttestationChallengeService();
        assertNotEquals(service.issue(), service.issue());
    }

    @Test
    void expiredChallengeRejected() throws Exception {
        AttestationChallengeService service = new AttestationChallengeService(1024, 1L);
        String challenge = service.issue();
        Thread.sleep(1100L);
        assertFalse(service.consume(challenge), "challenge must expire after its TTL");
    }
}
