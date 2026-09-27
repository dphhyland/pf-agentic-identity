package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache.Verdict;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import org.junit.jupiter.api.Test;

/**
 * The jti guard the federation endpoints authenticate clients with (OpenID Federation 1.0 §8.8): spent once,
 * refused after, and a store that cannot answer is a 503, never a spent jti.
 */
class OpenIdFederationServletJtiGuardTest {

    @Test
    void aJtiIsSpentOnceAndRefusedAfter() {
        AttestationReplayCache spent = new InMemoryAttestationReplayCache();
        assertTrue(OpenIdFederationServlet.assertionNotSpent(spent, "https://rp.example", "j1", 60L));
        assertFalse(OpenIdFederationServlet.assertionNotSpent(spent, "https://rp.example", "j1", 60L));
    }

    @Test
    @Requirement("RFC6749 §5.2")
    void aStoreThatCannotAnswerIsTemporarilyUnavailableNotASpentJti() {
        AttestationReplayCache down = (client, jti, ttl) -> Verdict.STORE_UNAVAILABLE;
        FederationException e = assertThrows(FederationException.class,
                () -> OpenIdFederationServlet.assertionNotSpent(down, "https://rp.example", "j1", 60L));
        assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, e.error());
        assertEquals(503, e.error().httpStatus());
    }
}
