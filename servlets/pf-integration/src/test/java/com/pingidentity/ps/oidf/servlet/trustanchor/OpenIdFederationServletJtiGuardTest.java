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

    /**
     * OpenID Federation 1.0 §8.9: "temporarily_unavailable - The server hosting the federation endpoint is currently
     * unable to handle the request due to temporary overloading or maintenance. The HTTP response status code SHOULD
     * be 503 (Service Unavailable)." A store that cannot say whether the assertion's {@code jti} was spent is that
     * condition, and never a spent {@code jti}.
     */
    @Test
    @Requirement("OIDFED §8.9")
    void aStoreThatCannotAnswerIsTemporarilyUnavailableNotASpentJti() {
        AttestationReplayCache down = (client, jti, ttl) -> Verdict.STORE_UNAVAILABLE;
        FederationException e = assertThrows(FederationException.class,
                () -> OpenIdFederationServlet.assertionNotSpent(down, "https://rp.example", "j1", 60L));
        assertEquals(FederationError.TEMPORARILY_UNAVAILABLE, e.error());
        assertEquals(503, e.error().httpStatus());
    }
}
