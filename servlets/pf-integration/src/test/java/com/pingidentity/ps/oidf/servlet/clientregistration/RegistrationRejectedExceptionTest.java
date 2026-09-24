package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.servlet.clientregistration.RegistrationRejectedException.Kind;
import org.junit.jupiter.api.Test;

/**
 * A refusal from the federation layer keeps its §8.9 code and status on the way out, and says what kind of
 * failure it was - the token endpoint answers a federation it could not reach differently from one that said no.
 */
class RegistrationRejectedExceptionTest {

    private static RegistrationRejectedException from(FederationError error) {
        return RegistrationRejectedException.from(new FederationException(error, "because"));
    }

    @Test
    @Requirement("OIDFED §12.2.4(1)")
    void aFederationRefusalKeepsItsCodeAndStatus() {
        RegistrationRejectedException e = from(FederationError.INVALID_TRUST_CHAIN);

        assertEquals(400, e.status());
        assertEquals("invalid_trust_chain", e.error());
        assertEquals("because", e.getMessage());
        assertEquals(Kind.TRUST, e.kind());
        assertFalse(e.isTransport());
    }

    @Test
    void eachFederationErrorIsTheKindOfFailureItReports() {
        assertEquals(Kind.TRANSPORT, from(FederationError.TEMPORARILY_UNAVAILABLE).kind());
        assertTrue(from(FederationError.TEMPORARILY_UNAVAILABLE).isTransport());
        assertEquals(503, from(FederationError.TEMPORARILY_UNAVAILABLE).status());
        assertEquals(Kind.METADATA, from(FederationError.INVALID_METADATA).kind());
        assertEquals(Kind.INTERNAL, from(FederationError.SERVER_ERROR).kind());
        assertEquals(Kind.TRUST, from(FederationError.INVALID_TRUST_ANCHOR).kind());
        assertEquals(404, from(FederationError.INVALID_TRUST_ANCHOR).status());
        assertEquals(Kind.TRUST, from(FederationError.NOT_FOUND).kind());
    }

    @Test
    void theFederationRefusalIsKeptAsTheCause() {
        FederationException cause = new FederationException(FederationError.INVALID_TRUST_CHAIN, "because");

        assertSame(cause, RegistrationRejectedException.from(cause).getCause());
    }

    @Test
    void aRefusalOfThisModulesOwnIsAboutMetadataUnlessItSaysOtherwise() {
        assertEquals(Kind.METADATA, new RegistrationRejectedException(400, "invalid_client_metadata", "x").kind());
        assertEquals(Kind.POLICY, new RegistrationRejectedException(400, "invalid_client_metadata", "x", Kind.POLICY, null).kind());
    }
}
