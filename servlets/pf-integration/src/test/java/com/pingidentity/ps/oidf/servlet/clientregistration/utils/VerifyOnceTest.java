package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

/**
 * The attestation is verified ONCE per request.
 *
 * <p>Two enforcement points run on the same request — the token-endpoint filter on the webapp
 * classloader, and this issuance criterion on the engine classloader — and both used to call
 * {@code ClientAttestationVerifier.verify()}. But {@code verify()} <em>consumes</em>: it burns the PoP
 * {@code jti} in the replay cache and single-uses any presented challenge. Two verifications of one
 * request therefore destroy each other.
 *
 * <p>That was latent only because challenges default off and the two classloaders get separate
 * in-memory stores. Configure one Redis — which {@code AttestationSupport} explicitly offers so replay
 * detection is "immune to the servlet-vs-hook classloader split" — and the second verify reports
 * "Replay detected for proof jti" and <em>nobody</em> gets a token. Which also meant challenges could
 * never be turned on.
 *
 * <p>So whichever point verifies first publishes its result, and the other reuses it.
 */
class VerifyOnceTest {

    /** An OGNL in-parameter map of the shape the criterion is handed. */
    private static Map<String, Object> inParams(HttpServletRequest request, String clientId) {
        Map<String, Object> in = new HashMap<>();
        AttributeValue requestValue = mock(AttributeValue.class);
        when(requestValue.getObjectValue()).thenReturn(request);
        in.put("context.HttpRequest", requestValue);
        AttributeValue clientValue = mock(AttributeValue.class);
        when(clientValue.getValue()).thenReturn(clientId);
        in.put("context.ClientId", clientValue);
        return in;
    }

    private static HttpServletRequest requestWith(Map<String, Object> verifiedContext) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        Map<String, Object> attributes = new HashMap<>();
        if (verifiedContext != null) {
            attributes.put(ClientAttestationUtils.VERIFIED_ATTESTATION_ATTRIBUTE, verifiedContext);
        }
        when(request.getAttribute(anyString())).thenAnswer(i -> attributes.get(i.getArgument(0)));
        org.mockito.Mockito.doAnswer(i -> attributes.put(i.getArgument(0), i.getArgument(1)))
                .when(request).setAttribute(anyString(), any());
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://as.example.com/as/token.oauth2"));
        when(request.getMethod()).thenReturn("POST");
        return request;
    }

    @Test
    void aRequestTheFilterAlreadyVerifiedIsNotVerifiedAgain() {
        Map<String, Object> verified = new HashMap<>();
        verified.put("client_id", "https://rp.example.com/agent-1");
        verified.put("sub", "https://rp.example.com/agent-1");
        HttpServletRequest request = requestWith(verified);

        // No attestation headers at all: if this returned true, it can only be because the published
        // verification was honoured rather than the header re-read.
        boolean permitted = ClientAttestationUtils.validateClientAttestation(
                inParams(request, "https://rp.example.com/agent-1"));

        assertTrue(permitted, "the filter's verification must satisfy the criterion");
    }

    @Test
    void thePriorVerificationIsRepublishedForTheRarProcessor() {
        Map<String, Object> verified = new HashMap<>();
        verified.put("client_id", "https://rp.example.com/agent-1");
        HttpServletRequest request = requestWith(verified);

        ClientAttestationUtils.validateClientAttestation(inParams(request, "https://rp.example.com/agent-1"));

        assertNotNull(request.getAttribute("com.pingidentity.ps.oidf.rar.attestation_context"),
                "the RAR processor reads this; reusing a verification must not stop publishing it");
    }

    /**
     * The fallback still has to fail closed. With nothing published and no valid attestation present,
     * the criterion denies — it must not treat "no prior verification" as permission.
     */
    @Test
    void nothingPublishedAndNoAttestationIsStillADenial() {
        HttpServletRequest request = requestWith(null);

        boolean permitted = ClientAttestationUtils.validateClientAttestation(
                inParams(request, "https://rp.example.com/agent-1"));

        assertFalse(permitted, "absent verification must fall through to verifying, and fail");
    }
}
