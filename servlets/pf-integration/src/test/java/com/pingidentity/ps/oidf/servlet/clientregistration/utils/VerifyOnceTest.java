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
import jakarta.servlet.http.HttpServletRequest;
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

    private static final String CLIENT = "https://rp.example.com/agent-1";
    private static final String ISSUER = "https://as.example.com";

    private static boolean criterion(HttpServletRequest request, String clientId, AttestationPolicyResolver resolver) {
        return ClientAttestationUtils.validateClientAttestationInner(inParams(request, clientId), false,
                "https://trust-controller.example.com", "https://trust-controller.example.com", r -> ISSUER, () -> null,
                resolver, CriterionTesting.NO_SUBJECT_TOKENS);
    }

    /** What the filter publishes for {@code clientId}: its members, and the fingerprint of the policy it verified under. */
    private static Map<String, Object> published(String clientId, AttestationPolicyResolver resolver) throws Exception {
        Map<String, Object> verified = new HashMap<>();
        verified.put("client_id", clientId);
        verified.put("sub", clientId);
        verified.put(ClientAttestationUtils.POLICY_FINGERPRINT_KEY, AttestationPolicyResolver.fingerprint(
                ClientAttestationUtils.effectivePolicy(resolver, clientId, ISSUER, null, null)));
        return verified;
    }

    @Test
    void aRequestTheFilterAlreadyVerifiedIsNotVerifiedAgain() throws Exception {
        HttpServletRequest request = requestWith(published(CLIENT, CriterionTesting.NO_CLIENTS));

        // No attestation headers at all: if this returned true, it can only be because the published
        // verification was honoured rather than the header re-read.
        boolean permitted = criterion(request, CLIENT, CriterionTesting.NO_CLIENTS);

        assertTrue(permitted, "the filter's verification must satisfy the criterion");
    }

    @Test
    void thePriorVerificationIsRepublishedForTheRarProcessor() throws Exception {
        HttpServletRequest request = requestWith(published(CLIENT, CriterionTesting.NO_CLIENTS));

        criterion(request, CLIENT, CriterionTesting.NO_CLIENTS);

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

        boolean permitted = criterion(request, CLIENT, CriterionTesting.NO_CLIENTS);

        assertFalse(permitted, "absent verification must fall through to verifying, and fail");
    }

    /**
     * A verification the filter made under another policy than the one this copy resolves for the client - a filter
     * from before 0.6.0, which ignored the client's properties, or properties changed in between - is refused, and so
     * is one for another client or one with no fingerprint (plan item S4c).
     */
    @Test
    void aVerificationUnderAnotherPolicyOrForAnotherClientIsRefused() throws Exception {
        AttestationPolicyResolver tighter = AttestationPolicyResolver.over(
                id -> Map.of(ClientAttestationPolicy.POP_MAX_AGE, java.util.List.of("30")), java.time.Clock.systemUTC(), () -> false);
        assertFalse(criterion(requestWith(published(CLIENT, CriterionTesting.NO_CLIENTS)), CLIENT, tighter),
                "the filter verified under the server's policy; the client's is tighter");
        assertTrue(criterion(requestWith(published(CLIENT, tighter)), CLIENT, tighter));
        assertFalse(criterion(requestWith(published(CLIENT, CriterionTesting.NO_CLIENTS)), "https://rp.example.com/other",
                CriterionTesting.NO_CLIENTS), "a context for another client");
        Map<String, Object> old = published(CLIENT, CriterionTesting.NO_CLIENTS);
        old.remove(ClientAttestationUtils.POLICY_FINGERPRINT_KEY);
        assertFalse(criterion(requestWith(old), CLIENT, CriterionTesting.NO_CLIENTS), "a filter from before 0.6.0");
    }
}
