/*
 * S-9's rule for the OGNL entry points (S9b): each answers false, or nothing, while its component is not serving - and
 * never throws.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.servlet.GateTesting;
import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.attribute.AttributeValue;

class CriterionComponentGateTest {

    private final HttpServletRequest request = mock(HttpServletRequest.class);

    @AfterEach
    void serveAgain() {
        GateTesting.healthy(Startup.ATTESTATION_AUTH);
        GateTesting.healthy(Startup.FEDERATION);
    }

    /** The criteria a mapping hands its OGNL: a client and the request, which the gate never reads. */
    private Map<String, Object> criteria() {
        Map<String, Object> in = new HashMap<>();
        in.put("context.ClientId", new AttributeValue("https://rp.example"));
        AttributeValue request = mock(AttributeValue.class);
        org.mockito.Mockito.when(request.getObjectValue()).thenReturn(this.request);
        in.put("context.HttpRequest", request);
        return in;
    }

    private static void notServing(String component, ComponentState state) {
        var part = Startup.begin(component, "CriterionComponentGateTestPart");
        switch (state) {
            case FAILED_CONFIG -> part.failedConfig("a test's broken configuration");
            case FAILED_DEPENDENCY -> part.failedDependency("a test's missing dependency");
            case REFUSED -> part.refused("a test's forbidden setting");
            default -> { }
        }
    }

    @Test
    void theAttestationCriteriaAnswerFalseOrNothingWhileAttestationIsNotServing() {
        for (ComponentState state : new ComponentState[] {ComponentState.STARTING, ComponentState.FAILED_CONFIG,
                ComponentState.FAILED_DEPENDENCY, ComponentState.REFUSED}) {
            notServing(Startup.ATTESTATION_AUTH, state);
            Map<String, Object> in = this.criteria();
            assertFalse(ClientAttestationUtils.validateClientAttestation(in), state.name());
            assertFalse(ClientAttestationUtils.validateClientAttestation(in, false, "https://ta.example"), state.name());
            assertFalse(ClientAttestationUtils.validateClientAttestation(in, false, "https://ta.example", "https://ta.example"), state.name());
            assertEquals("", ClientAttestationUtils.attestationClaim(in, "agent_id"), state.name());
            GateTesting.healthy(Startup.ATTESTATION_AUTH);
        }
        // Nothing was read from the request: the gate is the first statement.
        verifyNoInteractions(this.request);
    }

    @Test
    void theFederationCriteriaAnswerFalseWhileFederationIsNotServing() {
        for (ComponentState state : new ComponentState[] {ComponentState.STARTING, ComponentState.FAILED_CONFIG,
                ComponentState.FAILED_DEPENDENCY, ComponentState.REFUSED}) {
            notServing(Startup.FEDERATION, state);
            Map<String, Object> in = this.criteria();
            assertFalse(OIDFederationUtils.validateTrustChain(in), state.name());
            assertFalse(OIDFederationUtils.validateTrustChain(in, false, "https://ta.example"), state.name());
            assertFalse(OIDFederationUtils.validateTrustChain(in, false, "https://ta.example", "https://ta.example"), state.name());
            assertFalse(OIDFederationUtils.federationPolicy(in), state.name());
            GateTesting.healthy(Startup.FEDERATION);
        }
        verifyNoInteractions(this.request);
    }

    @Test
    void aServingFederationLetsThePolicyCriterionDecide() {
        GateTesting.serving(Startup.FEDERATION);
        // No decision point is configured for token issuance here, so the policy criterion permits.
        org.junit.jupiter.api.Assertions.assertTrue(OIDFederationUtils.federationPolicy(this.criteria()));
    }
}
