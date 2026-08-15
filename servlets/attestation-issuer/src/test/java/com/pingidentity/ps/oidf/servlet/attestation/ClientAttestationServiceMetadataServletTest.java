/*
 * Tests for the /.well-known/client-attestation-service discovery metadata document.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators;
import com.pingidentity.ps.oidf.issuer.SpiffeInstanceAttestationValidator;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.issuer.WalletInstanceAttestationValidator;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ClientAttestationServiceMetadataServletTest {

    private static final String ISSUER = "https://attester.example.com";

    @AfterEach
    void clearProps() {
        System.clearProperty("oidf.cimd.trust.bundles");
        System.clearProperty("oidf.attestation.custom.claims.required");
        System.clearProperty("oidf.attestation.custom.claims.supported");
    }

    @Test
    void defaultsPublishEndpointsAndClaimContract() throws Exception {
        Map<String, Object> m = initialized(Map.of()).metadata(ISSUER);
        assertEquals(ISSUER, m.get("issuer"));
        assertEquals(ISSUER + "/federation/attestation", m.get("attestation_endpoint"));
        assertEquals(ISSUER + "/federation/attestation-challenge", m.get("challenge_endpoint"));
        assertEquals(false, m.get("challenge_required"));
        // The built-in registry (InstanceAttestationValidators.defaults()) covers every cloud-platform
        // evidence type PLUS the wallet placeholder; every cloud type reports format "spiffe", so the
        // distinct families are spiffe + wallet even though "wallet" trust is unconfigured here.
        assertEquals(List.of("spiffe", "wallet"), m.get("instance_attestation_formats_supported"));
        assertEquals(List.of("registration"), m.get("client_metadata_sources_supported"));
        assertEquals(List.of("RS256", "PS256", "ES256"), m.get("attestation_signing_alg_values_supported"));
        assertEquals(List.of("client_id", "instance_key", "instance_attestation", "proof"),
                m.get("request_parameters_required"));
        assertEquals(List.of("aud", "jti"), m.get("proof_claims_required"));
        assertEquals(List.of("iss", "sub", "iat", "exp", "cnf", "workload"), m.get("attestation_claims_issued"));
        assertEquals(List.of("authorization_details"), m.get("attestation_claims_optional"));
        assertNull(m.get("custom_claims_required"));
        assertNull(m.get("custom_claims_supported"));
        assertEquals("reject", m.get("narrowing_behavior"));
        @SuppressWarnings("unchecked")
        List<String> proofAlgs = (List<String>) m.get("proof_signing_alg_values_supported");
        assertTrue(proofAlgs.contains("ES256") && proofAlgs.contains("RS256"));
    }

    @Test
    void challengeRequiredAddsChallengeToProofClaims() throws Exception {
        Map<String, Object> m = initialized(Map.of("challengeRequired", "true")).metadata(ISSUER);
        assertEquals(true, m.get("challenge_required"));
        assertEquals(List.of("aud", "jti", "challenge"), m.get("proof_claims_required"));
    }

    @Test
    void challengeEndpointCanBeDisabled() throws Exception {
        Map<String, Object> m = initialized(Map.of("challengeEndpointEnabled", "false")).metadata(ISSUER);
        assertFalse(m.containsKey("challenge_endpoint"));
    }

    @Test
    void customClaimsInitParamsAreAdvertised() throws Exception {
        Map<String, Object> m = initialized(Map.of(
                "customClaimsRequired", "deployment_id, region",
                "customClaimsSupported", "deployment_id, region, build_digest")).metadata(ISSUER);
        assertEquals(List.of("deployment_id", "region"), m.get("custom_claims_required"));
        assertEquals(List.of("deployment_id", "region", "build_digest"), m.get("custom_claims_supported"));
    }

    @Test
    void customClaimsFallBackToEnvironment() throws Exception {
        System.setProperty("oidf.attestation.custom.claims.required", "deployment_id");
        Map<String, Object> m = initialized(Map.of()).metadata(ISSUER);
        assertEquals(List.of("deployment_id"), m.get("custom_claims_required"));
    }

    @Test
    void formatsFollowRegisteredValidators() throws Exception {
        ClientAttestationServiceMetadataServlet servlet = initialized(Map.of());
        servlet.setInstanceValidators(new InstanceAttestationValidators(List.of(
                new SpiffeInstanceAttestationValidator(),
                new WalletInstanceAttestationValidator(new StaticAttesterKeyResolver(Map.of())))));
        assertEquals(List.of("spiffe", "wallet"),
                servlet.metadata(ISSUER).get("instance_attestation_formats_supported"));
    }

    @Test
    void cimdSourceAdvertisedWhenBundlesConfigured() throws Exception {
        System.setProperty("oidf.cimd.trust.bundles", "{\"banking.demo\":{\"keys\":[]}}");
        Map<String, Object> m = initialized(Map.of()).metadata(ISSUER);
        assertEquals(List.of("cimd", "registration"), m.get("client_metadata_sources_supported"));
    }

    @Test
    void signingAlgListIsOverridable() throws Exception {
        Map<String, Object> m = initialized(Map.of("attestationSigningAlgValuesSupported", "ES256"))
                .metadata(ISSUER);
        assertEquals(List.of("ES256"), m.get("attestation_signing_alg_values_supported"));
    }

    private static ClientAttestationServiceMetadataServlet initialized(Map<String, String> initParams)
            throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        initParams.forEach((k, v) -> when(config.getInitParameter(k)).thenReturn(v));
        ClientAttestationServiceMetadataServlet servlet = new ClientAttestationServiceMetadataServlet();
        servlet.init(config);
        return servlet;
    }
}
