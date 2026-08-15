package com.pingidentity.ps.oidf.federation;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttestationMetadataConfigTest {

    @Test
    void defaultsAdvertiseOnlyThePlainJwtFormat() {
        AttestationMetadataConfig defaults = AttestationMetadataConfig.defaults();
        assertEquals(java.util.List.of("jwt"), defaults.clientAttestationFormatsSupported());
        assertTrue(defaults.tokenEndpointAuthMethodsSupported().contains("attest_jwt_client_auth"));
        assertTrue(defaults.tokenEndpointAuthMethodsSupported().contains("attest_jwt_client_auth_dpop"));
    }

    @Test
    void defaultsAdvertiseBothPopMethods() {
        AttestationMetadataConfig defaults = AttestationMetadataConfig.defaults();
        assertEquals(java.util.List.of("attestation_pop_jwt", "dpop_combined"),
                defaults.clientAttestationPopMethodsSupported());
    }
}
