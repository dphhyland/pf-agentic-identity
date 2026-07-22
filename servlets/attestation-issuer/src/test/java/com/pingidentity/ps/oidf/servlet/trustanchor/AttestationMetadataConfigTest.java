package com.pingidentity.ps.oidf.servlet.trustanchor;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttestationMetadataConfigTest {

    @Test
    void defaultsAdvertiseBothAttestationFormats() {
        AttestationMetadataConfig defaults = AttestationMetadataConfig.defaults();
        assertEquals(java.util.List.of("jwt"), defaults.clientAttestationFormatsSupported());
        assertTrue(defaults.tokenEndpointAuthMethodsSupported().contains("attest_jwt_client_auth"));
        assertTrue(defaults.tokenEndpointAuthMethodsSupported().contains("attest_jwt_client_auth_dpop"));
    }
}
