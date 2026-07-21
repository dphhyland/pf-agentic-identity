package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.common.SigningKeyProvider;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Asserts the entity configuration's {@code openid_provider} metadata advertises the
 * attestation-based client-auth capabilities, including the draft-10
 * {@code client_attestation_pop_methods_supported} parameter.
 */
class FederationServiceMetadataTest {

    private static final String ISSUER = "https://as.example.com";

    @Test
    void entityConfigurationAdvertisesPopMethods() throws Exception {
        Map<String, Object> openidProvider = openidProviderMetadata(AttestationMetadataConfig.defaults());
        assertEquals(List.of("attestation_pop_jwt", "dpop_combined"),
                openidProvider.get("client_attestation_pop_methods_supported"));
        assertEquals(ISSUER + "/federation/attestation-challenge", openidProvider.get("challenge_endpoint"));
    }

    @Test
    void emptyPopMethodsListIsOmittedNotEmitted() throws Exception {
        AttestationMetadataConfig noMethods = new AttestationMetadataConfig(
                List.of("private_key_jwt"), List.of("RS256"), List.of("ES256"), List.of("ES256"),
                List.of("jwt"), List.of(), true);
        Map<String, Object> openidProvider = openidProviderMetadata(noMethods);
        assertFalse(openidProvider.containsKey("client_attestation_pop_methods_supported"),
                "draft-10 §8: the array MUST NOT be empty when the parameter is present");
    }

    private static Map<String, Object> openidProviderMetadata(AttestationMetadataConfig attestationMetadata)
            throws Exception {
        FederationConfiguration configuration = new FederationConfiguration(
                List.of(ISSUER), List.of(), null, false, false, null, null, null, 0, "RS256", attestationMetadata);
        FederationService service = new FederationService(configuration, testSigningKeys());
        String jwt = service.createEntityConfigurationJwt(ISSUER);
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        Map<String, Object> claims = JsonUtil.parseJson(payload);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) claims.get("metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> openidProvider = (Map<String, Object>) metadata.get("openid_provider");
        return openidProvider;
    }

    private static SigningKeyProvider testSigningKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return "test-signing-key";
            }

            @Override
            public RSAPrivateKey privateKey() {
                return (RSAPrivateKey) keyPair.getPrivate();
            }

            @Override
            public RSAPublicKey publicKey() {
                return (RSAPublicKey) keyPair.getPublic();
            }
        };
    }
}
