package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import com.pingidentity.ps.oidf.conformance.Requirement;
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
    @Requirement("ABCA-10 §8")
    void emptyPopMethodsListIsOmittedNotEmitted() throws Exception {
        AttestationMetadataConfig noMethods = new AttestationMetadataConfig(
                List.of("private_key_jwt"), List.of("RS256"), List.of("ES256"), List.of("ES256"),
                List.of("jwt"), List.of(), true);
        Map<String, Object> openidProvider = openidProviderMetadata(noMethods);
        assertFalse(openidProvider.containsKey("client_attestation_pop_methods_supported"),
                "draft-10 §8: the array MUST NOT be empty when the parameter is present");
    }

    /**
     * §5.1.3 and §5.1.4: every OpenID Connect Discovery / RFC 8414 parameter applies to these blocks, so they are the OP's
     * own discovery documents - what the suite checked, and found missing, was jwks_uri and the three REQUIRED
     * *_supported lists - with what federation and attestation add on top, and the issuer always the entity's.
     */
    @Test
    @Requirement({"OIDFED §5.1.3(2)", "OIDFED §5.1.4(2)"})
    void theProviderMetadataIsTheOpsOwnDiscoveryWithWhatFederationAdds() throws Exception {
        ProviderMetadata discovery = (type, issuer) -> "openid_provider".equals(type)
                ? Map.of("issuer", "https://elsewhere.example", "jwks_uri", ISSUER + "/pf/JWKS", "response_types_supported", List.of("code"),
                        "subject_types_supported", List.of("public"), "id_token_signing_alg_values_supported", List.of("RS256"),
                        "authorization_endpoint", ISSUER + "/custom/authorize", "client_registration_types_supported", List.of("stale"))
                : Map.of("introspection_endpoint", ISSUER + "/as/introspect.oauth2");
        FederationConfiguration configuration = new FederationConfiguration(
                List.of(ISSUER), List.of(), null, false, false, null, null, null, 0, "RS256", AttestationMetadataConfig.defaults());
        FederationService service = FederationService.builder(configuration, testSigningKeys()).providerMetadata(discovery).build();

        Map<String, Object> metadata = metadataOf(service.createEntityConfigurationJwt(ISSUER));
        @SuppressWarnings("unchecked")
        Map<String, Object> op = (Map<String, Object>) metadata.get("openid_provider");
        @SuppressWarnings("unchecked")
        Map<String, Object> as = (Map<String, Object>) metadata.get("oauth_authorization_server");

        assertEquals(ISSUER + "/pf/JWKS", op.get("jwks_uri"));
        assertEquals(List.of("public"), op.get("subject_types_supported"));
        assertEquals(ISSUER, op.get("issuer"), "the entity's issuer, whatever the document says");
        assertEquals(ISSUER + "/custom/authorize", op.get("authorization_endpoint"), "the document's endpoints over derived ones");
        assertEquals(List.of("automatic", "explicit"), op.get("client_registration_types_supported"), "what federation says of itself wins");
        assertEquals(ISSUER + "/as/introspect.oauth2", as.get("introspection_endpoint"));
        assertEquals(ISSUER + "/as/token.oauth2", as.get("token_endpoint"), "an endpoint the document leaves out is still there");
    }

    private static Map<String, Object> metadataOf(String jwt) throws Exception {
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) JsonUtil.parseJson(payload).get("metadata");
        return metadata;
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
