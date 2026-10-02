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
                List.of("private_key_jwt", "attest_jwt_client_auth"), List.of("RS256"), List.of("ES256"), List.of("ES256"),
                List.of("jwt"), List.of(), false);
        Map<String, Object> openidProvider = openidProviderMetadata(noMethods);
        assertFalse(openidProvider.containsKey("client_attestation_pop_methods_supported"),
                "draft-10 §8: the array MUST NOT be empty when the parameter is present");
        assertEquals(List.of("RS256"), openidProvider.get("client_attestation_signing_alg_values_supported"), "attestation is advertised");
        assertFalse(openidProvider.containsKey("challenge_endpoint"), "the challenge endpoint is not enabled");
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
                List.of(ISSUER), List.of(), false, false, null, null, null, 0, "RS256", AttestationMetadataConfig.defaults());
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

    /** The attestation members, as {@link AttestationMetadataConfig#extend} names them, that {@code block} carries. */
    static Map<String, Object> attestationMembers(Map<String, Object> block) {
        Map<String, Object> members = new java.util.LinkedHashMap<>();
        for (String name : List.of("client_attestation_signing_alg_values_supported", "client_attestation_pop_signing_alg_values_supported",
                "challenge_endpoint")) {
            if (block.containsKey(name)) {
                members.put(name, block.get(name));
            }
        }
        @SuppressWarnings("unchecked")
        List<String> methods = (List<String>) block.getOrDefault("token_endpoint_auth_methods_supported", List.of());
        members.put("attestation_methods", methods.stream().filter(AttestationMetadataConfig.ATTESTATION_METHODS::contains).toList());
        return members;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> block(FederationService service, String type) throws Exception {
        return (Map<String, Object>) metadataOf(service.createEntityConfigurationJwt(ISSUER)).get(type);
    }

    /**
     * ABCA-10 §6.1 (read 2026-10-01): an authorization server that supports RFC 8414 metadata "MUST signal support for the
     * challenge endpoint by including the metadata entry challenge_endpoint". oauth_authorization_server is RFC 8414
     * metadata, so it carries the same attestation members as openid_provider (F-0115), and PingFederate's own members
     * as PingFederate gave them.
     */
    @Test
    @Requirement({"ABCA-10 §6.1", "ABCA-10 §8"})
    void bothMetadataBlocksCarryTheSameAttestationMembers() throws Exception {
        ProviderMetadata discovery = (type, issuer) -> Map.of("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "private_key_jwt"),
                "dpop_signing_alg_values_supported", List.of("RS256", "ES384"));
        FederationService service = FederationService.builder(new FederationConfiguration(List.of(ISSUER), List.of(), false, false, null,
                null, null, 0, "RS256", AttestationMetadataConfig.defaults()), testSigningKeys()).providerMetadata(discovery).build();
        Map<String, Object> op = block(service, "openid_provider");
        Map<String, Object> as = block(service, "oauth_authorization_server");

        assertEquals(attestationMembers(op), attestationMembers(as));
        assertEquals(List.of("attest_jwt_client_auth", "attest_jwt_client_auth_dpop"), attestationMembers(as).get("attestation_methods"));
        assertEquals(ISSUER + "/federation/attestation-challenge", as.get("challenge_endpoint"));
        assertEquals(List.of("client_secret_basic", "private_key_jwt", "attest_jwt_client_auth", "attest_jwt_client_auth_dpop"),
                as.get("token_endpoint_auth_methods_supported"), "PingFederate's methods first, extended");
        assertEquals(List.of("RS256", "ES384"), as.get("dpop_signing_alg_values_supported"), "PingFederate's DPoP list kept");
        assertFalse(as.containsKey("client_attestation_pop_methods_supported"),
                "ABCA-10 §7.6: without none it asks every client for an attestation (F-0412)");
    }

    /** S9b: ATTESTATION_AUTH switched off advertises no attestation member in either block. */
    @Test
    void switchedOffNeitherBlockCarriesAnAttestationMember() throws Exception {
        FederationService service = FederationService.builder(AttestationMetadataConfigs.configuration(ISSUER, AttestationMetadataConfigs.switchedOff()),
                testSigningKeys()).build();
        for (String type : List.of("openid_provider", "oauth_authorization_server")) {
            Map<String, Object> blockOf = block(service, type);
            assertEquals(Map.of("attestation_methods", List.of()), attestationMembers(blockOf), type);
        }
        assertEquals(List.of("private_key_jwt"), block(service, "openid_provider").get("token_endpoint_auth_methods_supported"));
        assertFalse(block(service, "oauth_authorization_server").containsKey("token_endpoint_auth_methods_supported"),
                "nothing added to a block that had none");

        AttestationMetadataConfig attestationOnly = new AttestationMetadataConfig(List.of("attest_jwt_client_auth"), List.of("ES256"),
                List.of("ES256"), List.of("ES256"), List.of("jwt"), List.of(), true, true);
        assertFalse(block(FederationService.builder(AttestationMetadataConfigs.configuration(ISSUER, attestationOnly), testSigningKeys()).build(),
                "openid_provider").containsKey("token_endpoint_auth_methods_supported"), "never an empty list");
    }

    @Test
    void aMethodListThatCannotBeExtendedIsPublishedAsGiven() throws Exception {
        ProviderMetadata odd = (type, issuer) -> Map.of("token_endpoint_auth_methods_supported", "private_key_jwt");
        FederationService service = FederationService.builder(AttestationMetadataConfigs.configuration(ISSUER, AttestationMetadataConfig.defaults()),
                testSigningKeys()).providerMetadata(odd).build();
        Map<String, Object> as = block(service, "oauth_authorization_server");

        assertEquals("private_key_jwt", as.get("token_endpoint_auth_methods_supported"));
        assertFalse(as.containsKey("challenge_endpoint"), "the set is added whole or not at all");
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
                List.of(ISSUER), List.of(), false, false, null, null, null, 0, "RS256", attestationMetadata);
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
