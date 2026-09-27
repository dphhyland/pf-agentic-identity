package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.annotation.WebServlet;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

/**
 * Each surface's metadata names its own challenge endpoint, at the path that endpoint is mapped to, and never the
 * other's: the attester's two documents name {@code GET /federation/attestation/challenge}, the authorization
 * server's OP metadata in the Entity Configuration names {@code POST /federation/attestation-challenge}. The paths
 * are read off the servlets' {@code @WebServlet} mappings, so a moved servlet fails here rather than in a client.
 */
class ChallengeEndpointAdvertisementTest {
    private static final String ISSUER = "https://pf.example.com";

    private static String mapped(Class<?> servlet) {
        return servlet.getAnnotation(WebServlet.class).urlPatterns()[0];
    }

    private static final String AS_PATH = mapped(ClientAttestationChallengeServlet.class);
    private static final String CAS_PATH = mapped(AttestationIssuanceChallengeServlet.class);

    @Test
    void theTwoEndpointsAreTwoPaths() {
        assertNotEquals(AS_PATH, CAS_PATH);
    }

    /** CAS §5.1: {@code challenge_endpoint} is the "URL of the challenge endpoint (Section 4.1)" - the CAS's own. */
    @Test
    @Requirement("CAS §5.1")
    void theClientAttestationServiceDocumentNamesTheAttestersEndpoint() throws Exception {
        ClientAttestationServiceMetadataServlet servlet = new ClientAttestationServiceMetadataServlet();
        servlet.init(mock(ServletConfig.class));
        Map<String, Object> metadata = servlet.metadata(ISSUER);

        assertEquals(ISSUER + CAS_PATH, metadata.get("challenge_endpoint"));
        assertFalse(names(metadata, AS_PATH), "the authorization server's endpoint is not named");
    }

    @Test
    void theAttesterConfigurationNamesTheAttestersEndpoint() {
        Map<String, Object> metadata = AttesterConfigurationServlet.metadata(ISSUER, false, false);

        assertEquals(ISSUER + CAS_PATH, metadata.get("challenge_endpoint"));
        assertFalse(names(metadata, AS_PATH), "the authorization server's endpoint is not named");
    }

    @Test
    void theEntityConfigurationNamesTheAuthorizationServersEndpointOnly() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("trustAnchorIssuers")).thenReturn(ISSUER);
        FederationService federation = new FederationService(FederationConfiguration.fromServletConfig(config), signingKeys());
        String jwt = federation.createEntityConfigurationJwt(ISSUER);
        String payload = new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8);
        @SuppressWarnings("unchecked")
        Map<String, Object> metadata = (Map<String, Object>) JsonUtil.parseJson(payload).get("metadata");
        @SuppressWarnings("unchecked")
        Map<String, Object> openidProvider = (Map<String, Object>) metadata.get("openid_provider");

        assertEquals(ISSUER + AS_PATH, openidProvider.get("challenge_endpoint"));
        assertFalse(names(metadata, CAS_PATH), "the attester's endpoint is named nowhere in the Entity Configuration");
    }

    @Test
    void theWalkFindsAPathWhereverItIs() {
        assertEquals(true, names(Map.of("a", java.util.List.of(Map.of("b", ISSUER + CAS_PATH))), CAS_PATH));
        assertEquals(false, names(Map.of("a", java.util.List.of(1, ISSUER + AS_PATH)), CAS_PATH));
    }

    /**
     * Whether any string value in a parsed document, at any depth, names {@code path}. Walked rather than searched
     * as text, because the JSON writer may escape a solidus.
     */
    private static boolean names(Object value, String path) {
        if (value instanceof String text) {
            return text.contains(path);
        }
        if (value instanceof Map<?, ?> map) {
            return map.values().stream().anyMatch(v -> names(v, path));
        }
        if (value instanceof Iterable<?> list) {
            for (Object item : list) {
                if (names(item, path)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static SigningKeyProvider signingKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return "challenge-advertisement-test";
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
