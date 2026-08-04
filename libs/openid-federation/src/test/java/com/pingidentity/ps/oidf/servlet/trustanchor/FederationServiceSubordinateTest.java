package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.common.HttpGetClient;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Asserts the trust anchor's subordinate statements vouch for the subordinate's OWN keys
 * (fetched from its entity configuration), not the anchor's — the property chain verification
 * depends on — and that a configured attester JWKS is published under
 * {@code metadata.oauth_client_attester.jwks}.
 */
class FederationServiceSubordinateTest {

    private static final String ANCHOR = "https://anchor.example.com";
    private static final String SUBORDINATE = "https://leaf.example.com";

    @Test
    void subordinateStatementEmbedsTheSubordinatesOwnKeys() throws Exception {
        SigningKeyProvider anchorKeys = testSigningKeys("anchor-key");
        SigningKeyProvider leafKeys = testSigningKeys("leaf-key");

        FederationConfiguration leafConfig = new FederationConfiguration(
                List.of(ANCHOR), List.of(), null, false, false, null, null, null, 0, "RS256", null);
        String leafSelfConfig = new FederationService(leafConfig, leafKeys).createEntityConfigurationJwt(SUBORDINATE);

        HttpGetClient fetcher = (url, accept) -> {
            assertEquals(SUBORDINATE + "/.well-known/openid-federation", url);
            return leafSelfConfig;
        };
        FederationConfiguration anchorConfig = new FederationConfiguration(
                List.of(ANCHOR), List.of(ANCHOR, SUBORDINATE), null, false, false, null, null, null, 0, "RS256", null);
        FederationService anchor = new FederationService(anchorConfig, anchorKeys, fetcher);

        Map<String, Object> claims = payload(anchor.createEntityStatement(SUBORDINATE, null, ANCHOR));
        assertEquals(ANCHOR, claims.get("iss"));
        assertEquals(SUBORDINATE, claims.get("sub"));
        assertEquals("leaf-key", firstKid(claims), "subordinate statement must carry the subordinate's key, not the anchor's");
        assertFalse(claims.containsKey("metadata"), "subordinate statements carry no metadata; the leaf statement does");
        assertFalse(claims.containsKey("authority_hints"), "authority_hints belongs on entity configurations only");
    }

    @Test
    void selfStatementStillEmbedsOwnKeysAndMetadata() throws Exception {
        SigningKeyProvider anchorKeys = testSigningKeys("anchor-key");
        FederationConfiguration anchorConfig = new FederationConfiguration(
                List.of(ANCHOR), List.of(ANCHOR), null, false, false, null, null, null, 0, "RS256", null);
        FederationService anchor = new FederationService(anchorConfig, anchorKeys);

        Map<String, Object> claims = payload(anchor.createEntityStatement(ANCHOR, null, ANCHOR));
        assertEquals("anchor-key", firstKid(claims));
        assertTrue(claims.containsKey("metadata"));
    }

    @Test
    void unknownSubjectIsRejected() throws Exception {
        // A subject this federation doesn't recognise is "not found" (404), not a malformed request
        // (400) — the two used to collapse onto the same IllegalArgumentException, which is exactly
        // what OpenIdFederationServlet could not tell apart.
        SigningKeyProvider anchorKeys = testSigningKeys("anchor-key");
        FederationConfiguration anchorConfig = new FederationConfiguration(
                List.of(ANCHOR), List.of(ANCHOR), null, false, false, null, null, null, 0, "RS256", null);
        FederationService anchor = new FederationService(anchorConfig, anchorKeys, (url, accept) -> {
            throw new AssertionError("must not fetch for an unknown subject");
        });
        FederationEntityNotFoundException e = assertThrows(FederationEntityNotFoundException.class,
                () -> anchor.createEntityStatement("https://stranger.example.com", null, ANCHOR));
        assertTrue(e.getMessage().contains("https://stranger.example.com"), e.getMessage());
    }

    @Test
    void configuredAttesterJwksIsPublishedInEntityConfiguration() throws Exception {
        SigningKeyProvider anchorKeys = testSigningKeys("anchor-key");
        String attesterJwks = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"mock-attester-1\",\"k\":\"c2VjcmV0\"}]}";
        FederationConfiguration anchorConfig = new FederationConfiguration(
                List.of(ANCHOR), List.of(ANCHOR), null, false, false, null, null, null, 0, "RS256", null, attesterJwks);
        FederationService anchor = new FederationService(anchorConfig, anchorKeys);

        Map<String, Object> claims = payload(anchor.createEntityConfigurationJwt(ANCHOR));
        Map<String, Object> metadata = cast(claims.get("metadata"));
        Map<String, Object> attester = cast(metadata.get("oauth_client_attester"));
        assertNotNull(attester, "entity configuration must publish the co-hosted attester's keys");
        Map<String, Object> jwks = cast(attester.get("jwks"));
        List<?> keys = (List<?>) jwks.get("keys");
        assertEquals("mock-attester-1", cast(keys.get(0)).get("kid"));
    }

    private static Map<String, Object> payload(String jwt) throws Exception {
        return JsonUtil.parseJson(new String(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]), StandardCharsets.UTF_8));
    }

    private static String firstKid(Map<String, Object> claims) {
        Map<String, Object> jwks = cast(claims.get("jwks"));
        List<?> keys = (List<?>) jwks.get("keys");
        return (String) cast(keys.get(0)).get("kid");
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> cast(Object value) {
        return (Map<String, Object>) value;
    }

    private static SigningKeyProvider testSigningKeys(String keyId) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return keyId;
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
