package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.jwk.EcJwkGenerator;

/**
 * Regression coverage for the Phase 0.2 fix: {@code metadata_policy} is now actually applied while
 * walking a trust chain, not just parsed and discarded. Before this, a trust anchor's (or an
 * intermediate's) {@code metadata_policy} on a subordinate statement had no effect at all — the
 * leaf's self-published metadata was returned as-is.
 */
class TrustChainValidatorPolicyTest {
    private static final String LEAF = "https://agent.example.com";
    private static final String ANCHOR = "https://anchor.example.com";

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(key.toParams(org.jose4j.jwk.JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    private static String entityStatement(PublicJsonWebKey signingKey, String iss, String sub,
                                          Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600L));
        claims.forEach(c::setClaim);
        org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setKeyIdHeaderValue(signingKey.getKeyId());
        return jws.getCompactSerialization();
    }

    /** Builds a two-hop chain (leaf directly under the anchor) with the anchor's subordinate statement
     *  about the leaf carrying the given {@code metadata_policy.oauth_client}, and validates it. */
    private static TrustChainValidationResult validateWithAnchorPolicy(PublicJsonWebKey leafKey,
            PublicJsonWebKey anchorKey, Map<String, Object> leafOauthClient,
            Map<String, Object> anchorPolicyForOauthClient) throws Exception {
        String leafConfig = entityStatement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey),
                "authority_hints", List.of(ANCHOR),
                "metadata", Map.of("oauth_client", leafOauthClient)));
        String anchorConfig = entityStatement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        Map<String, Object> subordinateClaims = new HashMap<>(Map.of("jwks", jwks(leafKey)));
        if (!anchorPolicyForOauthClient.isEmpty()) {
            subordinateClaims.put("metadata_policy", Map.of("oauth_client", anchorPolicyForOauthClient));
        }
        String subordinate = entityStatement(anchorKey, ANCHOR, LEAF, subordinateClaims);

        Map<String, String> responses = new HashMap<>();
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig);
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(LEAF, StandardCharsets.UTF_8) + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8), subordinate);
        HttpGetClient http = (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };

        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        return validator.validate(List.of(), LEAF, LEAF);
    }

    @Test
    void anchorSubsetOfPolicyNarrowsLeafMetadata() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        Map<String, Object> leafOauthClient = Map.of(
                "grant_types", List.of("authorization_code", "client_credentials", "refresh_token"),
                "client_name", "Payment Agent");
        Map<String, Object> anchorPolicy = Map.of(
                "grant_types", Map.of("subset_of", List.of("authorization_code", "client_credentials")));

        TrustChainValidationResult result = validateWithAnchorPolicy(leafKey, anchorKey, leafOauthClient, anchorPolicy);

        // refresh_token was stripped by the anchor's subset_of policy.
        assertEquals(List.of("authorization_code", "client_credentials"),
                result.metadataFor("oauth_client").get("grant_types"));
        // Untouched fields pass through unchanged.
        assertEquals("Payment Agent", result.metadataFor("oauth_client").get("client_name"));
    }

    @Test
    void noAncestorPolicyLeavesMetadataUnchanged() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        Map<String, Object> leafOauthClient = Map.of(
                "grant_types", List.of("authorization_code", "client_credentials", "refresh_token"));

        TrustChainValidationResult result = validateWithAnchorPolicy(leafKey, anchorKey, leafOauthClient, Map.of());

        assertEquals(leafOauthClient.get("grant_types"), result.metadataFor("oauth_client").get("grant_types"));
    }

    @Test
    void anchorPolicyDisjointFromLeafMetadataFailsClosed() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        Map<String, Object> leafOauthClient = Map.of("grant_types", List.of("authorization_code"));
        // The anchor permits only "implicit" — nothing the leaf actually claims survives.
        Map<String, Object> anchorPolicy = Map.of("grant_types", Map.of("subset_of", List.of("implicit")));

        MetadataPolicy.PolicyException e = assertThrows(MetadataPolicy.PolicyException.class,
                () -> validateWithAnchorPolicy(leafKey, anchorKey, leafOauthClient, anchorPolicy));
        assertTrue(e.getMessage().contains("grant_types"), e.getMessage());
    }
}
