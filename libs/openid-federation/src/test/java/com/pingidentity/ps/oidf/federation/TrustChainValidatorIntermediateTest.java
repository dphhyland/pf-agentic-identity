package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

/**
 * Three-level chains (leaf → intermediate → configured anchor) supplied by the caller. The anchor's
 * subordinate statement about the intermediate is the only thing that ties the intermediate's keys to
 * the anchor: it must be part of what is verified, and its {@code metadata_policy} must reach the
 * leaf. {@link TrustChainValidatorRejectionTest} covers two-level chains only, where the anchor's
 * statement is the last entry and is always verified.
 */
class TrustChainValidatorIntermediateTest {
    private static final String LEAF = "https://agent.example.com";
    private static final String INTERMEDIATE = "https://intermediate.example.com";
    private static final String ANCHOR = "https://anchor.example.com";

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    private static String statement(PublicJsonWebKey signingKey, String iss, String sub,
                                    Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600L));
        claims.forEach(c::setClaim);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setKeyIdHeaderValue(signingKey.getKeyId());
        return jws.getCompactSerialization();
    }

    private static String fetchUrl(String subject) {
        return ANCHOR + "/fetch?sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(ANCHOR, StandardCharsets.UTF_8);
    }

    /** The anchor's side of the federation: its entity configuration and its fetch endpoint. */
    private static Map<String, String> anchorResponses(PublicJsonWebKey anchorKey, String anchorAboutIntermediate) throws Exception {
        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", statement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch")))));
        responses.put(fetchUrl(INTERMEDIATE), anchorAboutIntermediate);
        return responses;
    }

    private static HttpGetClient stub(Map<String, String> responses, List<String> fetched) {
        return (url, accept) -> {
            fetched.add(url);
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };
    }

    @Test
    void anIntermediateWhoseKeysTheAnchorNeverVouchedForIsRejected() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");
        PublicJsonWebKey realIntermediateKey = ec("intermediate-real");
        PublicJsonWebKey forgedIntermediateKey = ec("intermediate-forged");

        // The anchor genuinely lists the intermediate as a subordinate, vouching for its REAL key ...
        String anchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE, Map.of("jwks", jwks(realIntermediateKey)));
        // ... and the intermediate's real entity configuration is published under that key.
        String realIntermediateConfig = statement(realIntermediateKey, INTERMEDIATE, INTERMEDIATE, Map.of(
                "jwks", jwks(realIntermediateKey), "authority_hints", List.of(ANCHOR)));

        // The caller supplies a chain in which "the intermediate" is impersonated with a key of the
        // caller's own choosing: a self-signed entity configuration under the forged key, a subordinate
        // statement about the leaf signed with it, and the leaf itself. The anchor's own statement about
        // the intermediate is deliberately left out of the chain.
        String forgedIntermediateConfig = statement(forgedIntermediateKey, INTERMEDIATE, INTERMEDIATE, Map.of(
                "jwks", jwks(forgedIntermediateKey), "authority_hints", List.of(ANCHOR)));
        String forgedAboutLeaf = statement(forgedIntermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey), "authority_hints", List.of(INTERMEDIATE)));

        Map<String, String> responses = anchorResponses(anchorKey, anchorAboutIntermediate);
        responses.put(INTERMEDIATE + "/.well-known/openid-federation", realIntermediateConfig);
        List<String> fetched = new ArrayList<>();
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(stub(responses, fetched), ANCHOR), ANCHOR);

        Exception e = assertThrows(Exception.class,
                () -> validator.validate(List.of(leafConfig, forgedAboutLeaf, forgedIntermediateConfig), LEAF, LEAF));
        // Every URL the walk needed was stubbed: a refusal must come from verification, not from a
        // missing fixture.
        assertFalse(e.getMessage() != null && e.getMessage().contains("no stub for"), e.getMessage());
    }

    @Test
    void theAnchorsPolicyOnItsSubordinateStatementConstrainsTheLeafThroughAnIntermediate() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");

        // The anchor's statement about the intermediate carries the policy. The intermediate's own
        // statement about the leaf carries none, so anything narrowing the leaf came from the anchor.
        String anchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE, Map.of(
                "jwks", jwks(intermediateKey),
                "metadata_policy", Map.of("oauth_client", Map.of(
                        "grant_types", Map.of("subset_of", List.of("authorization_code"))))));
        String intermediateConfig = statement(intermediateKey, INTERMEDIATE, INTERMEDIATE, Map.of(
                "jwks", jwks(intermediateKey), "authority_hints", List.of(ANCHOR)));
        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey),
                "authority_hints", List.of(INTERMEDIATE),
                "metadata", Map.of("oauth_client", Map.of(
                        "grant_types", List.of("authorization_code", "client_credentials"),
                        "client_name", "Payment Agent"))));

        Map<String, String> responses = anchorResponses(anchorKey, anchorAboutIntermediate);
        List<String> fetched = new ArrayList<>();
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(stub(responses, fetched), ANCHOR), ANCHOR);

        TrustChainValidationResult result = validator.validate(
                List.of(leafConfig, intermediateAboutLeaf, intermediateConfig), LEAF, LEAF);

        assertEquals(ANCHOR, result.trustAnchorIssuer());
        assertEquals(LEAF, result.leafSubject());
        assertEquals(List.of("authorization_code"), result.metadataFor("oauth_client").get("grant_types"));
        assertEquals("Payment Agent", result.metadataFor("oauth_client").get("client_name"));
        assertTrue(result.isPoliced("oauth_client"));
        // The pushed chain already carried the intermediate's entity configuration; the anchor's
        // statement about it was fetched from the anchor, and nothing was fetched from the intermediate.
        assertTrue(fetched.contains(fetchUrl(INTERMEDIATE)), fetched.toString());
        assertFalse(fetched.contains(INTERMEDIATE + "/.well-known/openid-federation"), fetched.toString());
    }
}
