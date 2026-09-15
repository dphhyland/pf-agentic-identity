package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

/**
 * Where the anchor's keys come from. OpenID Federation 1.0 §4 distributes a Trust Anchor's public
 * keys "in some secure out-of-band way" and uses them to verify ES[i-1], the anchor's Subordinate
 * Statement; §2.1 explicitly does not rely on Web PKI / TLS for signing keys. Until the {@link TrustAnchor} existed the validator read the anchor's keys from
 * its {@code /.well-known/openid-federation} over HTTPS, so whoever answered at that URL was the
 * anchor. Every case here holds the anchor's HTTPS surface and the configured keys apart, and asserts
 * that only the configured keys decide.
 */
class TrustChainValidatorAnchorKeyTest {
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

    private static String statement(PublicJsonWebKey signingKey, String iss, String sub, Map<String, Object> claims) throws Exception {
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

    /** What the anchor's host serves: an entity configuration under {@code servedKey}, and one subordinate statement. */
    private static Map<String, String> anchorHost(PublicJsonWebKey servedKey, String subject, String subordinateStatement) throws Exception {
        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", statement(servedKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(servedKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch")))));
        responses.put(fetchUrl(subject), subordinateStatement);
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
    @Requirement({"OIDFED §2.1", "OIDFED §4"})
    void aKeyTheAnchorPublishesOverHttpsIsNotTrustedUnlessTheOperatorConfiguredIt() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey configuredKey = ec("anchor-configured");
        PublicJsonWebKey servedKey = ec("anchor-served");

        // Whoever controls the anchor's hostname serves a self-consistent federation: an entity
        // configuration under servedKey and a subordinate statement signed with it. Before the
        // TrustAnchor existed this validated - the keys were read from that very response.
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of("jwks", jwks(leafKey), "authority_hints", List.of(ANCHOR)));
        String servedSubordinate = statement(servedKey, ANCHOR, LEAF, Map.of("jwks", jwks(leafKey)));
        Map<String, String> responses = anchorHost(servedKey, LEAF, servedSubordinate);
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);

        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(stub(responses, new ArrayList<>()), ANCHOR), TrustAnchor.of(ANCHOR, jwks(configuredKey)));

        Exception e = assertThrows(Exception.class, () -> validator.validate(List.of(), LEAF, LEAF));
        assertTrue(e.getMessage() == null || !e.getMessage().contains("no stub for"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §4")
    void aGenuineAnchorConfigurationDoesNotLendTrustToASubordinateStatementUnderAnotherKey() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");
        PublicJsonWebKey otherKey = ec("not-the-anchor");

        // The anchor's entity configuration verifies with the pinned key, so the gateway accepts its
        // fetch endpoint. The statement that endpoint returns is signed by a different key, and it is the
        // statement - ES[i-1] - that §4 says the anchor's keys must verify.
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of("jwks", jwks(leafKey), "authority_hints", List.of(ANCHOR)));
        String foreignSubordinate = statement(otherKey, ANCHOR, LEAF, Map.of("jwks", jwks(leafKey)));
        Map<String, String> responses = anchorHost(anchorKey, LEAF, foreignSubordinate);
        responses.put(LEAF + "/.well-known/openid-federation", leafConfig);

        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(stub(responses, new ArrayList<>()), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        Exception e = assertThrows(Exception.class, () -> validator.validate(List.of(), LEAF, LEAF));
        assertTrue(e.getMessage() == null || !e.getMessage().contains("no stub for"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §4")
    void aCompletePushedChainVerifiesAgainstTheConfiguredKeysWithoutTouchingTheAnchor() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of("jwks", jwks(leafKey), "authority_hints", List.of(ANCHOR)));
        String subordinate = statement(anchorKey, ANCHOR, LEAF, Map.of("jwks", jwks(leafKey)));

        List<String> fetched = new ArrayList<>();
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(stub(Map.of(), fetched), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        TrustChainValidationResult result = validator.validate(List.of(leafConfig, subordinate), LEAF, LEAF);

        assertEquals(ANCHOR, result.trustAnchorIssuer());
        assertEquals(LEAF, result.leafSubject());
        assertTrue(fetched.isEmpty(), "the anchor's statement is verified with configured keys; nothing needs fetching: " + fetched);
    }

    @Test
    @Requirement("OIDFED §4")
    void theAnchorsStatementAboutAnIntermediateIsVerifiedWithTheConfiguredKeys() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        PublicJsonWebKey configuredKey = ec("anchor-configured");
        PublicJsonWebKey servedKey = ec("anchor-served");

        // A legitimate three-level chain in every respect except one: the anchor's statement about
        // the intermediate is signed by the key its host serves, not the key the operator configured.
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of("jwks", jwks(leafKey), "authority_hints", List.of(INTERMEDIATE)));
        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String intermediateConfig = statement(intermediateKey, INTERMEDIATE, INTERMEDIATE, Map.of("jwks", jwks(intermediateKey), "authority_hints", List.of(ANCHOR)));
        String servedAboutIntermediate = statement(servedKey, ANCHOR, INTERMEDIATE, Map.of("jwks", jwks(intermediateKey)));
        // The anchor's entity configuration itself is genuine, so what is refused is the statement.
        Map<String, String> responses = anchorHost(configuredKey, INTERMEDIATE, servedAboutIntermediate);

        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(stub(responses, new ArrayList<>()), ANCHOR), TrustAnchor.of(ANCHOR, jwks(configuredKey)));

        Exception e = assertThrows(Exception.class,
                () -> validator.validate(List.of(leafConfig, intermediateAboutLeaf, intermediateConfig), LEAF, LEAF));
        assertTrue(e.getMessage() == null || !e.getMessage().contains("no stub for"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §3.1.1")
    void aSuperiorStatementWithoutJwksCannotVouchForTheStatementBelowIt() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        // Everything is signed by the right keys; the anchor's statement about the intermediate just
        // omits jwks. Without it nothing asserts the intermediate's keys, and the validator used to fill
        // the gap by fetching the intermediate's own configuration - which is the intermediate vouching
        // for itself.
        String leafConfig = statement(leafKey, LEAF, LEAF, Map.of("jwks", jwks(leafKey), "authority_hints", List.of(INTERMEDIATE)));
        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String intermediateConfig = statement(intermediateKey, INTERMEDIATE, INTERMEDIATE, Map.of("jwks", jwks(intermediateKey), "authority_hints", List.of(ANCHOR)));
        String anchorAboutIntermediateNoJwks = statement(anchorKey, ANCHOR, INTERMEDIATE, Map.of());
        Map<String, String> responses = anchorHost(anchorKey, INTERMEDIATE, anchorAboutIntermediateNoJwks);
        responses.put(INTERMEDIATE + "/.well-known/openid-federation", intermediateConfig);

        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(stub(responses, new ArrayList<>()), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> validator.validate(List.of(leafConfig, intermediateAboutLeaf, intermediateConfig), LEAF, LEAF));
        assertTrue(e.getMessage().contains("jwks"), e.getMessage());
    }
}
