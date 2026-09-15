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
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

/**
 * Three-level chains: leaf → intermediate → anchor, with the chain caller-supplied (the shape
 * {@code POST /federation/register}, the {@code client_assertion} {@code trust_chain} header and the
 * attestation {@code trust_chain} header all arrive in).
 *
 * <p>OpenID Federation 1.0 §10.2 requires that, for each {@code j}, the signature of {@code ES[j]}
 * validates with a key in {@code ES[j+1]["jwks"]}, and that the statement about the intermediate
 * validates with a key of the Trust Anchor. The anchor's subordinate statement about the intermediate
 * is therefore the only thing that connects the intermediate's keys to the anchor. A validator that
 * merely notices such a statement exists — without verifying its signature against the anchor's keys
 * and without checking the intermediate's keys against it — lets anyone who can write three
 * self-consistent JWTs resolve a "valid" chain to the configured anchor. The existing three-level
 * coverage ({@link PackageChainValidationTest}, {@link LiveChainValidationTest}) is fixture-gated and
 * always supplies a genuine anchor statement, so it never asked this question.
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

    private static String fetchUrl(String issuer, String subject) {
        return issuer + "/fetch?sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(issuer, StandardCharsets.UTF_8);
    }

    private static HttpGetClient serving(Map<String, String> responses) {
        return (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };
    }

    /** The one statement every case shares: the anchor's own configuration, signed with its real key. */
    private static String anchorConfig(PublicJsonWebKey anchorKey) throws Exception {
        return statement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
    }

    private static String leafConfig(PublicJsonWebKey leafKey) throws Exception {
        return statement(leafKey, LEAF, LEAF, Map.of(
                "jwks", jwks(leafKey),
                "authority_hints", List.of(INTERMEDIATE),
                "metadata", Map.of("openid_relying_party", Map.of("client_name", "self-published"))));
    }

    private static String intermediateConfig(PublicJsonWebKey intermediateKey) throws Exception {
        return statement(intermediateKey, INTERMEDIATE, INTERMEDIATE, Map.of(
                "jwks", jwks(intermediateKey),
                "authority_hints", List.of(ANCHOR),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", INTERMEDIATE + "/fetch"))));
    }

    /**
     * An attacker who is not in the federation at all: they invent an intermediate, sign a statement
     * about the leaf with it, and forge the anchor's statement about that intermediate with a key of
     * their own. Every JWT is internally consistent; none of them is connected to the anchor.
     */
    @Test
    @Requirement("OIDFED §10.2")
    void aForgedAnchorStatementAboutAnIntermediateIsRejected() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey fakeIntermediateKey = ec("fake-intermediate-1");
        PublicJsonWebKey attackerKey = ec("not-the-anchors-key");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String intermediateAboutLeaf = statement(fakeIntermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        // iss says "anchor"; the signature says otherwise.
        String forgedAnchorAboutIntermediate = statement(attackerKey, ANCHOR, INTERMEDIATE,
                Map.of("jwks", jwks(fakeIntermediateKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        // The anchor has never heard of this intermediate: a fetch for it fails.
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(serving(responses), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        List<String> chain = List.of(leafConfig(leafKey), intermediateAboutLeaf,
                intermediateConfig(fakeIntermediateKey), forgedAnchorAboutIntermediate);
        assertThrows(Exception.class, () -> validator.validate(chain, LEAF, LEAF),
                "a chain whose only link to the anchor is a statement the anchor did not sign must not resolve");
    }

    /**
     * The same forgery, but the caller leaves the anchor statement out and lets the validator fetch it
     * — from an endpoint the attacker answers. Fetched bytes are no more trustworthy than supplied ones;
     * only the anchor's signature is.
     */
    @Test
    @Requirement("OIDFED §10.2")
    void aFetchedAnchorStatementIsVerifiedNotMerelyReceived() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey fakeIntermediateKey = ec("fake-intermediate-1");
        PublicJsonWebKey attackerKey = ec("not-the-anchors-key");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String intermediateAboutLeaf = statement(fakeIntermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String forgedAnchorAboutIntermediate = statement(attackerKey, ANCHOR, INTERMEDIATE,
                Map.of("jwks", jwks(fakeIntermediateKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        responses.put(fetchUrl(ANCHOR, INTERMEDIATE), forgedAnchorAboutIntermediate);
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(serving(responses), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        List<String> chain = List.of(leafConfig(leafKey), intermediateAboutLeaf, intermediateConfig(fakeIntermediateKey));
        assertThrows(Exception.class, () -> validator.validate(chain, LEAF, LEAF));
    }

    /**
     * THE case. The intermediate is real and the anchor is honest; the attacker impersonates the
     * intermediate. They forge its Entity Configuration and its statement about the leaf with a key of
     * their own, and supply nothing from the anchor. The validator then fetches the anchor's genuine
     * statement about the intermediate — which vouches for the intermediate's real key, not the
     * attacker's — and that statement must be what the intermediate's configuration is checked against.
     * A validator that fetches it, notes that it exists, and verifies the intermediate's configuration
     * only with the keys the forgery itself carries admits this chain.
     */
    @Test
    @Requirement("OIDFED §10.2")
    void aForgedIntermediateConfigurationIsCheckedAgainstTheAnchorsStatementAboutIt() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey attackerKey = ec("attacker-posing-as-intermediate");
        PublicJsonWebKey realIntermediateKey = ec("intermediate-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String forgedIntermediateAboutLeaf = statement(attackerKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String genuineAnchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE,
                Map.of("jwks", jwks(realIntermediateKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        responses.put(fetchUrl(ANCHOR, INTERMEDIATE), genuineAnchorAboutIntermediate);
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(serving(responses), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        List<String> chain = List.of(leafConfig(leafKey), forgedIntermediateAboutLeaf, intermediateConfig(attackerKey));
        assertThrows(Exception.class, () -> validator.validate(chain, LEAF, LEAF),
                "the anchor vouches for a different key than the one the intermediate's statements are signed with");
    }

    /**
     * A real subordinate of the anchor, but the anchor vouches for a different key than the one the
     * intermediate's configuration and its statement about the leaf are signed with — with the anchor's
     * statement caller-supplied this time. Whoever holds that other key is not the entity the anchor
     * admitted. (This case was already refused: a supplied subordinate statement is preferred over the
     * self-signed configuration and verified against the anchor. It is pinned so the fetched case above
     * and the supplied case never diverge again.)
     */
    @Test
    @Requirement("OIDFED §10.2")
    void anIntermediateWhoseKeyTheAnchorDoesNotVouchForIsRejectedWhenTheAnchorStatementIsSupplied() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        PublicJsonWebKey keyTheAnchorAdmitted = ec("intermediate-as-the-anchor-knows-it");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String anchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE,
                Map.of("jwks", jwks(keyTheAnchorAdmitted)));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(serving(responses), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        List<String> chain = List.of(leafConfig(leafKey), intermediateAboutLeaf,
                intermediateConfig(intermediateKey), anchorAboutIntermediate);
        assertThrows(Exception.class, () -> validator.validate(chain, LEAF, LEAF));
    }

    /**
     * The anchor's {@code metadata_policy} sits on its statement about the intermediate. When that
     * statement is fetched rather than supplied, it must still be part of the verified chain — or a
     * policy the anchor set for everything under an intermediate silently constrains nothing.
     */
    @Test
    @Requirement({"OIDFED §10.2", "OIDFED §6.1.4.1"})
    void theAnchorsPolicyReachesTheLeafWhenTheAnchorStatementIsFetched() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String anchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE, Map.of(
                "jwks", jwks(intermediateKey),
                "metadata_policy", Map.of("openid_relying_party", Map.of("client_name", Map.of("value", "as-the-anchor-says")))));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        responses.put(fetchUrl(ANCHOR, INTERMEDIATE), anchorAboutIntermediate);
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(serving(responses), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        List<String> chain = List.of(leafConfig(leafKey), intermediateAboutLeaf, intermediateConfig(intermediateKey));
        TrustChainValidationResult result = validator.validate(chain, LEAF, LEAF);

        assertEquals(ANCHOR, result.trustAnchorIssuer());
        assertTrue(result.isPoliced("openid_relying_party"), "the anchor's policy must count as applied");
        assertEquals("as-the-anchor-says", result.metadataFor("openid_relying_party").get("client_name"));
    }

    /**
     * Keeping the anchor's statement in the route must not bring back a live fetch per request: a pushed
     * chain that carries the intermediate's configuration is resolved with the anchor's endpoints alone,
     * and nothing is fetched from the intermediate.
     */
    @Test
    void aPushedChainThroughAnIntermediateFetchesOnlyFromTheAnchor() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String anchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE, Map.of("jwks", jwks(intermediateKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        responses.put(fetchUrl(ANCHOR, INTERMEDIATE), anchorAboutIntermediate);
        List<String> fetched = new ArrayList<>();
        HttpGetClient recording = (url, accept) -> {
            fetched.add(url);
            return serving(responses).get(url, accept);
        };
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(recording, ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        validator.validate(List.of(leafConfig(leafKey), intermediateAboutLeaf, intermediateConfig(intermediateKey)), LEAF, LEAF);

        assertTrue(fetched.contains(fetchUrl(ANCHOR, INTERMEDIATE)), fetched.toString());
        assertFalse(fetched.stream().anyMatch(u -> u.startsWith(INTERMEDIATE)), fetched.toString());
    }

    /**
     * Control: the genuine chain, anchor statement supplied, resolves and the anchor's
     * {@code metadata_policy} reaches the leaf.
     */
    @Test
    @Requirement({"OIDFED §10.2", "OIDFED §6.1.4.1"})
    void aGenuineThreeLevelChainWithTheAnchorStatementSuppliedValidatesWithPolicy() throws Exception {
        PublicJsonWebKey leafKey = ec("leaf-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        PublicJsonWebKey anchorKey = ec("anchor-1");

        String intermediateAboutLeaf = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of("jwks", jwks(leafKey)));
        String anchorAboutIntermediate = statement(anchorKey, ANCHOR, INTERMEDIATE, Map.of(
                "jwks", jwks(intermediateKey),
                "metadata_policy", Map.of("openid_relying_party", Map.of("client_name", Map.of("value", "as-the-anchor-says")))));

        Map<String, String> responses = new HashMap<>();
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig(anchorKey));
        TrustChainValidator validator = new TrustChainValidator(
                new HttpTrustControllerGateway(serving(responses), ANCHOR), TrustAnchor.of(ANCHOR, jwks(anchorKey)));

        List<String> chain = List.of(leafConfig(leafKey), intermediateAboutLeaf,
                intermediateConfig(intermediateKey), anchorAboutIntermediate);
        TrustChainValidationResult result = validator.validate(chain, LEAF, LEAF);

        assertEquals(ANCHOR, result.trustAnchorIssuer());
        assertEquals(LEAF, result.leafSubject());
        assertTrue(result.isPoliced("openid_relying_party"), "the anchor's policy must count as applied");
        assertEquals("as-the-anchor-says", result.metadataFor("openid_relying_party").get("client_name"));
    }
}
