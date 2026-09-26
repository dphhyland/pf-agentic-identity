package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
 * The gateway reads an authority's Entity Configuration to learn its {@code federation_fetch_endpoint}.
 * For the Trust Anchor that configuration is ES[i], which OpenID Federation 1.0 §10.2 requires to
 * validate with the anchor's own keys - the out-of-band ones (§4). §11.3 says a mismatch is retrieved
 * again before it is treated as a security or configuration problem.
 */
class HttpTrustControllerGatewayAnchorTest {
    private static final String ANCHOR = "https://anchor.example.com";
    private static final String INTERMEDIATE = "https://intermediate.example.com";
    private static final String LEAF = "https://agent.example.com";
    private static final String WELL_KNOWN = ANCHOR + "/.well-known/openid-federation";

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    private static String statement(PublicJsonWebKey key, String iss, String sub, Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600L));
        claims.forEach(c::setClaim);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setKeyIdHeaderValue(key.getKeyId());
        return jws.getCompactSerialization();
    }

    private static String entityConfiguration(PublicJsonWebKey key, String entity) throws Exception {
        return statement(key, entity, entity, Map.of(
                "jwks", jwks(key),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", entity + "/fetch"))));
    }

    private static String fetchUrl(String authority, String subject) {
        return authority + "/fetch?sub=" + URLEncoder.encode(subject, StandardCharsets.UTF_8)
                + "&iss=" + URLEncoder.encode(authority, StandardCharsets.UTF_8);
    }

    /** Answers each URL from a queue, so a URL fetched twice can return two different bodies. */
    private static HttpGetClient sequenced(Map<String, Deque<String>> responses, List<String> fetched) {
        return (url, accept) -> {
            fetched.add(url);
            Deque<String> queue = responses.get(url);
            if (queue == null || queue.isEmpty()) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return queue.size() > 1 ? queue.poll() : queue.peek();
        };
    }

    private static Deque<String> queue(String... bodies) {
        return new ArrayDeque<>(List.of(bodies));
    }

    @Test
    @Requirement("OIDFED §10.2")
    void theAnchorsEntityConfigurationIsVerifiedWithThePinnedKeysBeforeItsFetchEndpointIsUsed() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        String subordinate = statement(pinned, ANCHOR, LEAF, Map.of());
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(pinned, ANCHOR)));
        responses.put(fetchUrl(ANCHOR, LEAF), queue(subordinate));
        List<String> fetched = new ArrayList<>();
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, fetched), ANCHOR);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(pinned)), Set.of());

        assertEquals(subordinate, gateway.fetchSubordinateStatement(ANCHOR, LEAF));
        assertEquals(List.of(WELL_KNOWN, fetchUrl(ANCHOR, LEAF)), fetched);
    }

    @Test
    @Requirement({"OIDFED §10.2", "OIDFED §11.3"})
    void anEntityConfigurationThatNeverVerifiesStopsTheFetchAfterOneRetry() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        PublicJsonWebKey impostor = ec("anchor-impostor");
        Map<String, Deque<String>> responses = new HashMap<>();
        // Whoever answers at the anchor's host points its fetch endpoint wherever it likes.
        responses.put(WELL_KNOWN, queue(entityConfiguration(impostor, ANCHOR)));
        responses.put(fetchUrl(ANCHOR, LEAF), queue(statement(impostor, ANCHOR, LEAF, Map.of())));
        List<String> fetched = new ArrayList<>();
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, fetched), ANCHOR);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(pinned)), Set.of());

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> gateway.fetchSubordinateStatement(ANCHOR, LEAF));

        assertTrue(e.getMessage().contains("§11.3"), e.getMessage());
        assertEquals(List.of(WELL_KNOWN, WELL_KNOWN), fetched,
                "retrieved exactly twice, and the fetch endpoint it names is never called");
    }

    @Test
    @Requirement("OIDFED §11.3")
    void aCopyThatFailsIsRetrievedAgainAndTheVerifiedOneReplacesItInTheCache() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        PublicJsonWebKey stale = ec("anchor-retired");
        String subordinate = statement(pinned, ANCHOR, LEAF, Map.of());
        String goodConfiguration = entityConfiguration(pinned, ANCHOR);
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(stale, ANCHOR), goodConfiguration));
        responses.put(fetchUrl(ANCHOR, LEAF), queue(subordinate));
        List<String> fetched = new ArrayList<>();
        SubordinateStatementCache cache = new SubordinateStatementCache();
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, fetched), ANCHOR, cache);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(pinned)), Set.of());

        SubordinateStatementCache.PendingWrites pending = gateway.newPendingWrites();
        assertEquals(subordinate, gateway.fetchSubordinateStatement(ANCHOR, LEAF, -1L, pending));
        pending.commit();

        assertEquals(goodConfiguration, cache.get(ANCHOR, ANCHOR, 300L), "the verified copy is what gets cached");
        assertEquals(List.of(WELL_KNOWN, WELL_KNOWN, fetchUrl(ANCHOR, LEAF)), fetched);
    }

    @Test
    void theRetryAlsoWorksWithoutAPendingWriteBatch() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        String subordinate = statement(pinned, ANCHOR, LEAF, Map.of());
        String goodConfiguration = entityConfiguration(pinned, ANCHOR);
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(ec("anchor-retired"), ANCHOR), goodConfiguration));
        responses.put(fetchUrl(ANCHOR, LEAF), queue(subordinate));
        SubordinateStatementCache cache = new SubordinateStatementCache();
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, new ArrayList<>()), ANCHOR, cache);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(pinned)), Set.of());

        assertEquals(subordinate, gateway.fetchSubordinateStatement(ANCHOR, LEAF));
        assertEquals(goodConfiguration, cache.get(ANCHOR, ANCHOR, 300L));
    }

    @Test
    void theAcceptedAlgorithmsTheValidatorWasGivenApplyToTheAnchorsConfigurationToo() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(pinned, ANCHOR)));
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, new ArrayList<>()), ANCHOR);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(pinned)), Set.of("PS256"));

        assertThrows(IllegalStateException.class, () -> gateway.fetchSubordinateStatement(ANCHOR, LEAF));
    }

    @Test
    void anotherAuthoritysConfigurationIsADirectoryEntryNotATrustDecision() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        PublicJsonWebKey intermediateKey = ec("intermediate-1");
        String subordinate = statement(intermediateKey, INTERMEDIATE, LEAF, Map.of());
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(INTERMEDIATE + "/.well-known/openid-federation", queue(entityConfiguration(intermediateKey, INTERMEDIATE)));
        responses.put(fetchUrl(INTERMEDIATE, LEAF), queue(subordinate));
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, new ArrayList<>()), ANCHOR);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(pinned)), null);

        // The intermediate's statement about the leaf is verified by the chain against the keys the
        // anchor asserts for the intermediate, not here.
        assertEquals(subordinate, gateway.fetchSubordinateStatement(INTERMEDIATE, LEAF));
    }

    @Test
    void anUnboundGatewayKeepsItsDirectoryBehaviourForEveryAuthority() throws Exception {
        PublicJsonWebKey anyKey = ec("anchor-1");
        String subordinate = statement(anyKey, ANCHOR, LEAF, Map.of());
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(anyKey, ANCHOR)));
        responses.put(fetchUrl(ANCHOR, LEAF), queue(subordinate));
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, new ArrayList<>()), ANCHOR);

        assertEquals(subordinate, gateway.fetchSubordinateStatement(ANCHOR, LEAF));
    }

    @Test
    void bindingAddsAnchorsAndABindingForTheSameEntityReplacesItsKeys() throws Exception {
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway((url, accept) -> "", ANCHOR);
        TrustAnchor anchor = TrustAnchor.of(ANCHOR, jwks(ec("anchor-1")));

        assertThrows(NullPointerException.class, () -> gateway.bindTrustAnchor(null, Set.of()));
        gateway.bindTrustAnchor(anchor, Set.of());
        assertDoesNotThrow(() -> gateway.bindTrustAnchor(anchor, Set.of()), "the same anchor again is a no-op");
        assertDoesNotThrow(() -> gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(ec("anchor-2"))), Set.of()),
                "a rebuilt anchor object for the same entity replaces the keys (an operator key update)");
        assertDoesNotThrow(() -> gateway.bindTrustAnchor(TrustAnchor.of("https://other-anchor.example.com", jwks(ec("other-1"))), Set.of()),
                "a second federation's anchor is added beside the first");
    }

    @Test
    @Requirement({"OIDFED §10.2(3.6)", "OIDFED §10.2(3.7)"})
    void theAnchorsConfigurationIsHandedOverOnlyOnceItVerifiesWithThePinnedKeys() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(pinned, ANCHOR)));
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, new ArrayList<>()), ANCHOR);

        String configuration = gateway.anchorConfiguration(TrustAnchor.of(ANCHOR, jwks(pinned)), null, null);
        assertEquals(entityConfiguration(pinned, ANCHOR).split("\\.")[0], configuration.split("\\.")[0]);

        Map<String, Deque<String>> forged = new HashMap<>();
        forged.put(WELL_KNOWN, queue(entityConfiguration(ec("impostor-1"), ANCHOR), entityConfiguration(ec("impostor-2"), ANCHOR)));
        HttpTrustControllerGateway fooled = new HttpTrustControllerGateway(sequenced(forged, new ArrayList<>()), ANCHOR);
        assertThrows(IllegalStateException.class,
                () -> fooled.anchorConfiguration(TrustAnchor.of(ANCHOR, jwks(pinned)), Set.of(), null));
    }

    @Test
    @Requirement("OIDFED §9(1)")
    void configurationsAreFetchedFromTheWellKnownPathWithAnyTrailingSlashRemoved() throws Exception {
        List<String> fetched = new ArrayList<>();
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway((url, accept) -> {
            fetched.add(url);
            return "x";
        }, "https://pf.example/oidf", "https://pf.example");

        gateway.fetchEntityStatement("https://leaf.example/");
        gateway.fetchEntityStatement("https://pf.example/");

        assertEquals(List.of("https://leaf.example/.well-known/openid-federation",
                "https://pf.example/oidf/.well-known/openid-federation"), fetched,
                "its own identity is reached at its base URL, which may carry a context path");
    }

    /**
     * Two anchors on one gateway: each anchor's configuration is verified with the keys bound for the
     * identifier it claims, so one anchor's keys never vouch for the other's fetch endpoint.
     */
    @Test
    @Requirement("OIDFED §4(9)")
    void eachBoundAnchorsConfigurationIsVerifiedWithItsOwnKeysOnly() throws Exception {
        String other = "https://other-anchor.example.com";
        PublicJsonWebKey anchorKey = ec("anchor-1");
        PublicJsonWebKey otherKey = ec("other-1");
        String otherSubordinate = statement(otherKey, other, LEAF, Map.of());
        Map<String, Deque<String>> responses = new HashMap<>();
        responses.put(WELL_KNOWN, queue(entityConfiguration(anchorKey, ANCHOR)));
        // The other anchor's host serves a configuration signed with the FIRST anchor's key, twice.
        responses.put(other + "/.well-known/openid-federation", queue(entityConfiguration(anchorKey, other), entityConfiguration(anchorKey, other)));
        responses.put(fetchUrl(other, LEAF), queue(otherSubordinate));
        HttpTrustControllerGateway gateway = new HttpTrustControllerGateway(sequenced(responses, new ArrayList<>()), ANCHOR);
        gateway.bindTrustAnchor(TrustAnchor.of(ANCHOR, jwks(anchorKey)), Set.of());
        gateway.bindTrustAnchor(TrustAnchor.of(other, jwks(otherKey)), Set.of());

        IllegalStateException e = assertThrows(IllegalStateException.class, () -> gateway.fetchSubordinateStatement(other, LEAF));
        assertTrue(e.getMessage().contains(other), e.getMessage());
    }
}
