package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;

/**
 * Exercises trust establishment end-to-end: a real {@link TrustChainValidator} walking a minimal
 * federation (attester leaf -> trust anchor) served by a stubbed {@link HttpGetClient}.
 */
class FederationAttesterKeyResolverTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String ANCHOR = "https://anchor.example.com";
    private static final String OP = "https://op.example.com";

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        return Map.of("keys", List.of(TestJwts.publicParams(key)));
    }

    private static String entityStatement(PublicJsonWebKey signingKey, String iss, String sub,
                                          Map<String, Object> claims) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600L));
        claims.forEach(c::setClaim);
        return TestJwts.sign(signingKey, "ES256", "entity-statement+jwt", c);
    }

    private static HttpGetClient stubFederation(PublicJsonWebKey attesterKey, PublicJsonWebKey anchorKey,
                                                Map<String, Object> attesterExtraClaims) throws Exception {
        String attesterConfig = entityStatement(attesterKey, ATTESTER, ATTESTER, merge(
                Map.of("jwks", jwks(attesterKey), "authority_hints", List.of(ANCHOR)), attesterExtraClaims));
        String anchorConfig = entityStatement(anchorKey, ANCHOR, ANCHOR, Map.of(
                "jwks", jwks(anchorKey),
                "metadata", Map.of("federation_entity", Map.of("federation_fetch_endpoint", ANCHOR + "/fetch"))));
        String subordinate = entityStatement(anchorKey, ANCHOR, ATTESTER, Map.of("jwks", jwks(attesterKey)));

        Map<String, String> responses = new HashMap<>();
        responses.put(ATTESTER + "/.well-known/openid-federation", attesterConfig);
        responses.put(ANCHOR + "/.well-known/openid-federation", anchorConfig);
        responses.put(ANCHOR + "/fetch?sub=" + URLEncoder.encode(ATTESTER, StandardCharsets.UTF_8), subordinate);
        return (url, accept) -> {
            String jwt = responses.get(url);
            if (jwt == null) {
                throw new IllegalArgumentException("no stub for " + url);
            }
            return jwt;
        };
    }

    private static Map<String, Object> merge(Map<String, Object> a, Map<String, Object> b) {
        HashMap<String, Object> m = new HashMap<>(a);
        m.putAll(b);
        return m;
    }

    private static FederationAttesterKeyResolver resolver(HttpGetClient http) {
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(http, ANCHOR), ANCHOR);
        return new FederationAttesterKeyResolver(validator, OP);
    }

    @Test
    void resolvesChainValidatedAttesterKeys() throws Exception {
        PublicJsonWebKey attesterKey = TestJwts.ec("attester-1");
        PublicJsonWebKey anchorKey = TestJwts.ec("anchor-1");
        HttpGetClient http = stubFederation(attesterKey, anchorKey, Map.of());

        List<JsonWebKey> keys = resolver(http).resolve(ATTESTER, List.of());

        String expected = Jwks.thumbprint(JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey)));
        boolean found = false;
        for (JsonWebKey k : keys) {
            if (expected.equals(Jwks.thumbprint(k))) {
                found = true;
            }
        }
        assertTrue(found, "resolver should return the chain-validated attester key");
    }

    @Test
    void prefersDedicatedAttesterMetadataKeys() throws Exception {
        PublicJsonWebKey federationKey = TestJwts.ec("attester-fed");
        PublicJsonWebKey attestationSigningKey = TestJwts.ec("attester-sign");
        PublicJsonWebKey anchorKey = TestJwts.ec("anchor-1");
        // Attester publishes a dedicated oauth_client_attester.jwks distinct from its federation jwks.
        Map<String, Object> extra = Map.of("metadata",
                Map.of("oauth_client_attester", Map.of("jwks", jwks(attestationSigningKey))));
        HttpGetClient http = stubFederation(federationKey, anchorKey, extra);

        List<JsonWebKey> keys = resolver(http).resolve(ATTESTER, List.of());

        String wanted = Jwks.thumbprint(JsonWebKey.Factory.newJwk(TestJwts.publicParams(attestationSigningKey)));
        assertEquals(wanted, Jwks.thumbprint(keys.get(0)));
    }

    @Test
    void rejectsUnreachableAttester() {
        HttpGetClient http = (url, accept) -> {
            throw new IllegalArgumentException("GET failed: " + url);
        };
        assertThrows(Exception.class, () -> resolver(http).resolve(ATTESTER, List.of()));
    }
}
