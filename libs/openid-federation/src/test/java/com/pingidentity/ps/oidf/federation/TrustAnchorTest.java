package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

/**
 * The out-of-band anchor keys: what is accepted into the configured set, what is refused, and that
 * verification uses that set and nothing else. Every branch of {@link TrustAnchor#of},
 * {@link TrustAnchor#parse} and {@link TrustAnchor#verify} is gated at 100% in the pom.
 */
class TrustAnchorTest {
    private static final String ANCHOR = "https://anchor.example.com";

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> publicJwk(PublicJsonWebKey key) {
        return key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    private static Map<String, Object> jwks(Map<String, Object>... keys) {
        return Map.of("keys", List.of(keys));
    }

    private static String signed(PublicJsonWebKey key, String iss) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject("https://leaf.example.com");
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(key.getKeyId());
        return jws.getCompactSerialization();
    }

    @Test
    void parsesAJwkSetDocumentAndKeepsEveryKeyInOrder() throws Exception {
        PublicJsonWebKey first = ec("anchor-1");
        PublicJsonWebKey second = ec("anchor-2");
        String json = org.jose4j.json.JsonUtil.toJson(jwks(publicJwk(first), publicJwk(second)));

        TrustAnchor anchor = TrustAnchor.parse(ANCHOR, json);

        assertEquals(ANCHOR, anchor.entityId());
        assertEquals(List.of("anchor-1", "anchor-2"), anchor.keys().stream().map(JsonWebKey::getKeyId).toList());
        assertTrue(anchor.toString().contains("anchor-2"), anchor.toString());
    }

    @Test
    @Requirement("OIDFED §4")
    void anAbsentJwksIsRefusedAsAConfigurationErrorNotFetched() {
        IllegalArgumentException blank = assertThrows(IllegalArgumentException.class, () -> TrustAnchor.parse(ANCHOR, "  "));
        assertTrue(blank.getMessage().contains("out of band"), blank.getMessage());
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.parse(ANCHOR, null));
    }

    @Test
    void aDocumentThatIsNotJsonIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TrustAnchor.parse(ANCHOR, "{ not json"));
        assertTrue(e.getMessage().contains("not a JSON object"), e.getMessage());
    }

    @Test
    void aBlankEntityIdIsRefused() throws Exception {
        Map<String, Object> set = jwks(publicJwk(ec("anchor-1")));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(" ", set));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(null, set));
    }

    @Test
    void aSetWithNoKeysIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, null));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, Map.of()));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, Map.of("keys", "not-a-list")));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, Map.of("keys", List.of())));
        assertTrue(e.getMessage().contains("no keys"), e.getMessage());
    }

    @Test
    void aKeyEntryThatIsNotAnObjectIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> TrustAnchor.of(ANCHOR, Map.of("keys", List.of("just-a-string"))));
        assertTrue(e.getMessage().contains("not a JWK object"), e.getMessage());
    }

    @Test
    void aPrivateKeyIsRefusedBecauseConfiguringItWouldLeakIt() throws Exception {
        PublicJsonWebKey key = ec("anchor-1");
        Map<String, Object> withPrivate = key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, jwks(withPrivate)));
        assertTrue(e.getMessage().contains("private"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §3.1.1")
    void everyKeyNeedsAUniqueKid() throws Exception {
        PublicJsonWebKey noKid = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        IllegalArgumentException missing = assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, jwks(publicJwk(noKid))));
        assertTrue(missing.getMessage().contains("kid"), missing.getMessage());

        Map<String, Object> blankKid = new HashMap<>(publicJwk(ec("x")));
        blankKid.put("kid", " ");
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, jwks(blankKid)));

        Map<String, Object> numericKid = new HashMap<>(publicJwk(ec("x")));
        numericKid.put("kid", 7);
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, jwks(numericKid)));

        assertThrows(IllegalArgumentException.class,
                () -> TrustAnchor.of(ANCHOR, jwks(publicJwk(ec("same")), publicJwk(ec("same")))));
    }

    @Test
    void aSymmetricKeyIsRefused() {
        Map<String, Object> oct = Map.of("kty", "oct", "kid", "shared", "k", "AAAA");
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, jwks(oct)));
    }

    @Test
    void aKeyThatDoesNotParseIsRefused() {
        // jose4j decodes any base64url as a coordinate, so a malformed EC point is not enough to make
        // it throw; an unknown key type is.
        Map<String, Object> broken = new HashMap<>();
        broken.put("kty", "NOT-A-KEY-TYPE");
        broken.put("kid", "broken");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> TrustAnchor.of(ANCHOR, jwks(broken)));
        assertTrue(e.getMessage().contains("broken"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §4")
    void verifiesAgainstTheConfiguredKeysOnly() throws Exception {
        PublicJsonWebKey pinned = ec("anchor-1");
        PublicJsonWebKey other = ec("anchor-rogue");
        TrustAnchor anchor = TrustAnchor.of(ANCHOR, jwks(publicJwk(pinned)));

        JwtClaims claims = anchor.verify(signed(pinned, ANCHOR), Set.of());
        assertEquals(ANCHOR, claims.getIssuer());

        assertThrows(Exception.class, () -> anchor.verify(signed(other, ANCHOR), Set.of()),
                "a key the operator never configured must not verify, whoever publishes it");
        assertThrows(Exception.class, () -> anchor.verify(signed(pinned, "https://someone-else.example"), Set.of()),
                "the anchor's key signing a statement in another issuer's name is not the anchor speaking");
        assertThrows(Exception.class, () -> anchor.verify(signed(pinned, ANCHOR), Set.of("RS256")),
                "a disallowed algorithm is refused even with a valid signature");
    }
}
