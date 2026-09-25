package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;

/**
 * {@link JwtCodec#verifySignature}: the signature and nothing else, for a JWT whose claims the caller judges by its
 * own rules - a request object carries no {@code sub} and may carry no {@code exp} the statement verifiers would
 * accept.
 */
class JwtCodecSignatureTest {

    private static EllipticCurveJsonWebKey key(String kid) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key;
    }

    private static JsonWebKey publicOf(EllipticCurveJsonWebKey key) throws Exception {
        return JsonWebKey.Factory.newJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private static String signed(EllipticCurveJsonWebKey key, String kid) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://rp.example");
        claims.setClaim("client_id", "https://rp.example");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        if (kid != null) {
            jws.setKeyIdHeaderValue(kid);
        }
        return jws.getCompactSerialization();
    }

    @Test
    void aJwtWithNoSubjectAndNoExpiryVerifiesUnderTheKeyItsKidNames() throws Exception {
        EllipticCurveJsonWebKey k = key("k1");

        JwtClaims claims = JwtCodec.verifySignature(signed(k, "k1"), List.of(publicOf(key("k0")), publicOf(k)), Set.of("ES256"));

        assertEquals("https://rp.example", claims.getIssuer());
        assertNull(claims.getSubject());
    }

    @Test
    void withoutAKidWhicheverKeyVerifiesIsUsed() throws Exception {
        EllipticCurveJsonWebKey k = key("k1");
        OctetSequenceJsonWebKey secret = new OctetSequenceJsonWebKey(new HmacKey(new byte[32]));

        JwtClaims claims = JwtCodec.verifySignature(signed(k, null), List.of(secret, publicOf(key("k0")), publicOf(k)), Set.of());

        assertEquals("https://rp.example", claims.getIssuer());
    }

    @Test
    void aSignatureNoKeyVerifiesIsRefused() throws Exception {
        JwtVerificationException byKid = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), "k1"), List.of(publicOf(key("k1"))), Set.of("ES256")));
        assertEquals(JwtVerificationException.Reason.SIGNATURE, byKid.reason());

        JwtVerificationException oneKey = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), null), List.of(publicOf(key("k2"))), null));
        assertEquals(JwtVerificationException.Reason.SIGNATURE, oneKey.reason(), oneKey.getMessage());

        JwtVerificationException severalKeys = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), null), List.of(publicOf(key("k2")), publicOf(key("k3"))), null));
        assertEquals(JwtVerificationException.Reason.KEY, severalKeys.reason(), "none of them verifies: " + severalKeys.getMessage());
    }

    @Test
    void aKidThatNamesNoKeyOrASymmetricOneIsRefused() throws Exception {
        assertEquals(JwtVerificationException.Reason.KEY, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), "k9"), List.of(publicOf(key("k1"))), Set.of())).reason());
        OctetSequenceJsonWebKey secret = new OctetSequenceJsonWebKey(new HmacKey(new byte[32]));
        secret.setKeyId("k1");
        assertEquals(JwtVerificationException.Reason.KEY, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), "k1"), List.of(secret), Set.of())).reason());
        assertEquals(JwtVerificationException.Reason.KEY, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), "k1"), null, Set.of())).reason());
    }

    @Test
    void noneMacsAndAlgorithmsOutsideTheAcceptedSetAreRefused() throws Exception {
        JsonWebSignature mac = new JsonWebSignature();
        mac.setPayload("{}");
        mac.setKey(new HmacKey(new byte[32]));
        mac.setAlgorithmHeaderValue("HS256");
        String hs256 = mac.getCompactSerialization();
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String none = b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + ".";
        String noAlg = b64.encodeToString("{\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + ".";
        String blankAlg = b64.encodeToString("{\"alg\":\" \"}".getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString("{}".getBytes(StandardCharsets.UTF_8)) + ".";
        EllipticCurveJsonWebKey k = key("k1");

        for (String jwt : List.of(hs256, none, noAlg, blankAlg)) {
            assertEquals(JwtVerificationException.Reason.ALGORITHM, assertThrows(JwtVerificationException.class,
                    () -> JwtCodec.verifySignature(jwt, List.of(publicOf(k)), Set.of())).reason(), jwt);
        }
        assertEquals(JwtVerificationException.Reason.ALGORITHM, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(k, "k1"), List.of(publicOf(k)), Set.of("PS256"))).reason());
    }

    @Test
    void withoutAKidOrAnyKeysNothingVerifies() throws Exception {
        assertEquals(JwtVerificationException.Reason.KEY, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature(signed(key("k1"), null), null, Set.of())).reason());
    }

    @Test
    void somethingThatIsNotAJwtIsMalformed() {
        assertEquals(JwtVerificationException.Reason.MALFORMED, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifySignature("not.a-jwt", List.of(), Set.of())).reason());
    }
}
