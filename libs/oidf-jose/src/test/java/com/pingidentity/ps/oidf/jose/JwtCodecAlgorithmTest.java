package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;

/**
 * Since HJOSE (plan item H-JOSE-1) every verifier in {@link JwtCodec} - the policy-less overloads HFEDD removes among
 * them - lets the verifier, never the token, choose the algorithm and the key. RFC 8725 §3.1: "Libraries MUST enable
 * the caller to specify a supported set of algorithms and MUST NOT use any other algorithms when performing
 * cryptographic operations"; §3.2: "applications MUST only allow the use of cryptographically current algorithms that
 * meet the security requirements of the application". {@code none} and the MAC algorithms are refused whatever the
 * caller's set names, and only an asymmetric key not marked for encryption (RFC 7517 §4.2) is ever tried.
 */
@SuppressWarnings("removal")
class JwtCodecAlgorithmTest {

    private static final String ISSUER = "https://issuer.example";
    private static final long NOW = System.currentTimeMillis() / 1000;

    @Test
    @Requirement("RFC8725 §3.1")
    void anUnsignedTokenIsRefusedByEveryVerifier() throws Exception {
        String none = unsigned(statement());
        PublicJsonWebKey key = TestJwts.ec("k1");

        assertAlgorithm(() -> JwtCodec.verifyAgainstKeys(none, List.of(key), ISSUER, Set.of(), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifyAgainstKeys(none, List.of(key), ISSUER, Set.of("none"), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifyAgainstInlineJwks(none, jwks(key), ISSUER, Set.of(), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifySignature(none, List.of(key), Set.of()));
        assertAlgorithm(() -> JwtCodec.verifyAttestationPop(none, key.getPublicKey(), Set.of(), Set.of(), 60));
    }

    @Test
    @Requirement({"RFC8725 §3.1", "RFC8725 §3.2"})
    void aMacIsRefusedEvenWhenTheCallerNamesItAndTheKeySetHoldsTheSecret() throws Exception {
        OctetSequenceJsonWebKey secret = new OctetSequenceJsonWebKey(new HmacKey(new byte[32]));
        secret.setKeyId("shared");
        String hs256 = mac(secret, statement());
        Map<String, Object> inline = Map.of("keys", List.of(secret.toParams(JsonWebKey.OutputControlLevel.INCLUDE_SYMMETRIC)));

        assertAlgorithm(() -> JwtCodec.verifyAgainstKeys(hs256, List.of(secret), ISSUER, Set.of("HS256"), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifyAgainstKeys(hs256, List.of(secret), ISSUER, Set.of(), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifyAgainstInlineJwks(hs256, inline, ISSUER, Set.of(), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifyAgainstInlineJwks(hs256, inline, ISSUER, Set.of("HS256"), VerificationPolicy.legacy()));
        assertAlgorithm(() -> JwtCodec.verifySignature(hs256, List.of(secret), Set.of("HS256")));
    }

    @Test
    @Requirement("RFC8725 §3.1")
    void anAsymmetricAlgorithmWhoseKidNamesASymmetricKeyIsAKeyRefusal() throws Exception {
        PublicJsonWebKey signing = TestJwts.ec("shared");
        String es256 = TestJwts.sign(signing, "ES256", "entity-statement+jwt", statement());
        OctetSequenceJsonWebKey secret = new OctetSequenceJsonWebKey(new HmacKey(new byte[32]));
        secret.setKeyId("shared");

        JwtVerificationException e = assertThrows(JwtVerificationException.class, () -> JwtCodec.verifyAgainstKeys(es256,
                List.of(secret), ISSUER, Set.of(), VerificationPolicy.entityStatement()));
        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
    }

    @Test
    @Requirement("RFC8725 §3.1")
    void aKeyMarkedForEncryptionNeverVerifiesASignature() throws Exception {
        PublicJsonWebKey signing = TestJwts.ec("k1");
        String es256 = TestJwts.sign(signing, "ES256", "entity-statement+jwt", statement());
        PublicJsonWebKey encryption = (PublicJsonWebKey) JsonWebKey.Factory.newJwk(TestJwts.publicParams(signing));
        encryption.setUse("enc");

        JwtVerificationException byKid = assertThrows(JwtVerificationException.class, () -> JwtCodec.verifyAgainstKeys(es256,
                List.of(encryption), ISSUER, Set.of(), VerificationPolicy.entityStatement()));
        assertEquals(JwtVerificationException.Reason.KEY, byKid.reason());
        JwtVerificationException byResolver = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstKeys(es256, List.of(encryption), ISSUER, Set.of(), VerificationPolicy.legacy()));
        assertEquals(JwtVerificationException.Reason.KEY, byResolver.reason());
        assertThrows(JwtVerificationException.class, () -> JwtCodec.verifySignature(es256, List.of(encryption), Set.of()));

        PublicJsonWebKey forSigning = (PublicJsonWebKey) JsonWebKey.Factory.newJwk(TestJwts.publicParams(signing));
        forSigning.setUse("sig");
        assertEquals(ISSUER, JwtCodec.verifyAgainstKeys(es256, List.of(encryption, forSigning), ISSUER, Set.of(),
                VerificationPolicy.legacy()).getIssuer(), "a key marked sig, or unmarked, still verifies");
    }

    @Test
    @Requirement("RFC8725 §3.2")
    void anAlgorithmOutsideTheCallersSetIsRefused() throws Exception {
        PublicJsonWebKey signing = TestJwts.ec("k1");
        String es256 = TestJwts.sign(signing, "ES256", "entity-statement+jwt", statement());

        assertAlgorithm(() -> JwtCodec.verifyAgainstKeys(es256, List.of(signing), ISSUER, Set.of("PS256"), VerificationPolicy.legacy()));
        assertEquals(ISSUER, JwtCodec.verifyAgainstKeys(es256, List.of(signing), ISSUER, Set.of("ES256"),
                VerificationPolicy.legacy()).getIssuer());
        assertEquals(ISSUER, JwtCodec.verifyAgainstInlineJwks(es256, jwks(signing), ISSUER, Set.of("ES256"), VerificationPolicy.legacy()).getIssuer());
        assertEquals(ISSUER, JwtCodec.verifyAgainstKeys(es256, List.of(signing), ISSUER, null,
                VerificationPolicy.legacy()).getIssuer(), "no set is any asymmetric algorithm");
    }

    @Test
    void theAlgorithmChoiceRefusesAHeaderWithoutAUsableAlg() throws Exception {
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(null, Set.of()));
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(Map.of(), Set.of()));
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(Map.of("alg", " "), Set.of()));
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(Map.of("alg", 256), Set.of()));
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(Map.of("alg", "NONE"), Set.of()));
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(Map.of("alg", "hs512"), Set.of()));
        assertAlgorithm(() -> JwtCodec.permittedAlgorithms(Map.of("alg", "ES256"), Set.of("ES384")));
        assertArrayEquals(new String[] {"PS256"}, JwtCodec.permittedAlgorithms(Map.of("alg", "PS256"), null));
        assertArrayEquals(new String[] {"PS256"}, JwtCodec.permittedAlgorithms(Map.of("alg", "PS256"), Set.of("PS256")));
    }

    @Test
    void theSigningKeysOfNothingAreNone() throws Exception {
        assertTrue(JwtCodec.signingKeys(null).isEmpty());
        OctetSequenceJsonWebKey secret = new OctetSequenceJsonWebKey(new HmacKey(new byte[32]));
        PublicJsonWebKey ec = TestJwts.ec("k1");
        assertEquals(List.of(ec), JwtCodec.signingKeys(List.of(secret, ec)));
    }

    // ---- helpers --------------------------------------------------------------------------------

    private interface Call {
        Object run() throws Exception;
    }

    private static void assertAlgorithm(Call call) {
        JwtVerificationException e = assertThrows(JwtVerificationException.class, call::run);
        assertEquals(JwtVerificationException.Reason.ALGORITHM, e.reason());
    }

    private static JwtClaims statement() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject(ISSUER);
        claims.setIssuedAt(org.jose4j.jwt.NumericDate.fromSeconds(NOW - 10));
        claims.setExpirationTime(org.jose4j.jwt.NumericDate.fromSeconds(NOW + 600));
        claims.setJwtId("j1");
        return claims;
    }

    private static String unsigned(JwtClaims claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"none\",\"typ\":\"entity-statement+jwt\"}".getBytes(StandardCharsets.UTF_8))
                + "." + b64.encodeToString(claims.toJson().getBytes(StandardCharsets.UTF_8)) + ".";
    }

    private static String mac(OctetSequenceJsonWebKey key, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getKey());
        jws.setAlgorithmHeaderValue("HS256");
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setHeader("typ", "entity-statement+jwt");
        return jws.getCompactSerialization();
    }

    private static Map<String, Object> jwks(PublicJsonWebKey key) {
        Map<String, Object> jwks = new HashMap<>();
        jwks.put("keys", List.of(TestJwts.publicParams(key)));
        return jwks;
    }
}
