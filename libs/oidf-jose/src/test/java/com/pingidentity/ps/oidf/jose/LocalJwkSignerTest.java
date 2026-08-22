package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.json.JsonUtil;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * {@link LocalJwkSigner} is the dev/demo counterpart to {@link OpenBaoTransitSigner} and, unlike it,
 * had no tests of its own beyond incidental use inside {@link CompactJwsTest}. These pin the curve/alg
 * table, the RSA path, the raw-signature-bytes contract {@link JwsSigner} promises (fixed-width
 * {@code r||s} for ECDSA, not DER), and the constructor's rejection of unusable input.
 */
class LocalJwkSignerTest {

    @Test
    void p256SignsAsEs256WithA64ByteConcatenatedSignature() throws Exception {
        assertSignsAndVerifies(EllipticCurves.P256, "ES256", 64);
    }

    @Test
    void p384SignsAsEs384WithA96ByteConcatenatedSignature() throws Exception {
        assertSignsAndVerifies(EllipticCurves.P384, "ES384", 96);
    }

    @Test
    void p521SignsAsEs512WithA132ByteConcatenatedSignature() throws Exception {
        assertSignsAndVerifies(EllipticCurves.P521, "ES512", 132);
    }

    @Test
    void rsaDefaultsToRs256WhenNoAlgIsDeclared() throws Exception {
        org.jose4j.jwk.RsaJsonWebKey rsa = org.jose4j.jwk.RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("rsa1");
        LocalJwkSigner signer = new LocalJwkSigner(rsa.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        assertEquals("RS256", signer.algorithm());
        assertVerifies(signer);
    }

    @Test
    void rsaHonoursADeclaredAlg() throws Exception {
        org.jose4j.jwk.RsaJsonWebKey rsa = org.jose4j.jwk.RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("rsa1");
        Map<String, Object> params = new LinkedHashMap<>(rsa.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        params.put("alg", "RS384");
        LocalJwkSigner signer = new LocalJwkSigner(params);

        assertEquals("RS384", signer.algorithm());
        assertVerifies(signer);
    }

    @Test
    void keyIdComesFromTheSuppliedKidWhenPresent() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("explicit-kid");
        LocalJwkSigner signer = new LocalJwkSigner(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        assertEquals("explicit-kid", signer.keyId());
        assertEquals("explicit-kid", signer.publicJwk().get("kid"));
    }

    @Test
    void keyIdFallsBackToTheRfc7638ThumbprintWhenNoKidIsSupplied() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        // deliberately no setKeyId
        Map<String, Object> params = key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        LocalJwkSigner signer = new LocalJwkSigner(params);

        String expectedThumbprint = Jwks.thumbprint(JsonWebKey.Factory.newJwk(TestJwts.publicParams(key)));
        assertEquals(expectedThumbprint, signer.keyId());
    }

    @Test
    void publicJwkCarriesNoPrivateMaterial() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("k1");
        LocalJwkSigner signer = new LocalJwkSigner(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        Jwks.assertPublicOnly(signer.publicJwk()); // throws if any private member leaked through
    }

    @Test
    void publicJwkIsDefensivelyCopiedOnEachCall() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("k1");
        LocalJwkSigner signer = new LocalJwkSigner(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        Map<String, Object> first = signer.publicJwk();
        first.put("kid", "mutated-by-caller");

        assertEquals("k1", signer.publicJwk().get("kid"), "a caller mutating a returned map must not affect the signer");
    }

    @Test
    void rejectsAJwkWithNoPrivateKeyMaterial() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        Map<String, Object> publicOnly = key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);

        assertThrows(IllegalArgumentException.class, () -> new LocalJwkSigner(publicOnly));
    }

    @Test
    void rejectsAnUnsupportedEcCurve() {
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "EC");
        jwk.put("crv", "secp256k1");
        jwk.put("x", "AAAA");
        jwk.put("y", "AAAA");
        jwk.put("d", "AAAA");

        assertThrows(Exception.class, () -> new LocalJwkSigner(jwk));
    }

    @Test
    void rejectsAnUnsupportedKeyType() {
        Map<String, Object> jwk = Map.of("kty", "oct", "k", "c2VjcmV0");

        assertThrows(IllegalArgumentException.class, () -> new LocalJwkSigner(jwk));
    }

    @Test
    void rejectsAMalformedJwk() {
        Map<String, Object> jwk = Map.of("kty", "EC"); // missing crv/x/y/d entirely
        assertThrows(IllegalArgumentException.class, () -> new LocalJwkSigner(jwk));
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static void assertSignsAndVerifies(java.security.spec.ECParameterSpec curve, String expectedAlg,
            int expectedConcatLength) throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(curve);
        key.setKeyId("k1");
        LocalJwkSigner signer = new LocalJwkSigner(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));

        assertEquals(expectedAlg, signer.algorithm());
        byte[] signature = signer.sign("signing-input".getBytes(StandardCharsets.US_ASCII));
        assertEquals(expectedConcatLength, signature.length, "must be the fixed-width r||s concatenation, not DER");
        assertVerifies(signer);
    }

    private static void assertVerifies(JwsSigner signer) throws Exception {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", signer.algorithm());
        header.put("typ", "test+jwt");
        header.put("kid", signer.keyId());
        String compact = CompactJws.sign(header, Map.of("sub", "x"), signer);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(compact);
        jws.setKey(((PublicJsonWebKey) JsonWebKey.Factory.newJwk(signer.publicJwk())).getPublicKey());
        assertTrue(jws.verifySignature());
    }
}
