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
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

/**
 * {@link LocalJwkSigner} is the dev/demo counterpart to {@link OpenBaoTransitSigner} and, unlike it,
 * had no tests of its own beyond incidental use inside {@link CompactJwsTest}. These pin the curve/alg
 * table, the RSA path, the raw-signature-bytes contract {@link JwsSigner} promises (fixed-width
 * {@code r||s} for ECDSA, not DER), and the constructor's rejection of unusable input.
 */
class LocalJwkSignerTest {

    @Test
    @Requirement("RFC7518 §3.4")
    void p256SignsAsEs256WithA64ByteConcatenatedSignature() throws Exception {
        assertSignsAndVerifies(EllipticCurves.P256, "ES256", 64);
    }

    @Test
    @Requirement("RFC7518 §3.4")
    void p384SignsAsEs384WithA96ByteConcatenatedSignature() throws Exception {
        assertSignsAndVerifies(EllipticCurves.P384, "ES384", 96);
    }

    @Test
    @Requirement("RFC7518 §3.4")
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

    @Test
    @Requirement("RFC7518 §3.5")
    void rsaSignsPs256Ps384AndPs512ThatAVerifierAccepts() throws Exception {
        org.jose4j.jwk.RsaJsonWebKey rsa = org.jose4j.jwk.RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("rsa-pss");
        for (String alg : new String[] {"PS256", "PS384", "PS512"}) {
            Map<String, Object> params = new LinkedHashMap<>(rsa.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
            params.put("alg", alg);
            LocalJwkSigner signer = new LocalJwkSigner(params);

            assertEquals(alg, signer.algorithm());
            assertEquals(alg, signer.publicJwk().get("alg"));
            // jose4j's own RSASSA-PSS verifier, with the algorithm pinned: the round trip F-0112 found missing.
            assertVerifies(signer);
        }
    }

    @Test
    @Requirement({"RFC7518 §3.3", "RFC7518 §3.5"})
    void anRsaKeyUnder2048BitsIsRefused() throws Exception {
        org.jose4j.jwk.RsaJsonWebKey small = org.jose4j.jwk.RsaJwkGenerator.generateJwk(1024);
        Map<String, Object> params = new LinkedHashMap<>(small.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        params.put("alg", "PS256");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new LocalJwkSigner(params));
        assertTrue(e.getMessage().contains("2048"), e.getMessage());
        assertTrue(e.getMessage().contains("1024"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> LocalJwkSigner.rsaAlgorithm(2047, null));
        assertEquals("RS256", LocalJwkSigner.rsaAlgorithm(2048, null));
        assertEquals("PS512", LocalJwkSigner.rsaAlgorithm(4096, "PS512"));
    }

    @Test
    @Requirement("RFC7518 §3.3")
    void anRsaKeyDeclaredWithAnAlgorithmItCannotSignIsRefused() throws Exception {
        for (String alg : new String[] {"ES256", "HS256", "none", "RSA-OAEP"}) {
            assertThrows(IllegalArgumentException.class, () -> LocalJwkSigner.rsaAlgorithm(2048, alg), alg);
        }
    }

    @Test
    @Requirement({"RFC7518 §3.4", "RFC8725 §3.1"})
    void anEcKeyDeclaredWithAnotherCurvesAlgorithmIsRefused() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        Map<String, Object> params = new LinkedHashMap<>(key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        params.put("alg", "ES384");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new LocalJwkSigner(params));
        assertTrue(e.getMessage().contains("ES256"), e.getMessage());

        params.put("alg", "ES256");
        assertEquals("ES256", new LocalJwkSigner(params).algorithm(), "the curve's own alg, declared, is accepted");
        assertEquals("ES384", LocalJwkSigner.ecAlgorithm("P-384", "ES384"));
        assertEquals("ES512", LocalJwkSigner.ecAlgorithm("P-521", null));
        assertThrows(IllegalArgumentException.class, () -> LocalJwkSigner.ecAlgorithm("P-521", "ES256"));
    }

    @Test
    @Requirement("RFC7518 §3.4")
    void anEcKeyOffTheThreeCurvesIsRefused() {
        for (String crv : new String[] {"secp256k1", "P-192", "Ed25519"}) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> LocalJwkSigner.ecAlgorithm(crv, null));
            assertTrue(e.getMessage().contains("P-256, P-384 and P-521"), e.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () -> LocalJwkSigner.ecAlgorithm(null, null));
    }

    @Test
    void eachAlgorithmHasItsJcaNameItsPssParametersAndItsSignatureLength() {
        assertEquals("SHA256withECDSA", LocalJwkSigner.jcaAlgorithm("ES256"));
        assertEquals("SHA384withECDSA", LocalJwkSigner.jcaAlgorithm("ES384"));
        assertEquals("SHA512withECDSA", LocalJwkSigner.jcaAlgorithm("ES512"));
        assertEquals("SHA256withRSA", LocalJwkSigner.jcaAlgorithm("RS256"));
        assertEquals("SHA384withRSA", LocalJwkSigner.jcaAlgorithm("RS384"));
        assertEquals("SHA512withRSA", LocalJwkSigner.jcaAlgorithm("RS512"));
        assertEquals("RSASSA-PSS", LocalJwkSigner.jcaAlgorithm("PS384"));
        assertEquals(32, LocalJwkSigner.pssParameters("PS256").getSaltLength());
        assertEquals("SHA-384", LocalJwkSigner.pssParameters("PS384").getDigestAlgorithm());
        assertEquals(java.security.spec.MGF1ParameterSpec.SHA512, LocalJwkSigner.pssParameters("PS512").getMGFParameters());
        assertEquals(null, LocalJwkSigner.pssParameters("RS256"));
        assertEquals(64, LocalJwkSigner.ecConcatLength("ES256"));
        assertEquals(96, LocalJwkSigner.ecConcatLength("ES384"));
        assertEquals(132, LocalJwkSigner.ecConcatLength("ES512"));
        assertEquals(0, LocalJwkSigner.ecConcatLength("PS256"));
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
        jws.setAlgorithmConstraints(new org.jose4j.jwa.AlgorithmConstraints(
                org.jose4j.jwa.AlgorithmConstraints.ConstraintType.PERMIT, signer.algorithm()));
        jws.setKey(((PublicJsonWebKey) JsonWebKey.Factory.newJwk(signer.publicJwk())).getPublicKey());
        assertTrue(jws.verifySignature());
    }
}
