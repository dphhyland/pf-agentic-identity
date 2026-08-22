package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.jose.Jwks;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link EnclaveKeyProofValidator} in isolation.
 *
 * <p>{@code EnrolmentServiceTest} exercises this validator only through {@code reissue} — the wrong-key
 * and jti-replay cases. Every other branch (algorithm pinning, a private key smuggled into the {@code jwk}
 * header, a forged signature, audience, {@code jti} presence, the {@code iat} clock-skew window, the
 * {@code typ} check, and a malformed proof) has no direct coverage anywhere in the module. Those are the
 * checks that stand between "the caller signed with the enrolled key" and "the caller signed with
 * something else", so they are pinned here.
 */
class EnclaveKeyProofValidatorTest {

    private static final String AUDIENCE = "https://platform.example.com";

    private EnclaveKeyProofValidator validator;
    private PublicJsonWebKey enclaveKey;
    private String expectedJkt;

    @BeforeEach
    void setUp() throws Exception {
        validator = new EnclaveKeyProofValidator();
        enclaveKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enclaveKey.setKeyId("enclave-1");
        expectedJkt = Jwks.thumbprint(publicParams(enclaveKey));
    }

    private JsonWebSignature freshProof() {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim("challenge", "chal-1");

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", EnclaveKeyProofValidator.TYP);
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey));
        return jws;
    }

    // ---- the happy path ------------------------------------------------------------------------------

    @Test
    void aWellFormedProofYieldsTheJtiChallengeAndPublicKey() throws Exception {
        EnclaveKeyProofValidator.Result result =
                validator.validate(freshProof().getCompactSerialization(), expectedJkt, AUDIENCE);

        assertEquals("chal-1", result.challenge());
        assertTrue(result.jti() != null && !result.jti().isBlank());
        assertEquals(expectedJkt, Jwks.thumbprint(result.publicJwk()));
        assertNull(result.publicJwk().get("d"), "the result must carry only the public key");
    }

    @Test
    void theTypHeaderIsOptionalButMustMatchWhenPresent() throws Exception {
        JsonWebSignature jws = freshProof();
        jws.getHeaders().setStringHeaderValue("typ", "something-else");
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("typ"), e.getMessage());
    }

    // ---- absence and malformed input ------------------------------------------------------------------

    @Test
    void aNullOrBlankProofIsRefused() {
        assertEquals(EnrolmentException.INVALID_KEY_PROOF,
                assertThrows(EnrolmentException.class,
                        () -> validator.validate(null, expectedJkt, AUDIENCE)).error());
        assertEquals(EnrolmentException.INVALID_KEY_PROOF,
                assertThrows(EnrolmentException.class,
                        () -> validator.validate("   ", expectedJkt, AUDIENCE)).error());
    }

    @Test
    void garbageIsRefusedRatherThanThrowingUnchecked() {
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate("not-a-jws", expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
    }

    // ---- the jwk header --------------------------------------------------------------------------------

    @Test
    void aProofWithNoJwkHeaderIsRefused() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", "x");
        claims.setIssuedAtToNow();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        // Deliberately no jwk header.

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("jwk"), e.getMessage());
    }

    /**
     * A real Secure Enclave key can never appear as a private key in a header — the enclave does not
     * export it. Presenting one here is either a bug on the client or an impostor, and either way it
     * must be refused rather than accepted as "a key that happens to verify".
     */
    @Test
    void aPrivateKeyInTheJwkHeaderIsRefused() throws Exception {
        JsonWebSignature jws = freshProof();
        jws.getHeaders().setObjectHeaderValue("jwk", privateParams(enclaveKey));

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("public key"), e.getMessage());
    }

    @Test
    void theThumbprintMustMatchTheOneBoundAtEnrolment() throws Exception {
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(freshProof().getCompactSerialization(), "some-other-thumbprint", AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("not the one bound"), e.getMessage());
    }

    // ---- algorithm --------------------------------------------------------------------------------------

    @Test
    void anRs256ProofIsRefusedEvenIfInternallyConsistent() throws Exception {
        RsaJsonWebKey rsaKey = RsaJwkGenerator.generateJwk(2048);
        rsaKey.setKeyId("rsa-1");
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", "x");
        claims.setIssuedAtToNow();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(rsaKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("RS256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(rsaKey));

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), Jwks.thumbprint(publicParams(rsaKey)), AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("ES256"), e.getMessage());
    }

    // ---- signature integrity ------------------------------------------------------------------------------

    @Test
    void aTamperedPayloadFailsSignatureVerification() throws Exception {
        String proof = freshProof().getCompactSerialization();
        String[] parts = proof.split("\\.");
        // Flip the payload to something else, signed by nobody.
        String tamperedPayload = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString("{\"jti\":\"tampered\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + tamperedPayload + "." + parts[2];

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(tampered, expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
    }

    @Test
    void aProofSignedByAKeyOtherThanTheOneAdvertisedInItsOwnHeaderIsRefused() throws Exception {
        // The jwk header claims to be the enclave key, matching expectedJkt, but the JWS is actually
        // signed by a different key entirely — the thumbprint check alone must not be trusted without
        // signature verification.
        PublicJsonWebKey impostor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        impostor.setKeyId("impostor");

        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", "x");
        claims.setIssuedAtToNow();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(impostor.getPrivateKey());   // signed by the impostor...
        jws.setAlgorithmHeaderValue("ES256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey)); // ...but claims the real key

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
    }

    // ---- audience -----------------------------------------------------------------------------------------

    @Test
    void aProofForADifferentAudienceIsRefused() throws Exception {
        JsonWebSignature jws = freshProof();
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, "https://somewhere-else.example"));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("audience"), e.getMessage());
    }

    @Test
    void aProofWithNoAudienceAtAllIsRefused() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("jti", "x");
        claims.setIssuedAtToNow();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey));

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
    }

    // ---- jti ------------------------------------------------------------------------------------------------

    @Test
    void aProofWithNoJtiIsRefused() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setIssuedAtToNow();
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey));

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("jti"), e.getMessage());
    }

    // ---- the iat clock-skew window ------------------------------------------------------------------------

    @Test
    void aProofIssuedTooFarInTheFutureIsRefused() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", "x");
        claims.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey));

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("future"), e.getMessage());
    }

    @Test
    void aProofOlderThanTheConfiguredMaxAgeIsRefused() throws Exception {
        // Default validator: maxAgeSeconds=300, allowedClockSkewSeconds=60 -> refuse beyond 360s old.
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", "x");
        claims.setIssuedAt(NumericDate.fromSeconds(NumericDate.now().getValue() - 3600));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey));

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE));
        assertEquals(EnrolmentException.INVALID_KEY_PROOF, e.error());
        assertTrue(e.getMessage().contains("too old"), e.getMessage());
    }

    @Test
    void anAbsentIatSkipsTheAgeCheckEntirely() throws Exception {
        // validate() only enforces the age window "if (claims.hasClaim("iat"))" — documenting that
        // behaviour, since an absent iat is otherwise silently accepted.
        JwtClaims claims = new JwtClaims();
        claims.setAudience(AUDIENCE);
        claims.setClaim("jti", "x");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(enclaveKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.getHeaders().setObjectHeaderValue("jwk", publicParams(enclaveKey));

        EnclaveKeyProofValidator.Result result =
                validator.validate(jws.getCompactSerialization(), expectedJkt, AUDIENCE);
        assertEquals("x", result.jti());
    }

    // ---- helpers ------------------------------------------------------------------------------------------

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private static Map<String, Object> privateParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
    }
}
