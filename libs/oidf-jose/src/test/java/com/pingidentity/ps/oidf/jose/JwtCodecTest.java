package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.junit.jupiter.api.Test;

/**
 * {@link JwtCodec} is the core signature-verification seam every attestation and federation path
 * verifies through, so these tests exercise the rejection paths as carefully as the happy path:
 * wrong issuer, expired token, missing subject, tampered signature, and the algorithm-constraint
 * behaviour a caller opts into (or doesn't).
 */
class JwtCodecTest {

    private static final String ISSUER = "https://issuer.example.com";

    // ---- verifyAgainstInlineJwks / verifyAgainstKeys: happy path -----------------------------

    @Test
    void verifiesAWellFormedStatementAgainstAnInlineJwks() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);

        JwtClaims verified = JwtCodec.verifyAgainstInlineJwks(jwt, jwks(key), ISSUER);

        assertEquals(ISSUER, verified.getIssuer());
        assertEquals(ISSUER, verified.getSubject());
    }

    @Test
    void verifiesDirectlyAgainstAResolvedKeyList() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);

        JwtClaims verified = JwtCodec.verifyAgainstKeys(
                jwt, List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(key))), ISSUER, Set.of());

        assertEquals(ISSUER, verified.getIssuer());
    }

    // ---- rejection paths -----------------------------------------------------------------------

    @Test
    void rejectsAnUnexpectedIssuer() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);

        assertThrows(InvalidJwtException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(key), "https://someone-else.example.com"));
    }

    @Test
    void rejectsAnExpiredStatement() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, -300);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(key), ISSUER));
    }

    @Test
    void rejectsAStatementWithNoExpiration() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject(ISSUER);
        // no exp set
        String jwt = TestJwts.sign(key, "ES256", null, claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(key), ISSUER));
    }

    @Test
    void rejectsAStatementWithNoSubject() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setExpirationTimeMinutesInTheFuture(5);
        // no sub set
        String jwt = TestJwts.sign(key, "ES256", null, claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(key), ISSUER));
    }

    @Test
    void rejectsATamperedSignature() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);
        String tampered = corruptSignature(jwt);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstInlineJwks(tampered, jwks(key), ISSUER));
    }

    @Test
    void rejectsAPayloadTamperedAfterSigning() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);
        String[] parts = jwt.split("\\.", -1);
        Map<String, Object> forged = new LinkedHashMap<>();
        forged.put("iss", ISSUER);
        forged.put("sub", ISSUER);
        forged.put("exp", System.currentTimeMillis() / 1000 + 300);
        forged.put("extra_claim_injected_by_attacker", true);
        String forgedPayload = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(JsonUtil.toJson(forged).getBytes(StandardCharsets.UTF_8));
        String tampered = parts[0] + "." + forgedPayload + "." + parts[2];

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstInlineJwks(tampered, jwks(key), ISSUER));
    }

    // ---- algorithm constraints -------------------------------------------------------------------

    @Test
    void algorithmConstraintRejectsAnUnlistedAlgorithm() throws Exception {
        RsaJsonWebKey rsaKey = TestJwts.rsa("rsa1");
        String jwt = signStatement(rsaKey, "RS256", ISSUER, ISSUER, 300);

        InvalidJwtException e = assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstKeys(
                jwt, List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(rsaKey))), ISSUER, Set.of("ES256")));
        assertTrue(e.getMessage() != null);
    }

    @Test
    void algorithmConstraintAcceptsAnExplicitlyListedAlgorithm() throws Exception {
        RsaJsonWebKey rsaKey = TestJwts.rsa("rsa1");
        String jwt = signStatement(rsaKey, "RS256", ISSUER, ISSUER, 300);

        JwtClaims verified = JwtCodec.verifyAgainstKeys(
                jwt, List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(rsaKey))), ISSUER, Set.of("RS256"));
        assertEquals(ISSUER, verified.getIssuer());
    }

    /**
     * {@code acceptedAlgorithms} is caller-opt-in: an empty set applies no algorithm constraint of
     * JwtCodec's own, so any algorithm the resolved key supports verifies. This is current, deliberate
     * behaviour of the convenience overloads real callers use in practice — {@code TrustChainValidator}
     * and {@code ClientAttestationVerifier} always pass an explicit set; this documents what happens
     * when a caller does not.
     */
    @Test
    void anEmptyAlgorithmSetAppliesNoAlgorithmConstraintOfItsOwn() throws Exception {
        RsaJsonWebKey rsaKey = TestJwts.rsa("rsa1");
        String jwt = signStatement(rsaKey, "RS256", ISSUER, ISSUER, 300);

        JwtClaims verified = JwtCodec.verifyAgainstKeys(
                jwt, List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(rsaKey))), ISSUER, Set.of());
        assertEquals(ISSUER, verified.getIssuer());
    }

    /**
     * Even with no algorithm constraint supplied by the caller, {@code alg: none} is still rejected —
     * jose4j's {@code JsonWebSignature} defaults to {@code AlgorithmConstraints.DISALLOW_NONE}
     * independently of anything {@link JwtCodec} sets. Worth pinning explicitly: it is the only thing
     * standing between the no-constraint overloads and an unsecured-JWT bypass.
     */
    @Test
    void alwaysRejectsAnUnsecuredNoneAlgorithmToken() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = unsecuredNoneAlgorithmJwt(ISSUER, ISSUER);

        assertThrows(Exception.class, () -> JwtCodec.verifyAgainstKeys(
                jwt, List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(key))), ISSUER, Set.of()));
    }

    // ---- verifyAttestationPop --------------------------------------------------------------------

    @Test
    void popVerifiesWhenJtiIatAndAudienceAreAllPresent() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setAudience("https://as.example.com/token");
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        JwtClaims verified = JwtCodec.verifyAttestationPop(jwt, key.getPublicKey(),
                Set.of("ES256"), Set.of("https://as.example.com/token"), 60);
        assertTrue(verified.hasClaim("jti"));
    }

    @Test
    void popRejectsAMissingJti() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        JwtClaims claims = new JwtClaims();
        claims.setIssuedAtToNow();
        claims.setAudience("https://as.example.com/token");
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAttestationPop(jwt, key.getPublicKey(),
                Set.of("ES256"), Set.of("https://as.example.com/token"), 60));
    }

    @Test
    void popRejectsAMissingIat() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setAudience("https://as.example.com/token");
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAttestationPop(jwt, key.getPublicKey(),
                Set.of("ES256"), Set.of("https://as.example.com/token"), 60));
    }

    @Test
    void popRejectsAnUnexpectedAudience() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setAudience("https://attacker.example.com/token");
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAttestationPop(jwt, key.getPublicKey(),
                Set.of("ES256"), Set.of("https://as.example.com/token"), 60));
    }

    @Test
    void popSkipsAudienceValidationWhenNoAudiencesAreConfigured() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        // no audience claim at all
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        JwtClaims verified = JwtCodec.verifyAttestationPop(jwt, key.getPublicKey(), Set.of("ES256"), Set.of(), 60);
        assertTrue(verified.hasClaim("jti"));
    }

    @Test
    void popAlgorithmConstraintRejectsAnUnlistedAlgorithm() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAttestationPop(jwt, key.getPublicKey(),
                Set.of("ES384"), Set.of(), 60));
    }

    @Test
    void popRejectsAKeyThatDidNotProduceTheSignature() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("pop1");
        PublicJsonWebKey otherKey = TestJwts.ec("pop2");
        JwtClaims claims = new JwtClaims();
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        String jwt = TestJwts.sign(key, "ES256", "oauth-pop+jwt", claims);

        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAttestationPop(jwt, otherKey.getPublicKey(),
                Set.of("ES256"), Set.of(), 60));
    }

    // ---- typ header handling ------------------------------------------------------------------

    @Test
    void requireTypeAcceptsAnExactMatch() throws Exception {
        JwtCodec.requireType(Map.of("typ", "oauth-client-attestation+jwt"), "oauth-client-attestation+jwt");
    }

    @Test
    void requireTypeIsCaseInsensitive() throws Exception {
        JwtCodec.requireType(Map.of("typ", "OAuth-Client-Attestation+JWT"), "oauth-client-attestation+jwt");
    }

    @Test
    void requireTypeToleratesAnApplicationPrefix() throws Exception {
        JwtCodec.requireType(Map.of("typ", "application/oauth-client-attestation+jwt"), "oauth-client-attestation+jwt");
    }

    @Test
    void requireTypeRejectsAMissingHeader() {
        assertThrows(IllegalArgumentException.class, () -> JwtCodec.requireType(Map.of(), "expected+jwt"));
    }

    @Test
    void requireTypeRejectsABlankHeader() {
        assertThrows(IllegalArgumentException.class, () -> JwtCodec.requireType(Map.of("typ", "  "), "expected+jwt"));
    }

    @Test
    void requireTypeRejectsAMismatch() {
        assertThrows(IllegalArgumentException.class,
                () -> JwtCodec.requireType(Map.of("typ", "something-else+jwt"), "expected+jwt"));
    }

    @Test
    void getTypeReturnsNullWhenHeadersAreNullOrMissing() {
        assertNull(JwtCodec.getType(null));
        assertNull(JwtCodec.getType(Map.of()));
    }

    // ---- header / unverified claim inspection --------------------------------------------------

    @Test
    void getJwtHeadersReturnsTheDeclaredHeaderValues() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);

        Map<String, Object> headers = JwtCodec.getJwtHeaders(jwt);
        assertEquals("ES256", headers.get("alg"));
        assertEquals("k1", headers.get("kid"));
    }

    @Test
    void parseUnverifiedClaimsReadsClaimsWithoutCheckingTheSignature() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        String jwt = signStatement(key, "ES256", ISSUER, ISSUER, 300);
        String tampered = corruptSignature(jwt);

        // A tampered signature must not stop unverified inspection - that is the whole point of this
        // method - but a verified path (verifyAgainstInlineJwks) must still reject the same token.
        JwtClaims claims = JwtCodec.parseUnverifiedClaims(tampered);
        assertEquals(ISSUER, claims.getIssuer());
        assertThrows(InvalidJwtException.class, () -> JwtCodec.verifyAgainstInlineJwks(tampered, jwks(key), ISSUER));
    }

    @Test
    void parseUnverifiedClaimsRejectsGarbageInput() {
        assertThrows(Exception.class, () -> JwtCodec.parseUnverifiedClaims("not-a-jwt-at-all"));
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static String signStatement(PublicJsonWebKey key, String alg, String issuer, String subject,
            long expiresInSeconds) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setExpirationTime(org.jose4j.jwt.NumericDate.fromSeconds(
                System.currentTimeMillis() / 1000 + expiresInSeconds));
        return TestJwts.sign(key, alg, null, claims);
    }

    private static Map<String, Object> jwks(JsonWebKey key) {
        return Map.of("keys", List.of(TestJwts.publicParams(key)));
    }

    /**
     * Flips a bit in the first byte of the signature. Corrupting the base64url text directly is not
     * reliable here: a compact JWS signature is rarely a multiple of 3 bytes, so the last character
     * often carries only the encoding's own padding bits, and changing it can leave the decoded byte
     * sequence — and so the signature — untouched.
     */
    private static String corruptSignature(String jwt) {
        String[] parts = jwt.split("\\.", -1);
        byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
        signature[0] ^= 0x01;
        String corrupted = Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        return parts[0] + "." + parts[1] + "." + corrupted;
    }

    /** Hand-assembled {@code alg: none} unsecured JWT - jose4j's signing API refuses to produce one. */
    private static String unsecuredNoneAlgorithmJwt(String issuer, String subject) {
        Map<String, Object> header = Map.of("alg", "none", "typ", "JWT");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", issuer);
        payload.put("sub", subject);
        payload.put("exp", System.currentTimeMillis() / 1000 + 300);
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String encodedHeader = b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8));
        String encodedPayload = b64.encodeToString(JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8));
        return encodedHeader + "." + encodedPayload + ".";
    }
}
