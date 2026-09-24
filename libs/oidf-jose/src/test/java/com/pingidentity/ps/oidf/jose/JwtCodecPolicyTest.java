package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OctetSequenceJsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jwt.consumer.ErrorCodes;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.UnresolvableKeyException;
import org.junit.jupiter.api.Test;

/**
 * The {@link VerificationPolicy} paths of {@link JwtCodec}: {@code kid} selection by exact match,
 * required and past {@code iat}, {@code typ}, a caller-supplied clock - and the rule that no rejection
 * message ever carries the token.
 */
class JwtCodecPolicyTest {

    private static final String ISSUER = "https://issuer.example.com";
    private static final long NOW = 1_800_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
    private static final VerificationPolicy ENTITY = VerificationPolicy.entityStatement().withClock(CLOCK);

    // ---- kid ----------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void aStatementVerifiesAgainstTheKeyItsKidNames() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        PublicJsonWebKey other = TestJwts.ec("k2");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);

        JwtClaims verified = JwtCodec.verifyAgainstInlineJwks(jwt, jwks(other, signer), ISSUER, Set.of(), ENTITY);

        assertEquals(ISSUER, verified.getIssuer());
    }

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void aStatementWithoutAKidIsRefusedEvenWhenAKeyWouldVerifyIt() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, null, "entity-statement+jwt", NOW - 10, NOW + 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
    }

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void anEmptyKidIsRefused() {
        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.requireKid(Map.of("kid", "")));
        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
        assertThrows(JwtVerificationException.class, () -> JwtCodec.requireKid(Map.of("kid", 7)));
        assertThrows(JwtVerificationException.class, () -> JwtCodec.requireKid(null));
    }

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void aKidThatMatchesNoKeyIsRefusedRatherThanGuessed() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        // The set holds the signing key under a different kid: a heuristic resolver would find it by
        // key type; an exact-match selection must not.
        PublicJsonWebKey relabelled = PublicJsonWebKey.Factory.newPublicJwk(TestJwts.publicParams(signer));
        relabelled.setKeyId("k1-renamed");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(relabelled), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
    }

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void aKidPrefixIsNotAMatch() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1-long");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);

        assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));
    }

    @Test
    @Requirement("OIDFED §3.2(2.12)")
    void theKeyTheKidNamesMustBeTheOneThatSigned() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        PublicJsonWebKey impostor = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(impostor), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.SIGNATURE, e.reason());
    }

    @Test
    void selectByKidRefusesTwoKeysWithTheSameKid() throws Exception {
        JsonWebKey a = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("dup")));
        JsonWebKey b = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("dup")));

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.selectByKid(List.of(a, b), "dup"));

        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
        assertThrows(JwtVerificationException.class, () -> JwtCodec.selectByKid(null, "dup"));
    }

    @Test
    void aSymmetricKeySelectedByKidIsNeverUsedToVerify() throws Exception {
        OctetSequenceJsonWebKey hmac = new OctetSequenceJsonWebKey(new HmacKey(new byte[32]));
        hmac.setKeyId("shared");
        JwtClaims claims = claims(NOW - 10, NOW + 3600);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(hmac.getKey());
        jws.setAlgorithmHeaderValue("HS256");
        jws.setKeyIdHeaderValue("shared");
        jws.setHeader("typ", "entity-statement+jwt");
        String jwt = jws.getCompactSerialization();

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstKeys(jwt, List.of(hmac), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
    }

    @Test
    @Requirement("OIDFED §3.1.1")
    void anInlineSetWithASymmetricKeyIsRefusedBeforeAnyVerification() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);
        Map<String, Object> withOct = Map.of("keys", List.of(TestJwts.publicParams(signer),
                Map.of("kty", "oct", "kid", "shared", "k", "AAAA")));

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, withOct, ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.KEY, e.reason());
    }

    // ---- iat ----------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.2(2.7)")
    void aStatementWithoutIatIsRefused() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        JwtClaims noIat = new JwtClaims();
        noIat.setIssuer(ISSUER);
        noIat.setSubject(ISSUER);
        noIat.setExpirationTime(NumericDate.fromSeconds(NOW + 3600));
        String jwt = TestJwts.sign(signer, "ES256", "entity-statement+jwt", noIat);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.MISSING_CLAIM, e.reason());
        assertEquals("iat", e.detail());
    }

    @Test
    @Requirement("OIDFED §3.2(2.7)")
    void aStatementIssuedInTheFutureIsRefused() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW + 600, NOW + 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.NOT_YET_VALID, e.reason());
    }

    @Test
    @Requirement("OIDFED §3.2(2.7)")
    void anIatWithinTheSkewIsAccepted() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW + 59, NOW + 3600);

        assertEquals(ISSUER, JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY).getIssuer());
    }

    @Test
    void requireIssuedAtInPastReadsEveryShapeOfIat() throws Exception {
        JwtClaims malformed = new JwtClaims();
        malformed.setClaim("iat", "yesterday");
        assertEquals(JwtVerificationException.Reason.MALFORMED, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.requireIssuedAtInPast(malformed, 60, CLOCK)).reason());
        assertEquals(JwtVerificationException.Reason.MISSING_CLAIM, assertThrows(JwtVerificationException.class,
                () -> JwtCodec.requireIssuedAtInPast(null, 60, CLOCK)).reason());
        JwtClaims past = new JwtClaims();
        past.setIssuedAt(NumericDate.fromSeconds(System.currentTimeMillis() / 1000 - 5));
        JwtCodec.requireIssuedAtInPast(past, 0, null);
    }

    // ---- exp under a supplied clock -------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.2(2.8)")
    void expiryIsJudgedAgainstTheSuppliedClock() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 7200, NOW - 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));
        assertEquals(JwtVerificationException.Reason.EXPIRED, e.reason());
        assertTrue(e.isExpired());

        Clock earlier = Clock.fixed(Instant.ofEpochSecond(NOW - 5000), ZoneOffset.UTC);
        assertEquals(ISSUER, JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(),
                ENTITY.withClock(earlier)).getIssuer());
    }

    // ---- typ ----------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §3.2(2.2)")
    void aWrongTypIsRefusedBeforeTheSignatureIsLookedAt() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "JWT", NOW - 10, NOW + 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));

        assertEquals(JwtVerificationException.Reason.TYP, e.reason());
    }

    @Test
    void theTrustMarkProfileExpectsTheTrustMarkType() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "trust-mark+jwt", NOW - 10, NOW + 3600);

        VerificationPolicy marks = VerificationPolicy.trustMark().withClock(CLOCK);
        assertEquals(ISSUER, JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), marks).getIssuer());
        assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), ENTITY));
    }

    @Test
    void aPolicyWithoutKidOrTypStillAppliesTheClockAndSkew() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jwt = statement(signer, null, null, NOW - 10, NOW + 30);
        VerificationPolicy lenient = new VerificationPolicy(false, false, 0, null, CLOCK);

        assertEquals(ISSUER, JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), lenient).getIssuer());
        assertEquals(ISSUER, JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), ISSUER, Set.of(), null).getIssuer());
    }

    @Test
    void policyWithersKeepTheOtherSettings() {
        VerificationPolicy policy = VerificationPolicy.entityStatement().withClockSkewSeconds(5).withTyp("x+jwt");
        assertTrue(policy.requireKid());
        assertTrue(policy.requireIssuedAt());
        assertEquals(5, policy.clockSkewSeconds());
        assertEquals("x+jwt", policy.expectedTyp());
        assertEquals(Clock.systemUTC().getZone(), policy.effectiveClock().getZone());
        assertThrows(IllegalArgumentException.class, () -> policy.withClockSkewSeconds(-1));
        assertFalse(VerificationPolicy.legacy().requireKid());
    }

    // ---- messages never carry the token -------------------------------------------------------------

    @Test
    void aSignatureFailureMessageDoesNotContainTheToken() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        PublicJsonWebKey other = TestJwts.ec("k1");
        String jwt = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(other), ISSUER, Set.of()));

        assertNoTokenIn(e, jwt);
        assertEquals("signature", e.code());
        assertNull(e.getCause(), "the jose4j exception is not chained: a stack trace would print its message");
    }

    @Test
    void aClaimFailureMessageDoesNotContainTheClaims() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        JwtClaims claims = claims(NOW - 10, NOW + 3600);
        claims.setClaim("secret_marker", "do-not-log-me");
        String jwt = TestJwts.sign(signer, "ES256", null, claims);

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.verifyAgainstInlineJwks(jwt, jwks(signer), "https://someone-else.example", Set.of()));

        assertEquals(JwtVerificationException.Reason.ISSUER, e.reason());
        assertFalse(e.getMessage().contains("do-not-log-me"), e.getMessage());
        assertNoTokenIn(e, jwt);
    }

    @Test
    void anUnparseableTokenMessageDoesNotEchoTheInput() {
        String garbage = "eyJhbGciOiJFUzI1NiJ9.not-json-at-all.c2ln";

        JwtVerificationException e = assertThrows(JwtVerificationException.class,
                () -> JwtCodec.parseUnverifiedClaims(garbage));

        assertFalse(e.getMessage().contains("not-json-at-all"), e.getMessage());
        assertThrows(JwtVerificationException.class, () -> JwtCodec.getJwtHeaders(garbage + ".x.y"));
    }

    // ---- compact protected header --------------------------------------------------------------------

    @Test
    void readsTheProtectedHeaderOfAJwsAndOfAJwe() throws Exception {
        PublicJsonWebKey signer = TestJwts.ec("k1");
        String jws = statement(signer, "k1", "entity-statement+jwt", NOW - 10, NOW + 3600);
        assertEquals("k1", JwtCodec.compactProtectedHeader(jws).get("kid"));
        assertFalse(JwtCodec.isCompactJwe(jws));

        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(
                "{\"alg\":\"RSA-OAEP-256\",\"enc\":\"A256GCM\",\"kid\":\"enc-1\",\"trust_chain\":[\"a\"]}".getBytes(StandardCharsets.UTF_8));
        String jwe = header + ".a.b.c.d";
        Map<String, Object> read = JwtCodec.compactProtectedHeader(jwe);
        assertEquals("enc-1", read.get("kid"));
        assertEquals(List.of("a"), read.get("trust_chain"));
        assertTrue(JwtCodec.isCompactJwe(jwe));
        assertFalse(JwtCodec.isCompactJwe(null));
    }

    @Test
    void refusesSomethingThatIsNeitherAJwsNorAJwe() {
        assertThrows(JwtVerificationException.class, () -> JwtCodec.compactProtectedHeader(null));
        assertThrows(JwtVerificationException.class, () -> JwtCodec.compactProtectedHeader("a.b"));
        assertThrows(JwtVerificationException.class, () -> JwtCodec.compactProtectedHeader("!!!.b.c"));
        String notJson = Base64.getUrlEncoder().withoutPadding().encodeToString("[1,2]".getBytes(StandardCharsets.UTF_8));
        assertThrows(JwtVerificationException.class, () -> JwtCodec.compactProtectedHeader(notJson + ".b.c"));
    }

    // ---- translation of jose4j error codes -----------------------------------------------------------

    @Test
    void everyJose4jErrorCodeMapsToAStableReason() {
        assertReason(JwtVerificationException.Reason.EXPIRED, null, ErrorCodes.EXPIRED, ErrorCodes.ISSUER_INVALID);
        assertReason(JwtVerificationException.Reason.NOT_YET_VALID, null, ErrorCodes.NOT_YET_VALID);
        assertReason(JwtVerificationException.Reason.NOT_YET_VALID, null, ErrorCodes.ISSUED_AT_INVALID_FUTURE);
        assertReason(JwtVerificationException.Reason.SIGNATURE, null, ErrorCodes.SIGNATURE_INVALID);
        assertReason(JwtVerificationException.Reason.SIGNATURE, "unsigned", ErrorCodes.SIGNATURE_MISSING);
        assertReason(JwtVerificationException.Reason.ISSUER, null, ErrorCodes.ISSUER_INVALID);
        assertReason(JwtVerificationException.Reason.AUDIENCE, null, ErrorCodes.AUDIENCE_INVALID);
        assertReason(JwtVerificationException.Reason.SUBJECT, null, ErrorCodes.SUBJECT_INVALID);
        assertReason(JwtVerificationException.Reason.TYP, null, ErrorCodes.TYPE_INVALID);
        assertReason(JwtVerificationException.Reason.TYP, null, ErrorCodes.TYPE_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "iss", ErrorCodes.ISSUER_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "sub", ErrorCodes.SUBJECT_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "exp", ErrorCodes.EXPIRATION_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "iat", ErrorCodes.ISSUED_AT_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "nbf", ErrorCodes.NOT_BEFORE_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "jti", ErrorCodes.JWT_ID_MISSING);
        assertReason(JwtVerificationException.Reason.MISSING_CLAIM, "aud", ErrorCodes.AUDIENCE_MISSING);
        assertReason(JwtVerificationException.Reason.MALFORMED, null, ErrorCodes.JSON_INVALID);
        assertReason(JwtVerificationException.Reason.MALFORMED, null, ErrorCodes.MALFORMED_CLAIM);
        assertReason(JwtVerificationException.Reason.OTHER, "lifetime", ErrorCodes.EXPIRATION_TOO_FAR_IN_FUTURE);
        assertReason(JwtVerificationException.Reason.OTHER, "lifetime", ErrorCodes.ISSUED_AT_INVALID_PAST);
    }

    @Test
    void codeThatDrivesJose4jItselfGetsTheSameSafeTranslation() {
        org.jose4j.jwt.consumer.InvalidJwtException raw = new org.jose4j.jwt.consumer.InvalidJwtException(
                "JWT (claims->{\"sub\":\"alice\"}) rejected", List.of(new org.jose4j.jwt.consumer.ErrorCodeValidator.Error(
                        ErrorCodes.EXPIRED, "expired")), null);

        JwtVerificationException safe = JwtCodec.safe(raw);

        assertEquals(JwtVerificationException.Reason.EXPIRED, safe.reason());
        assertFalse(safe.getMessage().contains("alice"), safe.getMessage());
        assertEquals(List.of(ErrorCodes.EXPIRED), safe.joseErrorCodes());
    }

    @Test
    void aMiscellaneousFailureIsNamedByItsCause() {
        assertEquals(JwtVerificationException.Reason.ALGORITHM, JwtCodec.translate(List.of(ErrorCodes.MISCELLANEOUS),
                new RuntimeException(new InvalidAlgorithmException("no"))).reason());
        assertEquals(JwtVerificationException.Reason.KEY, JwtCodec.translate(List.of(ErrorCodes.MISCELLANEOUS),
                new UnresolvableKeyException("no")).reason());
        assertEquals(JwtVerificationException.Reason.MALFORMED, JwtCodec.translate(List.of(ErrorCodes.MISCELLANEOUS),
                new JoseException("no")).reason());
        assertEquals(JwtVerificationException.Reason.OTHER, JwtCodec.translate(List.of(ErrorCodes.MISCELLANEOUS),
                new IllegalStateException("no")).reason());
        assertEquals(JwtVerificationException.Reason.OTHER, JwtCodec.translate(List.of(), null).reason());
    }

    @Test
    void anExceptionCarriesItsCodeDetailAndErrorCodes() {
        JwtVerificationException e = new JwtVerificationException(null, " ", List.of(9));
        assertEquals(JwtVerificationException.Reason.OTHER, e.reason());
        assertEquals("JWT rejected (other): the token could not be verified", e.getMessage());
        assertEquals(List.of(9), e.joseErrorCodes());
        assertEquals(List.of(), new JwtVerificationException(JwtVerificationException.Reason.KEY, "x", null).joseErrorCodes());
        assertEquals("JWT rejected (key): no usable key matches the token's key id [x]",
                new JwtVerificationException(JwtVerificationException.Reason.KEY, "x").getMessage());
    }

    // ---- helpers --------------------------------------------------------------------------------------

    private static void assertReason(JwtVerificationException.Reason expected, String detail, Integer... codes) {
        JwtVerificationException e = JwtCodec.translate(List.of(codes), null);
        assertEquals(expected, e.reason(), "codes " + List.of(codes));
        assertEquals(detail, e.detail(), "codes " + List.of(codes));
    }

    private static void assertNoTokenIn(Exception e, String jwt) {
        String[] parts = jwt.split("\\.");
        for (String part : parts) {
            assertFalse(e.getMessage().contains(part), "message leaks a token segment: " + e.getMessage());
        }
        assertFalse(e.toString().contains(parts[1]), e.toString());
    }

    private static JwtClaims claims(long iat, long exp) {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setSubject(ISSUER);
        claims.setIssuedAt(NumericDate.fromSeconds(iat));
        claims.setExpirationTime(NumericDate.fromSeconds(exp));
        return claims;
    }

    private static String statement(PublicJsonWebKey key, String kid, String typ, long iat, long exp) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims(iat, exp).toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        if (kid != null) {
            jws.setKeyIdHeaderValue(kid);
        }
        return jws.getCompactSerialization();
    }

    private static Map<String, Object> jwks(PublicJsonWebKey... keys) {
        List<Map<String, Object>> list = new java.util.ArrayList<>();
        for (PublicJsonWebKey key : keys) {
            list.add(TestJwts.publicParams(key));
        }
        return Map.of("keys", list);
    }
}
