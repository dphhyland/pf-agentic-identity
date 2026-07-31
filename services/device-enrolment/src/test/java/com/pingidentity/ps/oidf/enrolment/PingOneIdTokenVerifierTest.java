package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The PingOne ID-token verifier, against a locally minted key rather than the live tenant.
 *
 * <p>Values here match the real environment: issuer
 * {@code https://auth.pingone.asia/fe8ab8dc-.../as}, RS256, and {@code acr} carrying a sign-on policy
 * name (this environment advertises no {@code acr_values_supported}, so the mapping is configuration).
 */
class PingOneIdTokenVerifierTest {

    private static final String ISSUER =
            "https://auth.pingone.asia/fe8ab8dc-0dbb-4da4-8ee5-004cb3a6f21d/as";
    private static final String CLIENT_ID = "98d2bb66-3568-4ecd-b4cd-6ee8625b1ccc";
    private static final String PASSKEY_POLICY = "Passkeys Sign On";

    private RsaJsonWebKey signingKey;
    private PingOneIdTokenVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = RsaJwkGenerator.generateJwk(2048);
        signingKey.setKeyId("pingone-1");
        verifier = new PingOneIdTokenVerifier(ISSUER, CLIENT_ID,
                kid -> signingKey,
                Map.of(PASSKEY_POLICY, UserAuthentication.AssuranceLevel.AAL2));
    }

    private String idToken(JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("RS256");
        jws.setKeyIdHeaderValue(signingKey.getKeyId());
        return jws.getCompactSerialization();
    }

    private JwtClaims validClaims() {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(CLIENT_ID);
        claims.setSubject("a1b2c3-user");
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setClaim("auth_time", NumericDate.now().getValue());
        claims.setClaim("acr", PASSKEY_POLICY);
        return claims;
    }

    @Test
    void aValidTokenYieldsTheSubjectAndAal2() throws Exception {
        UserAuthentication result = verifier.verify(idToken(validClaims()));
        assertEquals("a1b2c3-user", result.subject());
        assertEquals(UserAuthentication.AssuranceLevel.AAL2, result.assuranceLevel());
        assertTrue(result.meetsAssurance(UserAuthentication.AssuranceLevel.AAL2));
        // PingOne does not put the credential id in the ID token; it is looked up separately rather
        // than invented.
        assertNull(result.credentialId());
    }

    /**
     * The time-box is measured from {@code auth_time}, so it cannot be inferred. Falling back to
     * {@code iat} would let a client hold an old authentication and present it inside a freshly minted
     * token — precisely the window the time-box closes.
     */
    @Test
    void authTimeIsRequiredRatherThanInferredFromIat() throws Exception {
        JwtClaims claims = validClaims();
        claims.unsetClaim("auth_time");

        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> verifier.verify(idToken(claims)));
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED, e.error());
        assertTrue(e.getMessage().contains("auth_time"), e.getMessage());
    }

    @Test
    void authTimeIsCarriedThroughRatherThanReplacedWithNow() throws Exception {
        long tenMinutesAgo = NumericDate.now().getValue() - 600;
        JwtClaims claims = validClaims();
        claims.setClaim("auth_time", tenMinutesAgo);

        UserAuthentication result = verifier.verify(idToken(claims));
        assertEquals(Instant.ofEpochSecond(tenMinutesAgo), result.authenticatedAt());
        // A stale authentication is reported honestly; the service decides whether it is fresh enough.
    }

    /**
     * The direction of this default matters. PingOne puts the applied sign-on policy in acr, so an
     * unrecognised value means the user came through a policy nobody vetted — that must read as the
     * lowest assurance, never the highest.
     */
    @Test
    void anUnrecognisedAcrFallsToTheLowestAssurance() throws Exception {
        JwtClaims claims = validClaims();
        claims.setClaim("acr", "Some Other Policy");

        UserAuthentication result = verifier.verify(idToken(claims));
        assertEquals(UserAuthentication.AssuranceLevel.AAL1, result.assuranceLevel());
        assertTrue(!result.meetsAssurance(UserAuthentication.AssuranceLevel.AAL2),
                "an unvetted policy must not satisfy the binding requirement");
    }

    @Test
    void aMissingAcrAlsoFallsToTheLowestAssurance() throws Exception {
        JwtClaims claims = validClaims();
        claims.unsetClaim("acr");
        assertEquals(UserAuthentication.AssuranceLevel.AAL1,
                verifier.verify(idToken(claims)).assuranceLevel());
    }

    @Test
    void aTokenFromAnotherIssuerIsRefused() throws Exception {
        JwtClaims claims = validClaims();
        claims.setIssuer("https://auth.pingone.eu/some-other-env/as");
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED,
                assertThrows(EnrolmentException.class, () -> verifier.verify(idToken(claims))).error());
    }

    @Test
    void aTokenForAnotherApplicationIsRefused() throws Exception {
        JwtClaims claims = validClaims();
        claims.setAudience("some-other-client-id");
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED,
                assertThrows(EnrolmentException.class, () -> verifier.verify(idToken(claims))).error());
    }

    @Test
    void anExpiredTokenIsRefused() throws Exception {
        JwtClaims claims = validClaims();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() - 3600));
        assertTrue(assertThrows(EnrolmentException.class,
                () -> verifier.verify(idToken(claims))).getMessage().contains("expired"));
    }

    @Test
    void aTokenSignedByAnotherKeyIsRefused() throws Exception {
        RsaJsonWebKey attacker = RsaJwkGenerator.generateJwk(2048);
        attacker.setKeyId("pingone-1");   // same kid, different key
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(validClaims().toJson());
        jws.setKey(attacker.getPrivateKey());
        jws.setAlgorithmHeaderValue("RS256");
        jws.setKeyIdHeaderValue("pingone-1");

        String forged = jws.getCompactSerialization();
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED,
                assertThrows(EnrolmentException.class, () -> verifier.verify(forged)).error());
    }

    /** Algorithm substitution: the environment advertises RS256 only, so anything else is refused. */
    @Test
    void aNonRs256TokenIsRefused() throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(validClaims().toJson());
        jws.setAlgorithmHeaderValue("none");
        jws.setAlgorithmConstraints(org.jose4j.jwa.AlgorithmConstraints.ALLOW_ONLY_NONE);
        String unsigned = jws.getCompactSerialization();

        EnrolmentException e = assertThrows(EnrolmentException.class, () -> verifier.verify(unsigned));
        assertTrue(e.getMessage().contains("RS256"), e.getMessage());
    }

    @Test
    void anUnknownKidIsRefusedRatherThanFallingBackToAnyKey() {
        PingOneIdTokenVerifier strict = new PingOneIdTokenVerifier(ISSUER, CLIENT_ID,
                kid -> null, Map.of(PASSKEY_POLICY, UserAuthentication.AssuranceLevel.AAL2));
        EnrolmentException e = assertThrows(EnrolmentException.class,
                () -> strict.verify(idToken(validClaims())));
        assertTrue(e.getMessage().contains("no PingOne signing key"), e.getMessage());
    }

    @Test
    void garbageIsRefused() {
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED,
                assertThrows(EnrolmentException.class, () -> verifier.verify("not-a-jwt")).error());
        assertEquals(EnrolmentException.USER_AUTHENTICATION_FAILED,
                assertThrows(EnrolmentException.class, () -> verifier.verify("")).error());
    }

    /** The JWKS cache must refetch on an unknown kid, or a key rotation becomes an outage. */
    @Test
    void theKeySourceIsConsultedForEachDistinctKid() throws Exception {
        List<String> asked = new java.util.ArrayList<>();
        PingOneIdTokenVerifier tracking = new PingOneIdTokenVerifier(ISSUER, CLIENT_ID,
                kid -> {
                    asked.add(kid);
                    return signingKey;
                },
                Map.of(PASSKEY_POLICY, UserAuthentication.AssuranceLevel.AAL2));

        tracking.verify(idToken(validClaims()));
        assertEquals(List.of("pingone-1"), asked);
    }

    @Test
    void theJwksSourceIsAFunctionalSeam() throws Exception {
        // Documents the contract the HTTP implementation satisfies: given a kid, return a key or null.
        PingOneIdTokenVerifier.JwksSource source = kid -> signingKey;
        JsonWebKey key = source.find("anything");
        assertEquals("pingone-1", key.getKeyId());
    }
}
