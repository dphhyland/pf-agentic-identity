package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * What the resource server checks.
 *
 * <p>Two tests here are the ones that would matter in an incident:
 * {@link #aProofFromADifferentKeyIsRejected} — without it, sender-constraining is decorative — and
 * {@link #aProofCapturedForAnotherTokenIsRejected}, the RFC 9449 {@code ath} binding, without which a
 * captured proof works against any token bound to the same key.
 */
class DelegatedTokenValidatorTest {

    private static final String ISSUER = "https://pf.example.com";
    private static final String AUDIENCE = "https://rs.example.com";
    private static final String RESOURCE_URL = "https://rs.example.com/orders";
    private static final String HUMAN = "pingone|alice";
    private static final String INSTANCE = "8Kx2_opaque_instance_id";

    private PublicJsonWebKey asKey;        // the authorisation server's signing key
    private PublicJsonWebKey enclaveKey;   // the key the token is bound to
    private DelegatedTokenValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        asKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        asKey.setKeyId("pf-1");
        enclaveKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enclaveKey.setKeyId("enclave-1");

        JsonWebKey asPublic = JsonWebKey.Factory.newJwk(
                asKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        validator = DelegatedTokenValidator.builder(ISSUER, AUDIENCE)
                .keys(List.of(asPublic))
                .replayStore(new InMemoryReplayStore())
                .build();
    }

    // ---- the happy path -----------------------------------------------------------------------

    @Test
    void aDelegatedSenderConstrainedTokenValidates() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        DelegatedTokenValidator.Result result =
                validator.validate(token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL),
                        "GET", RESOURCE_URL);

        assertEquals(HUMAN, result.subject());
        assertTrue(result.isDelegated());
        assertEquals(INSTANCE, result.actingInstance().orElseThrow());
        assertEquals(List.of("orders:read"), result.scopes());
    }

    @Test
    void whatIsEchoedCarriesNoDeviceDataOrRawToken() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        Map<String, Object> described = validator
                .validate(token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL)
                .describe();

        assertEquals(HUMAN, described.get("subject"));
        assertEquals(INSTANCE, described.get("acting_instance"));
        assertFalse(described.toString().contains(token), "the raw token must not be echoed");
        assertFalse(described.containsKey("device_id"));
        assertFalse(described.containsKey("cnf"));
    }

    // ---- sender constraining ---------------------------------------------------------------------

    /**
     * The whole point of DPoP. Validating a well-formed proof without comparing its key to the token's {@code cnf.jkt}
     * accepts a proof from anyone.
     *
     * <p>RFC 9449 §7.1: "For such an access token, a resource server MUST check that a DPoP proof was also received in
     * the DPoP header field of the HTTP request, check the DPoP proof according to the rules in Section 4.3, and check
     * that the public key of the DPoP proof matches the public key to which the access token is bound per Section 6."
     */
    @Test
    @Requirement({"RFC9449 §6.1", "RFC9449 §7.1"})
    void aProofFromADifferentKeyIsRejected() throws Exception {
        PublicJsonWebKey attackerKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        attackerKey.setKeyId("attacker");

        String stolenToken = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String attackerProof = dpopProof(attackerKey, stolenToken, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(stolenToken, attackerProof, "GET", RESOURCE_URL));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("bound to a different key"), e.getMessage());
    }

    /**
     * Without ath, a proof captured for one token replays against another.
     *
     * <p>RFC 9449 §4.3, item 12: "If presented to a protected resource in conjunction with an access token, ensure that
     * the value of the ath claim equals the hash of that access token, and confirm that the public key to which the
     * access token is bound matches the public key from the DPoP proof."
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofCapturedForAnotherTokenIsRejected() throws Exception {
        String tokenA = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String tokenB = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String proofForA = dpopProof(enclaveKey, tokenA, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(tokenB, proofForA, "GET", RESOURCE_URL));
        assertEquals("invalid_dpop_proof", e.error());
        assertTrue(e.getMessage().contains("different access token"), e.getMessage());
    }

    /**
     * RFC 9449 §4.3, item 12: "If presented to a protected resource in conjunction with an access token, ensure that
     * the value of the ath claim equals the hash of that access token, and confirm that the public key to which the
     * access token is bound matches the public key from the DPoP proof."
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofWithoutAthIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String proofWithoutAth = dpopProof(enclaveKey, null, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, proofWithoutAth, "GET", RESOURCE_URL));
        assertTrue(e.getMessage().contains("no 'ath'"), e.getMessage());
    }

    /**
     * Local policy: this resource has no bearer mode, so a token without cnf is refused even when a proof comes with
     * it.
     */
    @Test
    void aTokenWithNoCnfIsRefusedRatherThanTreatedAsBearer() throws Exception {
        String bearerish = accessTokenWithoutCnf();
        String proof = dpopProof(enclaveKey, bearerish, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(bearerish, proof, "GET", RESOURCE_URL));
        assertTrue(e.getMessage().contains("not sender-constrained"), e.getMessage());
    }

    /**
     * RFC 9449 §7.1: "For such an access token, a resource server MUST check that a DPoP proof was also received in the
     * DPoP header field of the HTTP request, check the DPoP proof according to the rules in Section 4.3, and check that
     * the public key of the DPoP proof matches the public key to which the access token is bound per Section 6."
     */
    @Test
    @Requirement("RFC9449 §7.1")
    void aMissingProofIsNotAFallbackToBearer() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, null, "GET", RESOURCE_URL));
        assertTrue(e.getMessage().contains("only sender-constrained"), e.getMessage());
    }

    /**
     * RFC 9449 §4.3, items 8 and 9: "The htm claim matches the HTTP method of the current request." "The htu claim
     * matches the HTTP URI value for the HTTP request in which the JWT was received, ignoring any query and fragment
     * parts."
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofForAnotherMethodOrUrlIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String proof = dpopProof(enclaveKey, token, "GET", RESOURCE_URL);

        assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, proof, "DELETE", RESOURCE_URL));
        assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, proof, "GET", "https://rs.example.com/somewhere-else"));
    }

    // ---- the token itself --------------------------------------------------------------------------

    /**
     * RFC 9068 §4: "The issuer identifier for the authorization server (which is typically obtained during discovery)
     * MUST exactly match the value of the "iss" claim."
     */
    @Test
    @Requirement("RFC8725 §3.8")
    void aTokenFromAnotherIssuerIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE), "https://evil.example.com",
                AUDIENCE, 300);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL));
    }

    /**
     * RFC 7519 §4.1.3: "If the principal processing the claim does not identify itself with a value in the "aud" claim
     * when this claim is present, then the JWT MUST be rejected."
     */
    @Test
    @Requirement({"RFC8725 §3.9", "RFC7519 §4.1.3"})
    void aTokenForAnotherResourceIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE), ISSUER,
                "https://other-rs.example.com", 300);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL));
    }

    /**
     * RFC 7519 §4.1.4: "The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST
     * NOT be accepted for processing."
     */
    @Test
    @Requirement("RFC7519 §4.1.4")
    void anExpiredTokenIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE), ISSUER, AUDIENCE, -3600);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL));
    }

    /**
     * RFC 9068 §4: "The resource server MUST validate the signature of all incoming JWT access tokens according to
     * [RFC7515] using the algorithm specified in the JWT "alg" Header Parameter."
     *
     * <p>RFC 7515 §5.2: "If any of the listed steps fails, then the signature or MAC cannot be validated."
     */
    @Test
    @Requirement("RFC7515 §5.2")
    void aTokenSignedByAnotherKeyIsRejected() throws Exception {
        PublicJsonWebKey rogue = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        rogue.setKeyId("pf-1");   // same kid, different key
        String forged = accessToken(rogue, enclaveKey, Map.of("sub", INSTANCE), ISSUER, AUDIENCE, 300);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(forged, dpopProof(enclaveKey, forged, "GET", RESOURCE_URL),
                        "GET", RESOURCE_URL));
        assertEquals("invalid_token", e.error());
    }

    /**
     * The classic RS256/HS256 confusion attack: sign with the AS's own public key material used as an
     * HMAC secret. This must fail before signature verification is even attempted, because {@code HS256}
     * is not in the permitted algorithm set — if it were reached, jose4j would happily "verify" against
     * whatever key object is supplied.
     */
    @Test
    @Requirement("RFC8725 §3.1")
    void anAlgorithmConfusionAttackIsRejected() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject(HUMAN);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5);
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jkt", Jwks.thumbprint(enclaveKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        claims.setClaim("cnf", cnf);

        JsonWebSignature forged = new JsonWebSignature();
        forged.setPayload(claims.toJson());
        forged.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        forged.setKeyIdHeaderValue(asKey.getKeyId());
        forged.setHeader("typ", "at+jwt");
        forged.setKey(new HmacKey(asKey.getPublicKey().getEncoded()));
        String forgedToken = forged.getCompactSerialization();

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(forgedToken, dpopProof(enclaveKey, forgedToken, "GET", RESOURCE_URL),
                        "GET", RESOURCE_URL));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("not permitted"), e.getMessage());
    }

    /**
     * RFC 9068 §4: "The resource server MUST use the keys provided by the authorization server."
     *
     * <p>A kid the server does not publish names none of those keys; refusing it rather than trying every key is local
     * policy.
     */
    @Test
    void aTokenWithAnUnrecognisedKidIsRejected() throws Exception {
        PublicJsonWebKey unknown = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        unknown.setKeyId("not-in-the-jwks");
        String token = accessToken(unknown, enclaveKey, Map.of("sub", INSTANCE), ISSUER, AUDIENCE, 300);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL),
                        "GET", RESOURCE_URL));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("no authorisation server key matches"), e.getMessage());
    }

    /**
     * RFC 9068 §4: "The resource server MUST reject any JWT in which the value of "alg" is "none"."
     */
    @Test
    @Requirement("RFC8725 §3.1")
    void aTokenWithTheNoneAlgorithmIsRejected() throws Exception {
        // jose4j refuses to *sign* with "none" (it is a blocked algorithm), so the classic unsecured-JWT
        // token is built by hand here, the way an attacker would.
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject(HUMAN);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5);
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jkt", Jwks.thumbprint(enclaveKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        claims.setClaim("cnf", cnf);

        String header = "{\"alg\":\"none\",\"typ\":\"at+jwt\"}";
        java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
        String noneToken = b64.encodeToString(header.getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + b64.encodeToString(claims.toJson().getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + ".";

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(noneToken, dpopProof(enclaveKey, noneToken, "GET", RESOURCE_URL),
                        "GET", RESOURCE_URL));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("not permitted"), e.getMessage());
    }

    // ---- delegation ----------------------------------------------------------------------------------

    @Test
    void anUndelegatedTokenIsReportedAsSuchRatherThanRejected() throws Exception {
        // A human calling directly is legitimate; the resource decides whether it wants that.
        String token = accessToken(enclaveKey, null);
        DelegatedTokenValidator.Result result = validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL);

        assertFalse(result.isDelegated());
        assertTrue(result.actingInstance().isEmpty());
    }

    /** RFC 8693 §4.1: "The "act" claim value is a JSON object". The string form is refused by default. */
    @Test
    @Requirement("RFC8693 §4.1")
    void theLegacyStringActIsRefusedByDefault() throws Exception {
        String token = accessToken(enclaveKey, null, ISSUER, AUDIENCE, 300,
                Map.of("act", "{\"sub\":\"" + INSTANCE + "\"}"));
        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET",
                        RESOURCE_URL));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("act claim is a string"), e.getMessage());
    }

    @Test
    @Requirement("UNVERIFIED item 8")
    void theLegacyStringActIsSurfacedWhereDevelopmentAllowsIt() throws Exception {
        DelegatedTokenValidator lenient = DelegatedTokenValidator.builder(ISSUER, AUDIENCE)
                .keys(List.of(JsonWebKey.Factory.newJwk(asKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))))
                .replayStore(new InMemoryReplayStore())
                .allowLegacyStringAct(DeploymentProfile.DEVELOPMENT)
                .build();
        String token = accessToken(enclaveKey, null, ISSUER, AUDIENCE, 300,
                Map.of("act", "{\"sub\":\"" + INSTANCE + "\"}"));
        DelegatedTokenValidator.Result result = lenient.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL);

        assertEquals(INSTANCE, result.actingInstance().orElseThrow());
        assertEquals(Boolean.TRUE, result.describe().get("act_legacy_string_form"));
    }

    @Test
    void theLegacyStringActCannotBeSwitchedOnInProduction() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> DelegatedTokenValidator.builder(ISSUER, AUDIENCE)
                        .keys(List.of(JsonWebKey.Factory.newJwk(asKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))))
                        .replayStore(new InMemoryReplayStore())
                        .allowLegacyStringAct(DeploymentProfile.PRODUCTION).build());
        assertTrue(e.getMessage().contains("development"), e.getMessage());
    }

    /** The public switch reads this process's profile itself: unset, as in CI, is production, and build() throws. */
    @Test
    void thePublicSwitchReadsTheProcessProfile() throws Exception {
        DelegatedTokenValidator.Builder b = DelegatedTokenValidator.builder(ISSUER, AUDIENCE)
                .keys(List.of(JsonWebKey.Factory.newJwk(asKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))))
                .replayStore(new InMemoryReplayStore());
        assertSame(b, b.allowLegacyStringAct());
        if (DeploymentProfile.current().isDevelopment()) {
            b.build();
        } else {
            assertThrows(IllegalStateException.class, b::build);
        }
    }

    @Test
    void theDpopJtiIsReportedSoTheCallerCanReplayCacheIt() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        DelegatedTokenValidator.Result result = validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL);
        assertTrue(result.dpopJti() != null && !result.dpopJti().isBlank(),
                "without a jti the caller cannot detect a replayed proof");
    }

    // ---- builders -------------------------------------------------------------------------------------

    private String accessToken(PublicJsonWebKey boundTo, Map<String, Object> act) throws Exception {
        return accessToken(asKey, boundTo, act, ISSUER, AUDIENCE, 300, Map.of());
    }

    private String accessToken(PublicJsonWebKey boundTo, Map<String, Object> act, String issuer,
                               String audience, int expiresInSeconds) throws Exception {
        return accessToken(asKey, boundTo, act, issuer, audience, expiresInSeconds, Map.of());
    }

    private String accessToken(PublicJsonWebKey signingKey, PublicJsonWebKey boundTo,
                               Map<String, Object> act, String issuer, String audience,
                               int expiresInSeconds) throws Exception {
        return accessToken(signingKey, boundTo, act, issuer, audience, expiresInSeconds, Map.of());
    }

    private String accessToken(PublicJsonWebKey boundTo, Map<String, Object> act, String issuer,
                               String audience, int expiresInSeconds, Map<String, Object> extra)
            throws Exception {
        return accessToken(asKey, boundTo, act, issuer, audience, expiresInSeconds, extra);
    }

    private String accessToken(PublicJsonWebKey signingKey, PublicJsonWebKey boundTo,
                               Map<String, Object> act, String issuer, String audience,
                               int expiresInSeconds, Map<String, Object> extra) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setAudience(audience);
        claims.setSubject(HUMAN);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expiresInSeconds));
        claims.setClaim("scope", "orders:read");
        if (act != null) {
            claims.setClaim("act", act);
        }
        extra.forEach(claims::setClaim);
        if (boundTo != null) {
            Map<String, Object> cnf = new LinkedHashMap<>();
            cnf.put("jkt", Jwks.thumbprint(boundTo.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
            claims.setClaim("cnf", cnf);
        }
        return sign(signingKey, claims);
    }

    private String accessTokenWithoutCnf() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject(HUMAN);
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5);
        return sign(asKey, claims);
    }

    private static String sign(PublicJsonWebKey key, JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setHeader("typ", "at+jwt");
        return jws.getCompactSerialization();
    }

    /** A DPoP proof. Pass a null token to omit {@code ath}. */
    private static String dpopProof(PublicJsonWebKey key, String accessToken, String method, String url)
            throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", method);
        claims.setClaim("htu", url);
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        if (accessToken != null) {
            claims.setClaim("ath", DelegatedTokenValidator.accessTokenHash(accessToken));
        }
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "dpop+jwt");
        jws.getHeaders().setJwkHeaderValue("jwk",
                PublicJsonWebKey.Factory.newPublicJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return jws.getCompactSerialization();
    }
}
