package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.common.Jwks;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
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
        validator = new DelegatedTokenValidator(List.of(asPublic), ISSUER, AUDIENCE);
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
     * The whole point of DPoP. Validating a well-formed proof without comparing its key to the token's
     * {@code cnf.jkt} accepts a proof from anyone.
     */
    @Test
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

    /** RFC 9449 §4.3: without ath, a proof captured for one token replays against another. */
    @Test
    void aProofCapturedForAnotherTokenIsRejected() throws Exception {
        String tokenA = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String tokenB = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String proofForA = dpopProof(enclaveKey, tokenA, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(tokenB, proofForA, "GET", RESOURCE_URL));
        assertEquals("invalid_dpop_proof", e.error());
        assertTrue(e.getMessage().contains("different access token"), e.getMessage());
    }

    @Test
    void aProofWithoutAthIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String proofWithoutAth = dpopProof(enclaveKey, null, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, proofWithoutAth, "GET", RESOURCE_URL));
        assertTrue(e.getMessage().contains("no 'ath'"), e.getMessage());
    }

    @Test
    void aTokenWithNoCnfIsRefusedRatherThanTreatedAsBearer() throws Exception {
        String bearerish = accessTokenWithoutCnf();
        String proof = dpopProof(enclaveKey, bearerish, "GET", RESOURCE_URL);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(bearerish, proof, "GET", RESOURCE_URL));
        assertTrue(e.getMessage().contains("not sender-constrained"), e.getMessage());
    }

    @Test
    void aMissingProofIsNotAFallbackToBearer() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, null, "GET", RESOURCE_URL));
        assertTrue(e.getMessage().contains("only sender-constrained"), e.getMessage());
    }

    @Test
    void aProofForAnotherMethodOrUrlIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE));
        String proof = dpopProof(enclaveKey, token, "GET", RESOURCE_URL);

        assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, proof, "DELETE", RESOURCE_URL));
        assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(token, proof, "GET", "https://rs.example.com/somewhere-else"));
    }

    // ---- the token itself --------------------------------------------------------------------------

    @Test
    void aTokenFromAnotherIssuerIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE), "https://evil.example.com",
                AUDIENCE, 300);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL));
    }

    @Test
    void aTokenForAnotherResourceIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE), ISSUER,
                "https://other-rs.example.com", 300);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL));
    }

    @Test
    void anExpiredTokenIsRejected() throws Exception {
        String token = accessToken(enclaveKey, Map.of("sub", INSTANCE), ISSUER, AUDIENCE, -3600);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL));
    }

    @Test
    void aTokenSignedByAnotherKeyIsRejected() throws Exception {
        PublicJsonWebKey rogue = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        rogue.setKeyId("pf-1");   // same kid, different key
        String forged = accessToken(rogue, enclaveKey, Map.of("sub", INSTANCE), ISSUER, AUDIENCE, 300);

        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> validator.validate(forged, dpopProof(enclaveKey, forged, "GET", RESOURCE_URL),
                        "GET", RESOURCE_URL));
        assertEquals("invalid_token", e.error());
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

    @Test
    void theLegacyStringActIsSurfacedSoTheDeviationIsVisible() throws Exception {
        String token = accessToken(enclaveKey, null, ISSUER, AUDIENCE, 300,
                Map.of("act", "{\"sub\":\"" + INSTANCE + "\"}"));
        DelegatedTokenValidator.Result result = validator.validate(
                token, dpopProof(enclaveKey, token, "GET", RESOURCE_URL), "GET", RESOURCE_URL);

        assertEquals(INSTANCE, result.actingInstance().orElseThrow());
        assertEquals(Boolean.TRUE, result.describe().get("act_legacy_string_form"));
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
