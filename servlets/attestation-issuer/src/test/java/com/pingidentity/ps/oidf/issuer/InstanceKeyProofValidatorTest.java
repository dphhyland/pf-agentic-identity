package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
 * The instance-key proof's validity window (plan item S4c, finding F-0036). CAS §4.3: "{@code iat} (REQUIRED),
 * {@code exp} (REQUIRED, SHOULD be ≤ 5 minutes after {@code iat})"; "The CAS MUST [...] enforce {@code exp} with
 * small clock skew, and reject replayed {@code jti} values within the proof validity window."
 */
class InstanceKeyProofValidatorTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final long T = 1_900_000_000L;
    private static final long SKEW = 60L;

    private PublicJsonWebKey instanceKey;

    @BeforeEach
    void setUp() throws Exception {
        instanceKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        instanceKey.setKeyId("instance-1");
    }

    private static InstanceKeyProofValidator at(long nowEpochSeconds) {
        return new InstanceKeyProofValidator(InstanceKeyProofValidator.MAX_WINDOW_SECONDS, SKEW,
                Clock.fixed(Instant.ofEpochSecond(nowEpochSeconds), ZoneOffset.UTC));
    }

    private String proof(Long iat, Long exp) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(ISSUER);
        claims.setJwtId(UUID.randomUUID().toString());
        if (iat != null) {
            claims.setIssuedAt(NumericDate.fromSeconds(iat));
        }
        if (exp != null) {
            claims.setExpirationTime(NumericDate.fromSeconds(exp));
        }
        return sign(claims);
    }

    private String sign(JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(instanceKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", InstanceKeyProofValidator.TYP);
        return jws.getCompactSerialization();
    }

    private Map<String, Object> publicJwk() {
        return instanceKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    private void assertWindowRefused(InstanceKeyProofValidator validator, String proof) {
        IssuanceException e = assertThrows(IssuanceException.class, () -> validator.validate(proof, publicJwk(), ISSUER));
        assertEquals("invalid_instance_proof", e.error());
        assertEquals(InstanceKeyProofValidator.WINDOW_REFUSED, e.getMessage(),
                "every window refusal carries the one generic description, never the values sent");
    }

    @Test
    @Requirement("CAS §4.3")
    void aProofWithoutIatIsRefused() throws Exception {
        assertWindowRefused(at(T), proof(null, T + 120));
    }

    @Test
    @Requirement("CAS §4.3")
    void aProofWithoutExpIsRefused() throws Exception {
        // What every client-attestation-sdk-polyglot language sent before S4c: iat, jti, aud and no exp.
        assertWindowRefused(at(T), proof(T, null));
    }

    @Test
    @Requirement("CAS §4.3")
    void aWindowLongerThanFiveMinutesIsRefused() throws Exception {
        assertWindowRefused(at(T), proof(T, T + 301));
        InstanceKeyProofValidator.Result ok = at(T).validate(proof(T, T + 300), publicJwk(), ISSUER);
        assertEquals(T + 300 + SKEW, ok.retainUntilEpochSeconds());
    }

    @Test
    @Requirement("CAS §4.3")
    void anExpNotAfterIatIsRefused() throws Exception {
        assertWindowRefused(at(T), proof(T, T - 1));
        assertWindowRefused(at(T), proof(T, T));
    }

    @Test
    @Requirement("CAS §4.3")
    void theWindowOpensAtIatLessTheSkew() throws Exception {
        long iat = T + SKEW;
        at(T).validate(proof(iat, iat + 120), publicJwk(), ISSUER);
        assertWindowRefused(at(T - 1), proof(iat, iat + 120));
    }

    @Test
    @Requirement("CAS §4.3")
    void theWindowClosesAtExpPlusTheSkew() throws Exception {
        long exp = T + 120;
        InstanceKeyProofValidator.Result last = at(exp + SKEW).validate(proof(T, exp), publicJwk(), ISSUER);
        assertEquals(exp + SKEW, last.retainUntilEpochSeconds(),
                "the jti is remembered until the last second the proof can be accepted");
        assertWindowRefused(at(exp + SKEW + 1), proof(T, exp));
    }

    @Test
    void claimsThatAreNotNumbersOrWouldOverflowAreRefused() throws Exception {
        JwtClaims text = new JwtClaims();
        text.setAudience(ISSUER);
        text.setJwtId("j");
        text.setClaim("iat", "yesterday");
        text.setClaim("exp", T + 60);
        assertWindowRefused(at(T), sign(text));
        // A window that wraps: exp - iat overflows to a small negative number.
        assertWindowRefused(at(T), proof(Long.MIN_VALUE + 10, Long.MAX_VALUE - 10));
    }

    @Test
    void theWindowAndSkewAreBounded() {
        Clock clock = Clock.systemUTC();
        assertThrows(IllegalArgumentException.class, () -> new InstanceKeyProofValidator(0L, SKEW, clock));
        assertThrows(IllegalArgumentException.class, () -> new InstanceKeyProofValidator(301L, SKEW, clock));
        assertThrows(IllegalArgumentException.class, () -> new InstanceKeyProofValidator(300L, -1L, clock));
        assertThrows(NullPointerException.class, () -> new InstanceKeyProofValidator(300L, SKEW, null));
        assertEquals(Clock.systemUTC(), new InstanceKeyProofValidator().clock());
        assertEquals(Clock.systemUTC(), new InstanceKeyProofValidator(120L, 0L).clock());
    }
}
