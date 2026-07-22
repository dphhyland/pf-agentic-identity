package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SpiffeSvidValidatorTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final String SPIFFE_ID = "spiffe://banking.demo/payment-agent";
    private static final String TRUST_DOMAIN = "banking.demo";

    private PublicJsonWebKey bundleKey;
    private List<JsonWebKey> bundle;
    private SpiffeSvidValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        bundleKey = TestJwts.ec("svid-key-1");
        bundle = List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(bundleKey)));
        validator = new SpiffeSvidValidator();
    }

    private String svid(PublicJsonWebKey signingKey, String sub, String audience, long expOffsetSeconds) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(sub);
        claims.setAudience(audience);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffsetSeconds));
        return TestJwts.sign(signingKey, "ES256", "JWT", claims);
    }

    @Test
    void validSvidIsAccepted() throws Exception {
        SpiffeSvid parsed = validator.validate(svid(bundleKey, SPIFFE_ID, ISSUER, 600L), bundle, ISSUER, TRUST_DOMAIN);
        assertEquals(SPIFFE_ID, parsed.spiffeId());
        assertEquals(TRUST_DOMAIN, parsed.trustDomain());
        assertEquals("/payment-agent", parsed.path());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String s = svid(bundleKey, SPIFFE_ID, "https://someone-else.example.com", 600L);
        IssuanceException e = assertThrows(IssuanceException.class, () -> validator.validate(s, bundle, ISSUER, null));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredSvidIsRejected() throws Exception {
        String s = svid(bundleKey, SPIFFE_ID, ISSUER, -600L);
        IssuanceException e = assertThrows(IssuanceException.class, () -> validator.validate(s, bundle, ISSUER, null));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongTrustDomainIsRejected() throws Exception {
        String s = svid(bundleKey, SPIFFE_ID, ISSUER, 600L);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> validator.validate(s, bundle, ISSUER, "other.domain"));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void unknownKidIsRejected() throws Exception {
        PublicJsonWebKey otherKey = TestJwts.ec("some-other-kid");
        String s = svid(otherKey, SPIFFE_ID, ISSUER, 600L);
        IssuanceException e = assertThrows(IssuanceException.class, () -> validator.validate(s, bundle, ISSUER, null));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void badSignatureIsRejected() throws Exception {
        // Signed by a key that shares the bundle kid but is a different key → signature must not verify.
        PublicJsonWebKey impostor = TestJwts.ec("svid-key-1");
        String s = svid(impostor, SPIFFE_ID, ISSUER, 600L);
        IssuanceException e = assertThrows(IssuanceException.class, () -> validator.validate(s, bundle, ISSUER, null));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void malformedSpiffeIdIsRejected() throws Exception {
        String s = svid(bundleKey, "https://not-a-spiffe-id", ISSUER, 600L);
        IssuanceException e = assertThrows(IssuanceException.class, () -> validator.validate(s, bundle, ISSUER, null));
        assertEquals("invalid_svid", e.error());
    }
}
