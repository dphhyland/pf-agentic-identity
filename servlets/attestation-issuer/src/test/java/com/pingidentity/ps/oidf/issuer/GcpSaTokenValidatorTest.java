/*
 * GcpSaTokenValidator maps a verified Google SA ID token onto spiffe://<td>/sa/<email>.
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class GcpSaTokenValidatorTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String GOOGLE_ISSUER = "https://accounts.google.com";
    private static final String TRUST_DOMAIN = "demo-project.gcp.banking.demo";
    private static final String SA_EMAIL = "agent-runtime@demo-project.iam.gserviceaccount.com";

    private final GcpSaTokenValidator validator = new GcpSaTokenValidator();
    private PublicJsonWebKey googleKey;
    private List<JsonWebKey> bundle;
    private AttestationIssuanceConfig config;

    @BeforeEach
    void setUp() throws Exception {
        this.googleKey = TestJwts.rsa("google-key-1");
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.googleKey));
        this.bundle = List.of(pub);
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN);
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, TRUST_DOMAIN);
        props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, GOOGLE_ISSUER);
        this.config = AttestationIssuanceConfig.fromProperties(props);
    }

    private String token(String issuer, String email, String audience, long expOffsetSeconds) throws Exception {
        JwtClaims claims = new JwtClaims();
        if (issuer != null) {
            claims.setIssuer(issuer);
        }
        claims.setSubject("103954711982461927465"); // Google SA ID tokens carry an opaque numeric sub
        if (email != null) {
            claims.setClaim("email", email);
        }
        if (audience != null) {
            claims.setAudience(audience);
        }
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffsetSeconds));
        claims.setIssuedAtToNow();
        return TestJwts.sign(this.googleKey, "RS256", null, claims);
    }

    @Test
    void mapsVerifiedTokenOntoServiceAccountSpiffeId() throws Exception {
        String token = token(GOOGLE_ISSUER, SA_EMAIL, ATTESTER, 600);
        SpiffeSvid svid = this.validator.validateSvid(token, this.bundle, this.config);
        assertEquals("spiffe://" + TRUST_DOMAIN + "/sa/" + SA_EMAIL, svid.spiffeId());
        assertEquals(TRUST_DOMAIN, svid.trustDomain());
        assertEquals("/sa/" + SA_EMAIL, svid.path());
        assertEquals(token, svid.raw());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = token("https://evil.example.com", SA_EMAIL, ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void missingEmailIsRejected() throws Exception {
        String token = token(GOOGLE_ISSUER, null, ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String token = token(GOOGLE_ISSUER, SA_EMAIL, "https://other.example.com", 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = token(GOOGLE_ISSUER, SA_EMAIL, ATTESTER, -600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void gcpEvidenceRequiresATrustDomain() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE_URL, "https://www.googleapis.com/oauth2/v3/certs");
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }
}
