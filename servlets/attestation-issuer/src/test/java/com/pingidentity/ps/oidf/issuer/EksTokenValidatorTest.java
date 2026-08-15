/*
 * EksTokenValidator maps a verified EKS IRSA service-account token onto a SPIFFE ID.
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

class EksTokenValidatorTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLUSTER_ISSUER = "https://oidc.eks.us-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE";
    private static final String TRUST_DOMAIN = "eks.demo.aws";

    private final EksTokenValidator validator = new EksTokenValidator();
    private PublicJsonWebKey clusterKey;
    private List<JsonWebKey> bundle;
    private AttestationIssuanceConfig config;

    @BeforeEach
    void setUp() throws Exception {
        this.clusterKey = TestJwts.ec("eks-key-1");
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.clusterKey));
        this.bundle = List.of(pub);
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_EKS_SA_TOKEN);
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, TRUST_DOMAIN);
        props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, CLUSTER_ISSUER);
        this.config = AttestationIssuanceConfig.fromProperties(props);
    }

    private String token(String issuer, String subject, String audience, long expOffsetSeconds) throws Exception {
        JwtClaims claims = new JwtClaims();
        if (issuer != null) {
            claims.setIssuer(issuer);
        }
        if (subject != null) {
            claims.setSubject(subject);
        }
        if (audience != null) {
            claims.setAudience(audience);
        }
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffsetSeconds));
        claims.setIssuedAtToNow();
        return TestJwts.sign(this.clusterKey, "ES256", null, claims);
    }

    @Test
    void mapsVerifiedTokenOntoSpiffeId() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:payment-agent", ATTESTER, 600);
        SpiffeSvid svid = this.validator.validateSvid(token, this.bundle, this.config);
        assertEquals("spiffe://eks.demo.aws/ns/demo/sa/payment-agent", svid.spiffeId());
        assertEquals(TRUST_DOMAIN, svid.trustDomain());
        assertEquals("/ns/demo/sa/payment-agent", svid.path());
        assertEquals(List.of(ATTESTER), svid.audiences());
        assertEquals(token, svid.raw());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = token("https://oidc.eks.us-west-2.amazonaws.com/id/OTHER",
                "system:serviceaccount:demo:payment-agent", ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void nonServiceAccountSubjectIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "arn:aws:iam::123456789012:role/SomeRole", ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:payment-agent",
                "https://other.example.com", 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:payment-agent", ATTESTER, -600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }
}
