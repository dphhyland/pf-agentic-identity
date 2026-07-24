/*
 * GkeTokenValidator maps a verified GKE service-account token onto its canonical SPIFFE ID.
 */
package com.pingidentity.ps.oidf.common;

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

class GkeTokenValidatorTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLUSTER_ISSUER =
            "https://container.googleapis.com/v1/projects/demo-project/locations/us-central1-a/clusters/spiffe-demo";
    private static final String TRUST_DOMAIN = "demo-project.svc.id.goog";

    private final GkeTokenValidator validator = new GkeTokenValidator();
    private PublicJsonWebKey clusterKey;
    private List<JsonWebKey> bundle;
    private AttestationIssuanceConfig config;

    @BeforeEach
    void setUp() throws Exception {
        this.clusterKey = TestJwts.ec("gke-key-1");
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.clusterKey));
        this.bundle = List.of(pub);
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN);
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
    void mapsVerifiedTokenOntoCanonicalSpiffeId() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:payment-agent", ATTESTER, 600);
        SpiffeSvid svid = this.validator.validate(token, this.bundle, this.config);
        assertEquals("spiffe://demo-project.svc.id.goog/ns/demo/sa/payment-agent", svid.spiffeId());
        assertEquals(TRUST_DOMAIN, svid.trustDomain());
        assertEquals("/ns/demo/sa/payment-agent", svid.path());
        assertEquals(List.of(ATTESTER), svid.audiences());
        assertEquals(token, svid.raw());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = token("https://kubernetes.default.svc", "system:serviceaccount:demo:payment-agent",
                ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void nonServiceAccountSubjectIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "spiffe://demo-project.svc.id.goog/ns/demo/sa/payment-agent",
                ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:payment-agent",
                "https://other.example.com", 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:payment-agent", ATTESTER, -600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void unknownKidIsRejected() throws Exception {
        PublicJsonWebKey otherKey = TestJwts.ec("not-in-bundle");
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(CLUSTER_ISSUER);
        claims.setSubject("system:serviceaccount:demo:payment-agent");
        claims.setAudience(ATTESTER);
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        String token = TestJwts.sign(otherKey, "ES256", null, claims);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }
}
