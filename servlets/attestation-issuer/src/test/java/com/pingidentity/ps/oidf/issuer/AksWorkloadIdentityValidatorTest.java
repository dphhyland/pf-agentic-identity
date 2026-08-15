/*
 * AksWorkloadIdentityValidator maps a verified AKS Workload Identity Federation service-account token onto
 * a SPIFFE ID.
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

class AksWorkloadIdentityValidatorTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLUSTER_ISSUER =
            "https://australiaeast.oic.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/EXAMPLE/";
    private static final String TRUST_DOMAIN = "aks.demo.azure";

    private final AksWorkloadIdentityValidator validator = new AksWorkloadIdentityValidator();
    private PublicJsonWebKey clusterKey;
    private List<JsonWebKey> bundle;
    private AttestationIssuanceConfig config;

    @BeforeEach
    void setUp() throws Exception {
        this.clusterKey = TestJwts.ec("aks-key-1");
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.clusterKey));
        this.bundle = List.of(pub);
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_AKS_SA_TOKEN);
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
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:gateway-agent", ATTESTER, 600);
        SpiffeSvid svid = this.validator.validateSvid(token, this.bundle, this.config);
        assertEquals("spiffe://aks.demo.azure/ns/demo/sa/gateway-agent", svid.spiffeId());
        assertEquals(TRUST_DOMAIN, svid.trustDomain());
        assertEquals("/ns/demo/sa/gateway-agent", svid.path());
        assertEquals(List.of(ATTESTER), svid.audiences());
        assertEquals(token, svid.raw());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = token(
                "https://australiaeast.oic.prod-aks.azure.com/00000000-0000-0000-0000-000000000000/OTHER/",
                "system:serviceaccount:demo:gateway-agent", ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void nonServiceAccountSubjectIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER,
                "/subscriptions/00000000/resourcegroups/demo/providers/Microsoft.ManagedIdentity/"
                        + "userAssignedIdentities/gateway-mi",
                ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:gateway-agent",
                "https://other.example.com", 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = token(CLUSTER_ISSUER, "system:serviceaccount:demo:gateway-agent", ATTESTER, -600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }
}
