/*
 * AwsStsWebIdentityValidator maps a verified sts:GetWebIdentityToken onto a SPIFFE ID from the role ARN.
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

class AwsStsWebIdentityValidatorTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String ACCOUNT_ISSUER = "https://a1b2c3d4-e5f6-7890-abcd-ef1234567890.tokens.sts.global.api.aws";
    private static final String TRUST_DOMAIN = "123456789012.aws.demo";

    private final AwsStsWebIdentityValidator validator = new AwsStsWebIdentityValidator();
    private PublicJsonWebKey awsKey;
    private List<JsonWebKey> bundle;
    private AttestationIssuanceConfig config;

    @BeforeEach
    void setUp() throws Exception {
        this.awsKey = TestJwts.ec("aws-key-1");
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.awsKey));
        this.bundle = List.of(pub);
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_AWS_STS_WEB_IDENTITY);
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, TRUST_DOMAIN);
        props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, ACCOUNT_ISSUER);
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
        return TestJwts.sign(this.awsKey, "ES256", null, claims);
    }

    @Test
    void mapsIamRoleArnOntoSpiffeId() throws Exception {
        String token = token(ACCOUNT_ISSUER, "arn:aws:iam::123456789012:role/AgentExecutionRole", ATTESTER, 600);
        SpiffeSvid svid = this.validator.validate(token, this.bundle, this.config);
        assertEquals("spiffe://123456789012.aws.demo/aws/123456789012/role/AgentExecutionRole", svid.spiffeId());
        assertEquals(TRUST_DOMAIN, svid.trustDomain());
        assertEquals("/aws/123456789012/role/AgentExecutionRole", svid.path());
    }

    @Test
    void mapsAssumedRoleArnDroppingSession() throws Exception {
        String token = token(ACCOUNT_ISSUER,
                "arn:aws:sts::123456789012:assumed-role/AgentExecutionRole/session-abc123", ATTESTER, 600);
        SpiffeSvid svid = this.validator.validate(token, this.bundle, this.config);
        assertEquals("spiffe://123456789012.aws.demo/aws/123456789012/role/AgentExecutionRole", svid.spiffeId());
    }

    @Test
    void nonRoleSubjectIsRejected() throws Exception {
        String token = token(ACCOUNT_ISSUER, "system:serviceaccount:demo:payment-agent", ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = token("https://evil.tokens.sts.global.api.aws",
                "arn:aws:iam::123456789012:role/AgentExecutionRole", ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String token = token(ACCOUNT_ISSUER, "arn:aws:iam::123456789012:role/AgentExecutionRole",
                "https://other.example.com", 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = token(ACCOUNT_ISSUER, "arn:aws:iam::123456789012:role/AgentExecutionRole", ATTESTER, -600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validate(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }
}
