/*
 * AzureManagedIdentityValidator maps a verified Entra managed-identity token onto spiffe://<td>/azure/mi/<oid>.
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

class AzureManagedIdentityValidatorTest {

    private static final String ATTESTER = "https://attester.example.com";
    private static final String TENANT_ID = "00000000-0000-0000-0000-000000000000";
    private static final String ENTRA_ISSUER = "https://login.microsoftonline.com/" + TENANT_ID + "/v2.0";
    private static final String TRUST_DOMAIN = "demo-tenant.azure.demo";
    private static final String OID = "11111111-1111-1111-1111-111111111111";

    private final AzureManagedIdentityValidator validator = new AzureManagedIdentityValidator();
    private PublicJsonWebKey entraKey;
    private List<JsonWebKey> bundle;
    private AttestationIssuanceConfig config;

    @BeforeEach
    void setUp() throws Exception {
        this.entraKey = TestJwts.rsa("entra-key-1");
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(this.entraKey));
        this.bundle = List.of(pub);
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, new JsonWebKeySet(pub).toJson());
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN);
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, TRUST_DOMAIN);
        props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, ENTRA_ISSUER);
        this.config = AttestationIssuanceConfig.fromProperties(props);
    }

    private String token(String issuer, String oid, String audience, long expOffsetSeconds) throws Exception {
        JwtClaims claims = new JwtClaims();
        if (issuer != null) {
            claims.setIssuer(issuer);
        }
        claims.setSubject("some-opaque-sub"); // Azure MI tokens carry an opaque sub; oid is the stable id
        if (oid != null) {
            claims.setClaim("oid", oid);
        }
        if (audience != null) {
            claims.setAudience(audience);
        }
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffsetSeconds));
        claims.setIssuedAtToNow();
        return TestJwts.sign(this.entraKey, "RS256", null, claims);
    }

    @Test
    void mapsVerifiedTokenOntoManagedIdentitySpiffeId() throws Exception {
        String token = token(ENTRA_ISSUER, OID, ATTESTER, 600);
        SpiffeSvid svid = this.validator.validateSvid(token, this.bundle, this.config);
        assertEquals("spiffe://" + TRUST_DOMAIN + "/azure/mi/" + OID, svid.spiffeId());
        assertEquals(TRUST_DOMAIN, svid.trustDomain());
        assertEquals("/azure/mi/" + OID, svid.path());
        assertEquals(token, svid.raw());
    }

    @Test
    void wrongIssuerIsRejected() throws Exception {
        String token = token("https://login.microsoftonline.com/OTHER-TENANT/v2.0", OID, ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void missingOidIsRejected() throws Exception {
        String token = token(ENTRA_ISSUER, null, ATTESTER, 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String token = token(ENTRA_ISSUER, OID, "https://other.example.com", 600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void expiredTokenIsRejected() throws Exception {
        String token = token(ENTRA_ISSUER, OID, ATTESTER, -600);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.validator.validateSvid(token, this.bundle, this.config));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void azureMiEvidenceRequiresATrustDomain() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_BUNDLE_URL,
                "https://login.microsoftonline.com/" + TENANT_ID + "/discovery/v2.0/keys");
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_AZURE_MI_TOKEN);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }
}
