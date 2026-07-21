package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** End-to-end verification of the optional SD-JWT attestation encoding + its Key-Binding {@code sd_hash}. */
class ClientAttestationVerifierSdJwtTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;
    private AttesterKeyResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        attesterKey = TestJwts.ec("attester-1");
        instanceKey = TestJwts.ec("instance-1");
        resolver = (iss, chain) -> List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey)));
    }

    private ClientAttestationVerifier verifier(boolean requireSdJwt, boolean acceptSdJwt) {
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .addAcceptedAudience(TOKEN_ENDPOINT)
                .expectedHtu(TOKEN_ENDPOINT)
                .acceptSdJwt(acceptSdJwt)
                .requireSdJwt(requireSdJwt)
                .build();
        return new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
    }

    /** Issuer JWT with two entitlement entries as SD array elements and a workload field in {@code _sd}. */
    private String issuerJwt(String dEmeaDigest, String dAmerDigest, String dSoftwareDigest) throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        att.setClaim("_sd_alg", "sha-256");
        att.setClaim("_sd", List.of(dSoftwareDigest));
        att.setClaim("authorization_details", List.of(Map.of("...", dEmeaDigest), Map.of("...", dAmerDigest)));
        return TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+sd-jwt", att);
    }

    private String pop(String audience, String jti, String sdHash) throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(audience);
        pop.setJwtId(jti);
        pop.setIssuedAtToNow();
        if (sdHash != null) {
            pop.setClaim("sd_hash", sdHash);
        }
        return TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
    }

    private String dEmea() {
        return SdJwt.arrayDisclosure("s1", Map.of("type", "sales_agent", "sales_regions", List.of("EMEA")));
    }

    private String dAmer() {
        return SdJwt.arrayDisclosure("s2", Map.of("type", "sales_agent", "sales_regions", List.of("AMER")));
    }

    private String dSoft() {
        return SdJwt.objectDisclosure("s3", "software_id", "pf-oidf-demo");
    }

    @Test
    void sdJwtHappyPathDisclosesOnlyEmea() throws Exception {
        String de = dEmea();
        String da = dAmer();
        String ds = dSoft();
        String issuer = issuerJwt(SdJwt.digest(de), SdJwt.digest(da), SdJwt.digest(ds));
        String presentation = issuer + "~" + de + "~" + ds + "~"; // disclose EMEA + software_id; withhold AMER

        ClientAttestationResult r = verifier(false, true).verify(
                presentation, pop(OP_ISSUER, "p1", SdJwt.digest(presentation)), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, r.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, r.mode());
        assertEquals(1, r.entitledAuthorizationDetails().size());
        assertEquals("sales_agent", r.entitledAuthorizationDetails().get(0).get("type"));
        assertEquals(List.of("EMEA"), r.entitledAuthorizationDetails().get(0).get("sales_regions"));
    }

    @Test
    void wrongSdHashRejected() throws Exception {
        String de = dEmea();
        String issuer = issuerJwt(SdJwt.digest(de), SdJwt.digest(dAmer()), SdJwt.digest(dSoft()));
        String presentation = issuer + "~" + de + "~";
        ClientAttestationException ex = assertThrows(ClientAttestationException.class, () -> verifier(false, true)
                .verify(presentation, pop(OP_ISSUER, "p1", "not-the-right-hash"), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    @Test
    void missingSdHashRejected() throws Exception {
        String de = dEmea();
        String issuer = issuerJwt(SdJwt.digest(de), SdJwt.digest(dAmer()), SdJwt.digest(dSoft()));
        String presentation = issuer + "~" + de + "~";
        assertThrows(ClientAttestationException.class, () -> verifier(false, true)
                .verify(presentation, pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    @Test
    void sdJwtRejectedWhenNotAccepted() throws Exception {
        String de = dEmea();
        String issuer = issuerJwt(SdJwt.digest(de), SdJwt.digest(dAmer()), SdJwt.digest(dSoft()));
        String presentation = issuer + "~" + de + "~";
        assertThrows(ClientAttestationException.class, () -> verifier(false, false)
                .verify(presentation, pop(OP_ISSUER, "p1", SdJwt.digest(presentation)), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    @Test
    void plainJwtRejectedWhenSdJwtRequired() throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        String plain = TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);

        assertThrows(ClientAttestationException.class, () -> verifier(true, true)
                .verify(plain, pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    /**
     * Federation-gated disclosure, AS side: when the AS requires {@code workload} disclosed, a presentation
     * that withholds it is rejected ({@code insufficient_disclosure}); disclosing it is accepted.
     */
    @Test
    void requiredWorkloadDisclosureEnforced() throws Exception {
        String dSoftware = SdJwt.objectDisclosure("s3", "software_id", "pf-oidf-demo");
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        att.setClaim("_sd_alg", "sha-256");
        att.setClaim("workload", Map.of("_sd", List.of(SdJwt.digest(dSoftware)))); // workload field, selectively disclosable
        String issuer = TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+sd-jwt", att);

        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER).addAcceptedAudience(TOKEN_ENDPOINT).expectedHtu(TOKEN_ENDPOINT)
                .requiredDisclosedClaims(Set.of("workload")).build();
        ClientAttestationVerifier v =
                new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());

        String withheld = issuer + "~"; // no disclosures → workload reconstructs empty
        ClientAttestationException ex = assertThrows(ClientAttestationException.class, () -> v.verify(
                withheld, pop(OP_ISSUER, "w1", SdJwt.digest(withheld)), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INSUFFICIENT_DISCLOSURE, ex.error());

        String disclosed = issuer + "~" + dSoftware + "~"; // present the workload field
        ClientAttestationResult r = v.verify(
                disclosed, pop(OP_ISSUER, "w2", SdJwt.digest(disclosed)), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, r.clientId());
    }
}
