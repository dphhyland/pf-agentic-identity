package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AttestationMinterTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final String SPIFFE_ID = "spiffe://banking.demo/payment-agent";

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;
    private Map<String, Object> instancePublicJwk;
    private SpiffeSvid svid;

    @BeforeEach
    void setUp() throws Exception {
        attesterKey = TestJwts.ec("attester-1");
        instanceKey = TestJwts.ec("instance-1");
        instancePublicJwk = TestJwts.publicParams(instanceKey);
        svid = new SpiffeSvid(SPIFFE_ID, "banking.demo", "/payment-agent",
                List.of(ISSUER), NumericDate.now().getValue() + 600, NumericDate.now().getValue(), "raw.svid.token");
    }

    private String mint(JwsSigner signer, List<Map<String, Object>> details) {
        return AttestationMinter.mint(ISSUER, CLIENT_ID, instancePublicJwk, svid,
                Map.of("region", "EMEA", "environment", "prod"), details, 300L, signer);
    }

    @Test
    void claimLayoutIsCorrect() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        String jwt = mint(signer, List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"))));

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        assertEquals("oauth-client-attestation+jwt", jws.getHeader("typ"));
        JwtClaims claims = JwtClaims.parse(jws.getUnverifiedPayload());

        assertEquals(ISSUER, claims.getIssuer());
        assertEquals(CLIENT_ID, claims.getSubject());

        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) claims.getClaimValue("cnf");
        @SuppressWarnings("unchecked")
        Map<String, Object> cnfJwk = (Map<String, Object>) cnf.get("jwk");
        assertEquals("EC", cnfJwk.get("kty"));
        assertEquals(instancePublicJwk.get("x"), cnfJwk.get("x"));

        @SuppressWarnings("unchecked")
        Map<String, Object> workload = (Map<String, Object>) claims.getClaimValue("workload");
        assertEquals("spiffe", workload.get("attested_by"));
        assertEquals(SPIFFE_ID, workload.get("spiffe_id"));
        assertEquals("raw.svid.token", workload.get("svid"));
        @SuppressWarnings("unchecked")
        Map<String, Object> attributes = (Map<String, Object>) workload.get("attributes");
        assertEquals("EMEA", attributes.get("region"));

        assertNotNull(claims.getClaimValue("authorization_details"));
    }

    /** The minted attestation verifies unchanged through the existing verifier (issuance ↔ verify align). */
    @Test
    void mintedAttestationVerifiesThroughClientAttestationVerifier() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        String attestation = mint(signer, List.of());

        JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey));
        AttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(ISSUER, List.of(attesterPub)));
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .addAcceptedAudience(TOKEN_ENDPOINT)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        ClientAttestationVerifier verifier = new ClientAttestationVerifier(
                resolver, config, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());

        String pop = pop(OP_ISSUER, "pop-1");
        ClientAttestationResult result = verifier.verify(attestation, pop, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ISSUER, result.attesterIssuer());
    }

    /** Works identically with the vault-backed signer. */
    @Test
    void vaultSignedAttestationVerifies() throws Exception {
        try (FakeBaoServer bao = new FakeBaoServer("tok")) {
            OpenBaoTransitSigner signer = new OpenBaoTransitSigner(bao.url(), "tok", FakeBaoServer.KEY_NAME);
            String attestation = mint(signer, List.of());

            JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(signer.publicJwk());
            AttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(ISSUER, List.of(attesterPub)));
            ClientAttestationConfig config = ClientAttestationConfig.builder()
                    .addAcceptedAudience(OP_ISSUER)
                    .expectedHtu(TOKEN_ENDPOINT)
                    .build();
            ClientAttestationVerifier verifier = new ClientAttestationVerifier(
                    resolver, config, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());

            ClientAttestationResult result = verifier.verify(attestation, pop(OP_ISSUER, "pop-2"), null,
                    "POST", TOKEN_ENDPOINT, CLIENT_ID);
            assertEquals(CLIENT_ID, result.clientId());
        }
    }

    private String pop(String audience, String jti) throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(audience);
        pop.setJwtId(jti);
        pop.setIssuedAtToNow();
        return TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
    }
}
