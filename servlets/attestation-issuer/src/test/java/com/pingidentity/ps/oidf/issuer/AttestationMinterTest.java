package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.BeforeEach;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.jose.OpenBaoTransitSigner;

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
    @Requirement({"CAS §4.5", "CLAIM-DICT divergence 1"})
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
        assertNull(workload.get("svid"), "the raw evidence never leaves the attester (F-0002)");
        assertEquals(InstanceIdentity.sha256Hex("raw.svid"), workload.get("instance_attestation_sha256"),
                "the digest covers the signing input, the first two segments");
        assertEquals("spiffe-jwt", workload.get("instance_attestation_type"));
        assertEquals(svid.expEpochSeconds(), ((Number) workload.get("instance_attestation_exp")).longValue());
        assertEquals(SPIFFE_ID, workload.get("subject"), "the spec's format-neutral workload.subject");
        @SuppressWarnings("unchecked")
        Map<String, Object> attributes = (Map<String, Object>) workload.get("attributes");
        assertEquals("EMEA", attributes.get("region"));

        assertNotNull(claims.getClaimValue("authorization_details"));
        assertNull(claims.getClaimValue("agent_id"), "the 8-arg overload must not emit agent_id at all");
    }

    // ---- agent_id (Phase 2.1/2.2) ------------------------------------------------------------------

    @Test
    @Requirement("PROFILE §6(2)")
    void agentIdIsEmittedWhenPresent() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        String jwt = AttestationMinter.mint(ISSUER, CLIENT_ID, instancePublicJwk,
                InstanceIdentity.ofSpiffe(svid), Map.of(), List.of(), 300L, signer, "agent-id-1");

        JwtClaims claims = payload(jwt);
        assertEquals("agent-id-1", claims.getClaimValue("agent_id"));
    }

    @Test
    void agentIdIsOmittedRatherThanEmittedBlankOrNull() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        for (String blank : new String[]{null, "", "   "}) {
            String jwt = AttestationMinter.mint(ISSUER, CLIENT_ID, instancePublicJwk,
                    InstanceIdentity.ofSpiffe(svid), Map.of(), List.of(), 300L, signer, blank);
            assertNull(payload(jwt).getClaimValue("agent_id"), "blank agentId=" + blank + " must not be emitted");
        }
    }

    private static JwtClaims payload(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        return JwtClaims.parse(jws.getUnverifiedPayload());
    }

    /** The minted attestation verifies unchanged through the existing verifier (issuance ↔ verify align). */
    @Test
    void mintedAttestationVerifiesThroughClientAttestationVerifier() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        String attestation = mint(signer, List.of());

        JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey));
        AttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(ISSUER, List.of(attesterPub)));
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .expectedAudience(OP_ISSUER)
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
                    .expectedAudience(OP_ISSUER)
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

    // ---- S3b: the attestation never outlives its evidence, and says what the evidence was without carrying it ----

    /** CAS §4.5, of {@code workload.instance_attestation_exp}: "The Client Attestation's {@code exp} MUST NOT be later." */
    @Test
    @Requirement("CAS §4.5")
    void theAttestationExpiresNoLaterThanItsEvidence() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        long evidenceExp = NumericDate.now().getValue() + 30;
        SpiffeSvid shortLived = new SpiffeSvid(SPIFFE_ID, "banking.demo", "/payment-agent",
                List.of(ISSUER), evidenceExp, NumericDate.now().getValue(), "raw.svid.token");
        String jwt = AttestationMinter.mint(ISSUER, CLIENT_ID, instancePublicJwk, shortLived,
                Map.of(), List.of(), 300L, signer);
        assertEquals(evidenceExp, payload(jwt).getExpirationTime().getValue());
        String longer = AttestationMinter.mint(ISSUER, CLIENT_ID, instancePublicJwk, svid, Map.of(), List.of(), 300L, signer);
        assertTrue(payload(longer).getExpirationTime().getValue() <= svid.expEpochSeconds());
    }

    @Test
    void anIdentityWithNothingToDigestCarriesOnlyTheEvidenceExpiry() throws Exception {
        JwsSigner signer = new LocalJwkSigner(TestJwts.privateParams(attesterKey));
        InstanceIdentity device = new InstanceIdentity("device", "device:1", null, null, Map.of("device_id", "1"),
                NumericDate.now().getValue() + 600);
        @SuppressWarnings("unchecked")
        Map<String, Object> workload = (Map<String, Object>) payload(AttestationMinter.mint(ISSUER, CLIENT_ID,
                instancePublicJwk, device, Map.of(), List.of(), 300L, signer, null)).getClaimValue("workload");
        assertNull(workload.get("instance_attestation_sha256"));
        assertNull(workload.get("instance_attestation_type"));
        assertEquals(device.expEpochSeconds(), ((Number) workload.get("instance_attestation_exp")).longValue());
        assertEquals("1", workload.get("device_id"));
    }

    @Test
    void theDigestIsWhatSha256sumPrints() {
        // printf 'abc' | sha256sum
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", InstanceIdentity.sha256Hex("abc"));
    }

    @Test
    void theEvidenceDigestCoversTheSigningInputAndNotTheSignature() {
        // token='ab.c.sig'; printf %s "${token%.*}" | sha256sum
        assertEquals(InstanceIdentity.sha256Hex("ab.c"), InstanceIdentity.evidenceDigest("ab.c.sig"));
        assertEquals(InstanceIdentity.evidenceDigest("ab.c.sig"), InstanceIdentity.evidenceDigest("ab.c.other-sig \n"),
                "whatever follows the second '.' is the signature's, which a verifier accepts in more than one encoding");
        assertEquals(InstanceIdentity.sha256Hex("ab.c"), InstanceIdentity.evidenceDigest("ab.c."));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> InstanceIdentity.evidenceDigest("ab.c"));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> InstanceIdentity.evidenceDigest("abc"));
    }
}
