package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.AttesterKeyResolver;
import com.pingidentity.ps.oidf.common.AttesterSigningKey;
import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationResult;
import com.pingidentity.ps.oidf.common.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.common.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.common.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.common.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.IssuanceException;
import com.pingidentity.ps.oidf.common.StaticAttesterKeyResolver;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AttestationIssuanceServletTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final String SPIFFE_ID = "spiffe://banking.demo/payment-agent";

    private PublicJsonWebKey bundleKey;   // signs SVIDs
    private PublicJsonWebKey attesterKey; // signs attestations (inline signer)
    private PublicJsonWebKey instanceKey; // the workload's cnf key
    private AttestationIssuanceServlet servlet;

    @BeforeEach
    void setUp() throws Exception {
        bundleKey = ec("svid-key-1");
        attesterKey = ec("attester-1");
        instanceKey = ec("instance-1");
        servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(fixedResolver(config()));
        servlet.setAttesterSigningKey(new AttesterSigningKey(null, null)); // inline JWK signing
    }

    @Test
    void happyPathIssuesVerifiableAttestation() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        Map<String, Object> body = servlet.issue(req);
        String attestation = (String) body.get("attestation");
        assertNotNull(attestation);
        assertEquals(300L, ((Number) body.get("expires_in")).longValue());
        assertRoundTrips(attestation);
    }

    @Test
    void unknownSpiffeIdIsRejected() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req =
                request("spiffe://banking.demo/stranger", ISSUER, newProof(null), List.of());
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("spiffe_id_not_authorized", e.error());
    }

    @Test
    void wrongSvidAudienceIsRejected() throws Exception {
        // SVID minted for a different audience than the attester issuer.
        String badSvid = svid(bundleKey, SPIFFE_ID, "https://elsewhere.example.com", 600L);
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.clientId = CLIENT_ID;
        req.instanceKey = publicParams(instanceKey);
        req.svid = badSvid;
        req.proof = newProof(null);
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void proofSignedByWrongKeyIsRejected() throws Exception {
        PublicJsonWebKey attacker = ec("attacker-1");
        String proof = proof(attacker, ISSUER, UUID.randomUUID().toString(), null);
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, proof, List.of());
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    void replayedProofIsRejected() throws Exception {
        String proof = newProof(null);
        servlet.issue(request(SPIFFE_ID, ISSUER, proof, List.of()));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, proof, List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    void requestExceedingEntitlementIsDenied() throws Exception {
        // Binding entitlement allows only EMEA; request AMER.
        List<Map<String, Object>> requested =
                List.of(Map.of("type", "sales_agent", "sales_regions", List.of("AMER")));
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), requested);
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("access_denied", e.error());
    }

    @Test
    void disabledOrUnknownClientIsRejected() throws Exception {
        servlet.setClientResolver(clientId -> {
            throw IssuanceException.invalidClient("client is disabled: " + clientId);
        });
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_client", e.error());
    }

    // ---- fixtures ---------------------------------------------------------------------------------

    private AttestationIssuanceConfig config() throws Exception {
        String bundle = new JsonWebKeySet(JsonWebKey.Factory.newJwk(publicParams(bundleKey))).toJson();
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, bundle);
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK,
                org.jose4j.json.JsonUtil.toJson(privateParams(attesterKey)));
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + SPIFFE_ID + "\","
                        + "\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}],"
                        + "\"metadata\":{\"region\":\"EMEA\"}}]");
        return AttestationIssuanceConfig.fromProperties(props);
    }

    private static IssuanceClientResolver fixedResolver(AttestationIssuanceConfig config) {
        return clientId -> config;
    }

    private AttestationIssuanceServlet.IssuanceRequest request(String spiffeId, String svidAudience,
            String proof, List<Map<String, Object>> details) throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.clientId = CLIENT_ID;
        req.instanceKey = publicParams(instanceKey);
        req.svid = svid(bundleKey, spiffeId, svidAudience, 600L);
        req.proof = proof;
        req.requestedDetails = details;
        return req;
    }

    private String newProof(String challenge) throws Exception {
        return proof(instanceKey, ISSUER, UUID.randomUUID().toString(), challenge);
    }

    private void assertRoundTrips(String attestation) throws Exception {
        JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(publicParams(attesterKey));
        AttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(ISSUER, List.of(attesterPub)));
        ClientAttestationConfig cfg = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        ClientAttestationVerifier verifier = new ClientAttestationVerifier(
                resolver, cfg, new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId("pop-" + UUID.randomUUID());
        pop.setIssuedAtToNow();
        String popJwt = signCompact(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
        ClientAttestationResult result = verifier.verify(attestation, popJwt, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ISSUER, result.attesterIssuer());
    }

    // ---- jose helpers -----------------------------------------------------------------------------

    private static PublicJsonWebKey ec(String kid) throws Exception {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        jwk.setKeyId(kid);
        return jwk;
    }

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    private static Map<String, Object> privateParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    private static String svid(PublicJsonWebKey signingKey, String sub, String audience, long expOffset) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setSubject(sub);
        claims.setAudience(audience);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffset));
        return signCompact(signingKey, "ES256", "JWT", claims);
    }

    private static String proof(PublicJsonWebKey signingKey, String audience, String jti, String challenge)
            throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(audience);
        claims.setJwtId(jti);
        claims.setIssuedAtToNow();
        if (challenge != null) {
            claims.setClaim("challenge", challenge);
        }
        return signCompact(signingKey, "ES256", InstanceKeyProofValidator.TYP, claims);
    }

    private static String signCompact(PublicJsonWebKey signingKey, String alg, String typ, JwtClaims claims)
            throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(alg);
        jws.setHeader("typ", typ);
        if (signingKey.getKeyId() != null) {
            jws.setKeyIdHeaderValue(signingKey.getKeyId());
        }
        return jws.getCompactSerialization();
    }
}
