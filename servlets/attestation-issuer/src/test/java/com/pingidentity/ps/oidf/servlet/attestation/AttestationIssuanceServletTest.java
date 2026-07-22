package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.AttestationSupport;
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
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.ReadListener;
import javax.servlet.ServletConfig;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.json.JsonUtil;
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

    @Test
    void missingRequiredFieldsAreRejected() throws Exception {
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.clientId = ""))).error());
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.instanceKey = null))).error());
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.svid = null))).error());
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.proof = null))).error());
    }

    @Test
    void requestWithinEntitlementIsGranted() throws Exception {
        List<Map<String, Object>> requested =
                List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA")));
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), requested));
        assertRoundTrips((String) body.get("attestation"));
    }

    @Test
    void malformedAuthorizationDetailsMapsToInvalidRequest() throws Exception {
        // An entry missing its 'type' is malformed → invalid_authorization_details → invalid_request.
        List<Map<String, Object>> requested = List.of(Map.of("sales_regions", List.of("EMEA")));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), requested)));
        assertEquals("invalid_request", e.error());
    }

    @Test
    void presentedChallengeIsConsumedOnceThenRefused() throws Exception {
        String challenge = AttestationSupport.challengeService().issue();
        servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())); // consumes it
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    void blankChallengeIsTreatedAsAbsent() throws Exception {
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(""), List.of()));
        assertNotNull(body.get("attestation"));
    }

    @Test
    void challengeRequiredButAbsentIsRejected() throws Exception {
        servlet.setChallengeRequired(true);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    // ---- doPost (HTTP layer) ----------------------------------------------------------------------

    @Test
    void doPostReturns200WithAttestation() throws Exception {
        Captured out = doPost(bodyJson(SPIFFE_ID, null));
        assertEquals(200, out.status);
        assertTrue(out.body.contains("attestation"), out.body);
        assertTrue(out.body.contains("expires_in"), out.body);
    }

    @Test
    void doPostMalformedJsonReturns400() throws Exception {
        Captured out = doPost("this is not json");
        assertEquals(400, out.status);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void doPostMapsIssuanceErrorToStatusAndBody() throws Exception {
        // Missing svid → issue() throws invalid_request → 400 JSON error body.
        Map<String, Object> body = baseBody();
        body.remove("svid");
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(400, out.status);
        assertTrue(out.body.contains("\"error\""), out.body);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void doPostAuthorizationDetailsMustBeArray() throws Exception {
        Map<String, Object> body = baseBody();
        body.put("authorization_details", "not-an-array");
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(400, out.status);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void doPostWithValidAuthorizationDetailsArray() throws Exception {
        Map<String, Object> body = baseBody();
        body.put("authorization_details",
                List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"))));
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(200, out.status);
        assertTrue(out.body.contains("attestation"), out.body);
    }

    @Test
    void doPostAuthorizationDetailsEntryMustBeObject() throws Exception {
        Map<String, Object> body = baseBody();
        body.put("authorization_details", List.of("not-an-object"));
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(400, out.status);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void doPostInstanceKeyNotObjectIsRejected() throws Exception {
        Map<String, Object> body = baseBody();
        body.put("instance_key", "not-an-object");
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(400, out.status);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void doPostServerErrorIsMappedTo500() throws Exception {
        // signing_key_ref set but no vault configured → server_error (500) at the signing step.
        servlet.setClientResolver(fixedResolver(configWithKeyRef()));
        servlet.setAttesterSigningKey(new AttesterSigningKey(null, null));
        Captured out = doPost(bodyJson(SPIFFE_ID, null));
        assertEquals(500, out.status);
        assertTrue(out.body.contains("server_error"), out.body);
    }

    @Test
    void attesterSigningKeyDefaultsToEnvironmentWhenUnset() throws Exception {
        // No signer injected → the servlet lazily builds one from the environment; inline-JWK config
        // signs without any vault, so issuance still succeeds.
        AttestationIssuanceServlet s = new AttestationIssuanceServlet();
        s.setClientResolver(fixedResolver(config()));
        Map<String, Object> body = s.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        assertNotNull(body.get("attestation"));
    }

    // ---- default resolver seam --------------------------------------------------------------------

    @Test
    void defaultClientResolverIsPingFederateBacked() {
        assertTrue(new AttestationIssuanceServlet().defaultClientResolver() instanceof PfIssuanceClientResolver);
    }

    @Test
    void lazilyInitializesClientResolverFromDefaultSeam() throws Exception {
        AttestationIssuanceConfig cfg = config();
        AttestationIssuanceServlet s = new AttestationIssuanceServlet() {
            @Override
            protected com.pingidentity.ps.oidf.common.IssuanceClientResolver defaultClientResolver() {
                return clientId -> cfg;
            }
        };
        s.setAttesterSigningKey(new AttesterSigningKey(null, null)); // no resolver injected → lazy path runs
        Map<String, Object> body = s.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        assertNotNull(body.get("attestation"));
    }

    // ---- init() -----------------------------------------------------------------------------------

    @Test
    void initParsesChallengeRequired() throws Exception {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("challengeRequired")).thenReturn("true");
        AttestationIssuanceServlet s = new AttestationIssuanceServlet();
        s.init(cfg);
        s.setClientResolver(fixedResolver(config()));
        s.setAttesterSigningKey(new AttesterSigningKey(null, null));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> s.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    void initWithOnlyOpenBaoUrlDoesNotBindVault() throws Exception {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("openBaoUrl")).thenReturn("http://openbao.invalid");
        // openBaoToken returns null → the vault signer is NOT constructed (both params required).
        AttestationIssuanceServlet s = new AttestationIssuanceServlet();
        s.init(cfg);
        s.setClientResolver(fixedResolver(config()));
        Map<String, Object> body = s.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        assertNotNull(body.get("attestation"));
    }

    @Test
    void initWithOpenBaoParamsStillServesInlineSigning() throws Exception {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("openBaoUrl")).thenReturn("http://openbao.invalid");
        when(cfg.getInitParameter("openBaoToken")).thenReturn("tok");
        AttestationIssuanceServlet s = new AttestationIssuanceServlet();
        s.init(cfg); // constructs an AttesterSigningKey bound to the vault
        s.setClientResolver(fixedResolver(config())); // config uses an inline JWK → vault untouched
        Map<String, Object> body = s.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        assertNotNull(body.get("attestation"));
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

    private AttestationIssuanceConfig configWithKeyRef() throws Exception {
        String bundle = new JsonWebKeySet(JsonWebKey.Factory.newJwk(publicParams(bundleKey))).toJson();
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE, bundle);
        props.put(AttestationIssuanceConfig.P_SIGNING_KEY_REF, "attestation-es256");
        props.put(AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":\"" + SPIFFE_ID + "\"}]");
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

    // ---- request-body + doPost helpers -----------------------------------------------------------

    private AttestationIssuanceServlet.IssuanceRequest mutate(
            java.util.function.Consumer<AttestationIssuanceServlet.IssuanceRequest> mutation) throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        mutation.accept(req);
        return req;
    }

    private Map<String, Object> baseBody() throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", CLIENT_ID);
        body.put("instance_key", publicParams(instanceKey));
        body.put("svid", svid(bundleKey, SPIFFE_ID, ISSUER, 600L));
        body.put("proof", newProof(null));
        return body;
    }

    private String bodyJson(String spiffeId, String challenge) throws Exception {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("client_id", CLIENT_ID);
        body.put("instance_key", publicParams(instanceKey));
        body.put("svid", svid(bundleKey, spiffeId, ISSUER, 600L));
        body.put("proof", newProof(challenge));
        return JsonUtil.toJson(body);
    }

    private Captured doPost(String bodyJson) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getInputStream()).thenReturn(new FakeServletInputStream(bodyJson.getBytes(StandardCharsets.UTF_8)));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter sw = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(sw));
        int[] status = {0};
        doAnswer(inv -> {
            status[0] = inv.getArgument(0);
            return null;
        }).when(resp).setStatus(anyInt());
        servlet.doPost(req, resp);
        Captured captured = new Captured();
        captured.status = status[0];
        captured.body = sw.toString();
        return captured;
    }

    private static final class Captured {
        int status;
        String body;
    }

    private static final class FakeServletInputStream extends ServletInputStream {
        private final ByteArrayInputStream in;

        FakeServletInputStream(byte[] bytes) {
            this.in = new ByteArrayInputStream(bytes);
        }

        @Override
        public int read() {
            return this.in.read();
        }

        @Override
        public boolean isFinished() {
            return this.in.available() == 0;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener readListener) {
        }
    }
}
