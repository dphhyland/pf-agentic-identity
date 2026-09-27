package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.agent.AgentIdentity;
import com.pingidentity.ps.oidf.agent.AgentRegistry;
import com.pingidentity.ps.oidf.agent.AgentRegistryException;
import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.issuer.InstanceIdentity;
import com.pingidentity.ps.oidf.issuer.EvidencePolicy;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.clientattestation.InMemoryEvidenceBindingStore;
import com.pingidentity.ps.oidf.clientattestation.EvidenceBindingStore;
import com.pingidentity.ps.oidf.clientattestation.AttestationReplayCache;
import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService.Consumption;
import com.pingidentity.ps.oidf.clientattestation.AttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.issuer.AttesterSigningKey;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationResult;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationVerifier;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationChallengeService;
import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.issuer.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.issuer.RemoteJwksCache;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.clientattestation.StoreNamespace;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationException;
import com.pingidentity.ps.oidf.clientattestation.servlet.ClientAttestationChallengeServlet;
import java.io.ByteArrayInputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.json.JsonUtil;
import org.jose4j.jws.JsonWebSignature;
import com.pingidentity.ps.oidf.jose.Jwks;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

class AttestationIssuanceServletTest {
    private static final String ISSUER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";
    private static final String SPIFFE_ID = "spiffe://banking.demo/payment-agent";
    private static final String WALLET_PROVIDER = "https://wallet.example.com";
    private static final String WALLET_INSTANCE_ID = "urn:wallet:instance:abc123";
    private static final String GKE_CLUSTER_ISSUER =
            "https://container.googleapis.com/v1/projects/demo-project/locations/us-central1-a/clusters/spiffe-demo";

    private PublicJsonWebKey bundleKey;   // signs SVIDs
    private PublicJsonWebKey attesterKey; // signs attestations (inline signer)
    private PublicJsonWebKey instanceKey; // the workload's cnf key
    private PublicJsonWebKey walletProviderKey; // signs Wallet Instance Attestations
    private AttestationIssuanceServlet servlet;

    @BeforeEach
    void setUp() throws Exception {
        bundleKey = ec("svid-key-1");
        attesterKey = ec("attester-1");
        instanceKey = ec("instance-1");
        walletProviderKey = ec("wallet-provider-1");
        servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(fixedResolver(config()));
        servlet.setAttesterSigningKey(new AttesterSigningKey(null, null)); // inline JWK signing
        // A binding store per test: two tests that mint the same SVID in the same second would otherwise
        // present the same evidence with different instance keys, and the second would be a conflict.
        servlet.setEvidenceBindingStore(new InMemoryEvidenceBindingStore());
        servlet.setEvidencePolicy(EvidencePolicy.defaults());
    }

    @Test
    @Requirement("CAS §4.5")
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
    @Requirement("CAS §4.3")
    void proofSignedByWrongKeyIsRejected() throws Exception {
        PublicJsonWebKey attacker = ec("attacker-1");
        String proof = proof(attacker, ISSUER, UUID.randomUUID().toString(), null);
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, proof, List.of());
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    @Requirement("CAS §4.3")
    void replayedProofIsRejected() throws Exception {
        String proof = newProof(null);
        servlet.issue(request(SPIFFE_ID, ISSUER, proof, List.of()));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, proof, List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    @Requirement("CAS §7")
    void requestExceedingEntitlementIsDenied() throws Exception {
        // Binding entitlement allows only EMEA; request AMER.
        List<Map<String, Object>> requested =
                List.of(Map.of("type", "sales_agent", "sales_regions", List.of("AMER")));
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), requested);
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("access_denied", e.error());
    }

    @Test
    void noAttestationClientsConfiguredIsRejected() throws Exception {
        servlet.setClientResolver(emptyResolver());
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_client", e.error());
    }

    /**
     * The README states "a {@code client_id} is accepted but ignored" — the client is resolved from the
     * evidence (which of every configured attestation client's trust bundle verifies it, and whose
     * bindings contain the resulting identity), never from this caller-supplied field. Pin it: a request
     * asserting someone else's client_id must still be minted for the client the evidence actually
     * matches, not the asserted one — otherwise a caller could name any client_id it likes and get an
     * attestation issued under that identity without the evidence to back it.
     */
    @Test
    @Requirement("CAS §6")
    void aCallerAssertedClientIdIsIgnoredInFavourOfTheEvidenceResolvedClient() throws Exception {
        String forgedClientId = "https://attacker.example.com/not-the-real-client";
        String realClientId = "https://real-client.example.com/agent";
        AttestationIssuanceConfig cfg = config();
        servlet.setClientResolver(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) {
                return cfg;
            }

            @Override
            public List<com.pingidentity.ps.oidf.issuer.AttesterClient> attestationClients() {
                return List.of(new com.pingidentity.ps.oidf.issuer.AttesterClient(realClientId, cfg));
            }
        });
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        req.clientId = forgedClientId; // the field the README says is "accepted but ignored"

        Map<String, Object> body = servlet.issue(req);

        String sub = attestationSubject((String) body.get("attestation"));
        assertEquals(realClientId, sub, "must be minted for the evidence-matched client");
        assertTrue(!forgedClientId.equals(sub), "a caller-asserted client_id must never decide the attestation subject");
    }

    /** The attestation's {@code sub} claim, read without verification (the signature is already covered elsewhere). */
    private static String attestationSubject(String attestation) throws Exception {
        String[] parts = attestation.split("\\.");
        String json = new String(java.util.Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        return (String) JsonUtil.parseJson(json).get("sub");
    }

    /**
     * Two independently configured attestation clients both binding the same SPIFFE ID is a
     * configuration error — an operator mistake, not a legitimate multi-tenant setup. Resolving it
     * arbitrarily (e.g. "first match wins") would let whichever client happens to be misconfigured
     * second silently steal issuance for an identity that was already claimed; this must be rejected
     * instead. {@code resolveByEvidence} throws as soon as a second candidate also validates the
     * evidence AND has a binding for the resolved subject.
     */
    @Test
    void anIdentityBoundToMoreThanOneClientIsRejected() throws Exception {
        AttestationIssuanceConfig first = config();
        AttestationIssuanceConfig second = config(); // separately built, same SPIFFE_ID binding
        servlet.setClientResolver(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) {
                return "https://client-a.example.com".equals(clientId) ? first : second;
            }

            @Override
            public List<com.pingidentity.ps.oidf.issuer.AttesterClient> attestationClients() {
                return List.of(
                        new com.pingidentity.ps.oidf.issuer.AttesterClient("https://client-a.example.com", first),
                        new com.pingidentity.ps.oidf.issuer.AttesterClient("https://client-b.example.com", second));
            }
        });

        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));

        assertEquals("invalid_client", e.error());
    }

    @Test
    void missingRequiredFieldsAreRejected() throws Exception {
        // client_id is deliberately NOT required — the workload names no client.
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.instanceKey = null))).error());
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.svid = null))).error());
        assertEquals("invalid_request", assertThrows(IssuanceException.class,
                () -> servlet.issue(mutate(r -> r.proof = null))).error());
    }

    @Test
    @Requirement("CAS §7")
    void requestWithinEntitlementIsGranted() throws Exception {
        List<Map<String, Object>> requested =
                List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA")));
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), requested));
        assertRoundTrips((String) body.get("attestation"));
    }

    // ---- agent_id resolution (Phase 2.1) -----------------------------------------------------------

    @Test
    void noAgentRegistryConfiguredMeansNoAgentIdClaim() throws Exception {
        // servlet.setAgentRegistry is never called in setUp() — back-compatible default.
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        assertNull(claimsOf((String) body.get("attestation")).getClaimValue("agent_id"));
    }

    @Test
    @Requirement("PROFILE §6(2)")
    void configuredAgentRegistryEmitsTheResolvedAgentId() throws Exception {
        servlet.setAgentRegistry(fixedAgentRegistry("agent-id-xyz"));
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        assertEquals("agent-id-xyz", claimsOf((String) body.get("attestation")).getClaimValue("agent_id"));
    }

    @Test
    void agentRegistryReceivesTheResolvedInstanceSubjectNotTheRawSvid() throws Exception {
        List<String[]> calls = new java.util.ArrayList<>();
        servlet.setAgentRegistry((iss, clientId, instanceFormat, instanceSubject) -> {
            calls.add(new String[]{iss, clientId, instanceFormat, instanceSubject});
            return new AgentIdentity("agent-1", iss, clientId, instanceFormat, instanceSubject, Instant.now());
        });
        servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));

        assertEquals(1, calls.size());
        assertEquals(List.of(ISSUER, CLIENT_ID, "spiffe", SPIFFE_ID), List.of(calls.get(0)));
    }

    @Test
    void aFailingAgentRegistryFailsTheRequestRatherThanSilentlyOmittingAgentId() throws Exception {
        servlet.setAgentRegistry((iss, clientId, instanceFormat, instanceSubject) -> {
            throw new AgentRegistryException(AgentRegistryException.STORAGE_FAILURE, "db is down");
        });
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("server_error", e.error());
    }

    private static AgentRegistry fixedAgentRegistry(String agentId) {
        return (iss, clientId, instanceFormat, instanceSubject) ->
                new AgentIdentity(agentId, iss, clientId, instanceFormat, instanceSubject, Instant.now());
    }

    private JwtClaims claimsOf(String jwt) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(jwt);
        return JwtClaims.parse(jws.getUnverifiedPayload());
    }

    // ---- gke-sa-token evidence --------------------------------------------------------------------

    @Test
    void gkeEvidenceWithFetchedBundleIssuesVerifiableAttestation() throws Exception {
        servlet.setClientResolver(fixedResolver(gkeConfig()));
        servlet.setJwksCache(fakeJwksCache());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.clientId = CLIENT_ID;
        req.instanceKey = publicParams(instanceKey);
        req.svid = ksaToken("system:serviceaccount:demo:payment-agent");
        req.proof = newProof(null);
        req.requestedDetails = List.of();

        Map<String, Object> body = servlet.issue(req);
        String attestation = (String) body.get("attestation");
        assertRoundTrips(attestation);
        // The attestation's workload claim carries the mapped canonical GKE SPIFFE ID.
        String payload = new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(payload.contains("spiffe://demo-project.svc.id.goog/ns/demo/sa/payment-agent"), payload);
    }

    // ---- wallet instance attestation (a non-SPIFFE format through the same reverse-mapping flow) --------

    @Test
    void walletInstanceAttestationIssuesAttestationAttestedByWallet() throws Exception {
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        servlet.setInstanceValidators(walletRegistry());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        req.svid = wia(WALLET_INSTANCE_ID, publicParams(instanceKey), 600L);
        req.proof = newProof(null);
        req.requestedDetails = List.of();

        Map<String, Object> body = servlet.issue(req);
        String attestation = (String) body.get("attestation");
        assertRoundTrips(attestation);
        String payload = new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]),
                StandardCharsets.UTF_8);
        // The minted workload claim reports the proving format and the wallet members, not a SPIFFE id.
        assertTrue(payload.contains("\"attested_by\":\"wallet\""), payload);
        assertTrue(payload.contains(WALLET_PROVIDER), payload);
        assertTrue(payload.contains(WALLET_INSTANCE_ID), payload);
    }

    @Test
    @Requirement("CAS §4.4")
    void walletAttestationBindingADifferentKeyThanInstanceKeyIsRejected() throws Exception {
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        servlet.setInstanceValidators(walletRegistry());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        // The WIA binds someone else's key — the request must not be able to bind its own instead.
        req.svid = wia(WALLET_INSTANCE_ID, publicParams(ec("other-instance")), 600L);
        req.proof = newProof(null);
        req.requestedDetails = List.of();

        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_instance_proof", e.error());
        assertTrue(e.getMessage().contains("does not match the key bound"), e.getMessage());
    }

    @Test
    void walletAttestationIsRefusedWhenNoWalletTrustIsConfigured() throws Exception {
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        // No setInstanceValidators: the default registry holds the unconfigured-trust placeholder.
        servlet.setInstanceValidators(
                com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators.defaults());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        req.svid = wia(WALLET_INSTANCE_ID, publicParams(instanceKey), 600L);
        req.proof = newProof(null);
        req.requestedDetails = List.of();

        // It must refuse, never fall through to accepting an unverifiable provider.
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_svid", e.error());
    }

    @Test
    void declaredFormatNarrowsWhichClientsAreTried() throws Exception {
        // A wallet client is configured, but the request declares the spiffe format: no candidate matches.
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        servlet.setInstanceValidators(walletRegistry());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        req.svid = wia(WALLET_INSTANCE_ID, publicParams(instanceKey), 600L);
        req.format = "spiffe";
        req.proof = newProof(null);
        req.requestedDetails = List.of();

        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_svid", e.error());
        assertTrue(e.getMessage().contains("format 'spiffe'"), e.getMessage());
    }

    @Test
    void gkeEvidenceForUnboundServiceAccountIsRejected() throws Exception {
        servlet.setClientResolver(fixedResolver(gkeConfig()));
        servlet.setJwksCache(fakeJwksCache());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.clientId = CLIENT_ID;
        req.instanceKey = publicParams(instanceKey);
        req.svid = ksaToken("system:serviceaccount:demo:stranger");
        req.proof = newProof(null);
        req.requestedDetails = List.of();
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("spiffe_id_not_authorized", e.error());
    }

    @Test
    void gkeBundleFetchFailureWithNoCacheIsServerError() throws Exception {
        servlet.setClientResolver(fixedResolver(gkeConfig()));
        servlet.setJwksCache(new RemoteJwksCache((url, accept) -> {
            throw new IllegalStateException("upstream down");
        }, 300));
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.clientId = CLIENT_ID;
        req.instanceKey = publicParams(instanceKey);
        req.svid = ksaToken("system:serviceaccount:demo:payment-agent");
        req.proof = newProof(null);
        req.requestedDetails = List.of();
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("server_error", e.error());
    }

    @Test
    void spireSelectorsAreIntrospectedIntoWorkloadAttributes() throws Exception {
        // A SPIRE-backed introspector adds selectors for the validated SPIFFE ID; they must appear in the
        // minted attestation's workload.attributes (available to the issuance/downscoping policy).
        servlet.setWorkloadIntrospector(svid -> Map.of(
                "selectors", List.of("k8s:ns:demo", "k8s:sa:payment-agent"),
                "spire", Map.of("k8s", List.of("ns:demo", "sa:payment-agent"))));
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of()));
        String attestation = (String) body.get("attestation");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(payload.contains("k8s:ns:demo"), payload);
        assertTrue(payload.contains("k8s:sa:payment-agent"), payload);
        // The binding's own metadata (region=EMEA) survives alongside the introspected selectors.
        assertTrue(payload.contains("EMEA"), payload);
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
    @Requirement("CAS §4.1")
    void presentedChallengeIsConsumedOnceThenRefused() throws Exception {
        String challenge = AttestationSupport.challengeService(StoreNamespace.CAS).issue();
        servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())); // consumes it
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    /**
     * CAS §4.1: "a challenge issued by one party MUST NOT be accepted by the other", and "the CAS MUST reject an
     * Instance Key Proof presenting a challenge it did not issue". The authorization server's endpoint issues into
     * {@code oidf:as:challenge:*}; the attester looks in {@code oidf:cas:challenge:*}, refuses, and spends nothing.
     */
    @Test
    @Requirement("CAS §4.1")
    void aChallengeFromTheAuthorizationServersEndpointIsRefusedAndLeftUnspent() throws Exception {
        String challenge = challengeFrom(new ClientAttestationChallengeServlet(), "POST");

        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())));
        assertEquals("invalid_instance_proof", e.error());
        assertTrue(e.getMessage().contains("challenge"), e.getMessage());
        assertEquals(Consumption.CONSUMED, AttestationSupport.challengeService(StoreNamespace.AS).consumeChallenge(challenge),
                "the refusal left the authorization server's challenge for the token endpoint");
    }

    /**
     * The other direction: a challenge from the attester's endpoint, echoed in a PoP at the token endpoint, meets a
     * verifier wired as {@code ClientAttestationAuthFilter} and {@code ClientAttestationUtils} wire it - over
     * {@link AttestationSupport#challengeService()}, the authorization server's store - and is refused with
     * {@code use_attestation_challenge}.
     */
    @Test
    @Requirement("CAS §4.1")
    void aChallengeFromTheAttestersEndpointIsRefusedAtTheTokenEndpoint() throws Exception {
        String challenge = challengeFrom(new AttestationIssuanceChallengeServlet(), "GET");
        String attestation = (String) servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())).get("attestation");

        JsonWebKey attesterPub = JsonWebKey.Factory.newJwk(publicParams(attesterKey));
        ClientAttestationVerifier tokenEndpoint = new ClientAttestationVerifier(
                new StaticAttesterKeyResolver(Map.of(ISSUER, List.of(attesterPub))),
                ClientAttestationConfig.builder().addAcceptedAudience(OP_ISSUER).expectedHtu(TOKEN_ENDPOINT).build(),
                AttestationSupport.replayCache(), AttestationSupport.challengeService());
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId("pop-" + UUID.randomUUID());
        pop.setIssuedAtToNow();
        pop.setClaim("challenge", challenge);
        String popJwt = signCompact(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);

        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> tokenEndpoint.verify(attestation, popJwt, null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.useChallenge("-").error(), e.error());
        assertEquals(Consumption.CONSUMED, AttestationSupport.challengeService(StoreNamespace.CAS).consumeChallenge(challenge),
                "the refusal left the attester's challenge for the attester");
    }

    /** CAS §4.1 end to end: the attester's own endpoint issues a challenge its issuance endpoint takes once. */
    @Test
    @Requirement("CAS §4.1")
    void aChallengeFromTheAttestersEndpointIsTakenOnceByTheAttester() throws Exception {
        String challenge = challengeFrom(new AttestationIssuanceChallengeServlet(), "GET");
        assertNotNull(servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())).get("attestation"));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(challenge), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    /** Fetches a challenge from an endpoint as a client would, through the container's entry point. */
    private static String challengeFrom(jakarta.servlet.http.HttpServlet endpoint, String method) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn(method);
        when(req.getRemoteAddr()).thenReturn("10.0.4." + (1 + new java.util.Random().nextInt(250)));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));
        endpoint.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) resp);
        org.mockito.Mockito.verify(resp).setStatus(200);
        return (String) JsonUtil.parseJson(body.toString()).get("attestation_challenge");
    }

    @Test
    void blankChallengeIsTreatedAsAbsent() throws Exception {
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(""), List.of()));
        assertNotNull(body.get("attestation"));
    }

    @Test
    @Requirement("CAS §4.3")
    void challengeRequiredButAbsentIsRejected() throws Exception {
        servlet.setChallengeRequired(true);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    // ---- deployment-required custom claims (in the instance-key proof) ----------------------------

    @Test
    @Requirement("CAS §5.3.2")
    void requiredCustomClaimMissingIsRejected() throws Exception {
        servlet.setCustomClaimsRequired(List.of("deployment_id"));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    @Requirement("CAS §5.3.2")
    void requiredCustomClaimPresentIsAccepted() throws Exception {
        servlet.setCustomClaimsRequired(List.of("deployment_id"));
        Map<String, Object> body = servlet.issue(
                request(SPIFFE_ID, ISSUER, newProofWith("deployment_id", "dep-42"), List.of()));
        assertNotNull(body.get("attestation"));
        assertRoundTrips((String) body.get("attestation"));
    }

    @Test
    @Requirement("CAS §5.3.2")
    void requiredCustomClaimBlankIsRejected() throws Exception {
        servlet.setCustomClaimsRequired(List.of("deployment_id"));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProofWith("deployment_id", " "), List.of())));
        assertEquals("invalid_instance_proof", e.error());
    }

    @Test
    void initParsesCustomClaimsRequired() throws Exception {
        ServletConfig cfg = mock(ServletConfig.class);
        when(cfg.getInitParameter("customClaimsRequired")).thenReturn("deployment_id, region");
        AttestationIssuanceServlet s = new AttestationIssuanceServlet();
        s.init(cfg);
        s.setClientResolver(fixedResolver(config()));
        s.setAttesterSigningKey(new AttesterSigningKey(null, null));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> s.issue(request(SPIFFE_ID, ISSUER, newProofWith("deployment_id", "dep-42"), List.of())));
        assertEquals("invalid_instance_proof", e.error()); // region still missing
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

    // ---- agent_id firewall (Phase 2.3) --------------------------------------------------------------

    @Test
    void aTopLevelAgentIdInTheRequestBodyIsRejected() throws Exception {
        Map<String, Object> body = baseBody();
        body.put("agent_id", "attacker-chosen");
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(400, out.status);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void anAgentIdInsideAnAuthorizationDetailsEntryIsRejected() throws Exception {
        Map<String, Object> body = baseBody();
        body.put("authorization_details",
                List.of(Map.of("type", "sales_agent", "sales_regions", List.of("EMEA"), "agent_id", "attacker-chosen")));
        Captured out = doPost(JsonUtil.toJson(body));
        assertEquals(400, out.status);
        assertTrue(out.body.contains("invalid_request"), out.body);
    }

    @Test
    void anAgentIdInBindingMetadataIsRejectedAtConfigParseTime() {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK, "{}");
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + SPIFFE_ID + "\",\"metadata\":{\"agent_id\":\"operator-typo\"}}]");
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> AttestationIssuanceConfig.fromProperties(props));
        assertEquals("invalid_client", e.error());
    }

    @Test
    @Requirement("CAS §5.3.2")
    void anAgentIdClaimInsideTheInstanceKeyProofDoesNotInfluenceTheMintedOne() throws Exception {
        // The proof JWT is fully parsed by InstanceKeyProofValidator, but only jti/challenge are ever
        // read out of it — a claim named agent_id inside the proof's own payload must have no effect.
        servlet.setAgentRegistry(fixedAgentRegistry("real-minted-agent-id"));
        JwtClaims proofClaims = new JwtClaims();
        proofClaims.setIssuer(CLIENT_ID);
        proofClaims.setAudience(ISSUER);
        proofClaims.setJwtId(UUID.randomUUID().toString());
        proofClaims.setIssuedAtToNow();
        proofClaims.setClaim("agent_id", "attacker-chosen-via-proof");
        String proof = signCompact(instanceKey, "ES256", InstanceKeyProofValidator.TYP, proofClaims);

        Map<String, Object> body = baseBody();
        body.put("proof", proof);
        Captured out = doPost(JsonUtil.toJson(body));

        assertEquals(200, out.status);
        Map<String, Object> parsed = JsonUtil.parseJson(out.body);
        assertEquals("real-minted-agent-id", claimsOf((String) parsed.get("attestation")).getClaimValue("agent_id"));
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
            protected com.pingidentity.ps.oidf.issuer.IssuanceClientResolver defaultClientResolver() {
                return fixedResolver(cfg);
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

    // ---- asserted-context resolver (Entra Agent ID directory) -------------------------------------

    private static final String ENTRA_OID = "d7c5a2b1-0000-4000-8000-copilot0demo";

    @Test
    void noResolverConfiguredIsCompletelyUnaffectedByAssertedContext() throws Exception {
        // A client with NO attestation_asserted_context_resolver set — the default, and every existing
        // GCP/AWS/wallet client — must be byte-for-byte unaffected even if a caller sends asserted_context.
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        req.assertedContext = ENTRA_OID; // present, but the client never opted in
        Map<String, Object> body = servlet.issue(req);
        String attestation = (String) body.get("attestation");
        assertRoundTrips(attestation);
        String payload = new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]),
                StandardCharsets.UTF_8);
        assertTrue(!payload.contains("\"asserted\""), payload);
    }

    @Test
    void assertedContextOmittedSkipsResolutionEvenWhenClientOptsIn() throws Exception {
        // The client opts in, but the CALLER doesn't supply asserted_context — resolution is skipped
        // entirely (Track A: a direct call with no Copilot-Studio-style upstream context still works,
        // unrestricted by a resolver it never invoked).
        servlet.setClientResolver(fixedResolver(configWithAssertedContext()));
        servlet.setAssertedContextResolvers(entraResolvers());
        List<Map<String, Object>> requested = List.of(Map.of("type", "payment_initiation", "actions",
                List.of("initiate")));
        Map<String, Object> body = servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), requested));
        assertRoundTrips((String) body.get("attestation"));
    }

    @Test
    void assertedContextNarrowsTheCeilingToTheDirectoryEntryGroups() throws Exception {
        // The evidenced binding is entitled to BOTH account_information and payment_initiation, but the
        // asserted Copilot agent's directory entry only covers account_information (it's not in the
        // payments group) — the effective ceiling after intersection excludes payment_initiation.
        servlet.setClientResolver(fixedResolver(configWithAssertedContext()));
        servlet.setAssertedContextResolvers(entraResolvers());

        AttestationIssuanceServlet.IssuanceRequest denied =
                request(SPIFFE_ID, ISSUER, newProof(null),
                        List.of(Map.of("type", "payment_initiation", "actions", List.of("initiate"))));
        denied.assertedContext = ENTRA_OID;
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(denied));
        assertEquals("access_denied", e.error());

        AttestationIssuanceServlet.IssuanceRequest allowed =
                request(SPIFFE_ID, ISSUER, newProof(null),
                        List.of(Map.of("type", "account_information", "actions", List.of("read"))));
        allowed.assertedContext = ENTRA_OID;
        Map<String, Object> body = servlet.issue(allowed);
        String attestation = (String) body.get("attestation");
        assertRoundTrips(attestation);
        String payload = new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]),
                StandardCharsets.UTF_8);
        // The asserted claims land under workload.attributes.asserted, labeled distinctly from proven facts.
        assertTrue(payload.contains("\"asserted\""), payload);
        assertTrue(payload.contains(ENTRA_OID), payload);
    }

    @Test
    void unknownAssertedOidIsAccessDenied() throws Exception {
        servlet.setClientResolver(fixedResolver(configWithAssertedContext()));
        servlet.setAssertedContextResolvers(entraResolvers());
        AttestationIssuanceServlet.IssuanceRequest req =
                request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        req.assertedContext = "ffffffff-not-in-directory";
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("access_denied", e.error());
    }

    @Test
    void clientOptingIntoAnUnregisteredResolverFailsClosed() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE,
                new JsonWebKeySet(JsonWebKey.Factory.newJwk(publicParams(bundleKey))).toJson());
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK,
                org.jose4j.json.JsonUtil.toJson(privateParams(attesterKey)));
        props.put(AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":\"" + SPIFFE_ID + "\"}]");
        props.put(AttestationIssuanceConfig.P_ASSERTED_CONTEXT_RESOLVER, "no-such-resolver");
        servlet.setClientResolver(fixedResolver(AttestationIssuanceConfig.fromProperties(props)));
        // No setAssertedContextResolvers() call — the registry is empty (no OIDF_ENTRA_AGENT_DIRECTORY set).
        AttestationIssuanceServlet.IssuanceRequest req =
                request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        req.assertedContext = ENTRA_OID;
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_client", e.error());
    }

    /** A client entitled to accounts AND payments at the evidence layer; the asserted layer narrows it. */
    private AttestationIssuanceConfig configWithAssertedContext() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_BUNDLE,
                new JsonWebKeySet(JsonWebKey.Factory.newJwk(publicParams(bundleKey))).toJson());
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK,
                org.jose4j.json.JsonUtil.toJson(privateParams(attesterKey)));
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"" + SPIFFE_ID + "\","
                        + "\"entitlement\":[{\"type\":\"account_information\",\"actions\":[\"read\"]},"
                        + "{\"type\":\"payment_initiation\",\"actions\":[\"initiate\"]}]}]");
        props.put(AttestationIssuanceConfig.P_ASSERTED_CONTEXT_RESOLVER,
                com.pingidentity.ps.oidf.issuer.EntraDirectoryAssertedContextResolver.ID);
        return AttestationIssuanceConfig.fromProperties(props);
    }

    /** An Entra Agent ID directory with one registered Copilot agent, accounts-only (no payments group). */
    private Map<String, com.pingidentity.ps.oidf.issuer.AssertedContextResolver> entraResolvers() {
        com.pingidentity.ps.oidf.issuer.EntraDirectoryAssertedContextResolver resolver =
                com.pingidentity.ps.oidf.issuer.EntraDirectoryAssertedContextResolver.fromJson(
                        "{\"" + ENTRA_OID + "\":{"
                                + "\"display_name\":\"Northwind Copilot (demo)\","
                                + "\"groups\":[\"copilot-bridge-users\"],"
                                + "\"ceiling\":[{\"type\":\"account_information\",\"actions\":[\"read\"]}]}}");
        return Map.of(resolver.id(), resolver);
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

    /**
     * A wallet-only client: it declares the wallet evidence type (which is what makes a SPIFFE bundle
     * unnecessary) and binds a wallet instance id rather than a SPIFFE ID.
     */
    private AttestationIssuanceConfig walletConfig(String pinnedProvider) throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_EVIDENCE,
                AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION);
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK,
                org.jose4j.json.JsonUtil.toJson(privateParams(attesterKey)));
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"wallet_instance\":\"" + WALLET_INSTANCE_ID + "\",\"metadata\":{\"tenant\":\"gold\"}}]");
        if (pinnedProvider != null) {
            props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, pinnedProvider);
        }
        return AttestationIssuanceConfig.fromProperties(props);
    }

    /** The default registry with the placeholder wallet validator replaced by one trusting our test provider. */
    private com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators walletRegistry() throws Exception {
        AttesterKeyResolver providerKeys = new StaticAttesterKeyResolver(Map.of(
                WALLET_PROVIDER, List.of(JsonWebKey.Factory.newJwk(publicParams(walletProviderKey)))));
        return com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators.defaults()
                .with(new com.pingidentity.ps.oidf.issuer.WalletInstanceAttestationValidator(providerKeys));
    }

    /** A Wallet Instance Attestation signed by the test wallet provider, binding {@code cnfJwk}. */
    private String wia(String instanceId, Map<String, Object> cnfJwk, long ttlSeconds) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(WALLET_PROVIDER);
        c.setSubject(instanceId);
        c.setAudience(ISSUER);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + ttlSeconds));
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jwk", cnfJwk);
        c.setClaim("cnf", cnf);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(c.toJson());
        jws.setKey(walletProviderKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(walletProviderKey.getKeyId());
        jws.setHeader("typ", "wallet-instance-attestation+jwt");
        return jws.getCompactSerialization();
    }

    /** gke-sa-token client: bundle by URL, trust domain pinned, same inline attester signing key. */
    private AttestationIssuanceConfig gkeConfig() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ISSUER);
        props.put(AttestationIssuanceConfig.P_EVIDENCE, AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN);
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, "demo-project.svc.id.goog");
        props.put(AttestationIssuanceConfig.P_BUNDLE_URL, "https://cluster.example/jwks");
        props.put(AttestationIssuanceConfig.P_EVIDENCE_ISSUER, GKE_CLUSTER_ISSUER);
        props.put(AttestationIssuanceConfig.P_SIGNING_JWK,
                org.jose4j.json.JsonUtil.toJson(privateParams(attesterKey)));
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"spiffe://demo-project.svc.id.goog/ns/demo/sa/payment-agent\","
                        + "\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]}]");
        return AttestationIssuanceConfig.fromProperties(props);
    }

    /** Serves the bundle key's JWKS for any URL (stands in for the GKE cluster's public JWKS). */
    private RemoteJwksCache fakeJwksCache() throws Exception {
        String jwks = new JsonWebKeySet(JsonWebKey.Factory.newJwk(publicParams(bundleKey))).toJson();
        return new RemoteJwksCache((url, accept) -> jwks, 300);
    }

    /** A GKE-projected service-account token signed by the cluster (test bundle) key. */
    private String ksaToken(String subject) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuer(GKE_CLUSTER_ISSUER);
        claims.setSubject(subject);
        claims.setAudience(ISSUER);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        return signCompact(bundleKey, "ES256", "JWT", claims);
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

    /** A resolver exposing one client (id = CLIENT_ID) — both by-id lookup and the attestation list. */
    private static IssuanceClientResolver fixedResolver(AttestationIssuanceConfig config) {
        return new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) {
                return config;
            }

            @Override
            public List<com.pingidentity.ps.oidf.issuer.AttesterClient> attestationClients() {
                return List.of(new com.pingidentity.ps.oidf.issuer.AttesterClient(CLIENT_ID, config));
            }
        };
    }

    /** A resolver with no attestation clients configured. */
    private static IssuanceClientResolver emptyResolver() {
        return new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.invalidClient("unknown client: " + clientId);
            }

            @Override
            public List<com.pingidentity.ps.oidf.issuer.AttesterClient> attestationClients() {
                return List.of();
            }
        };
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

    /** A fresh proof carrying one additional (custom) claim. */
    private String newProofWith(String claim, String value) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setAudience(ISSUER);
        claims.setJwtId(UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        claims.setClaim(claim, value);
        return signCompact(instanceKey, "ES256", InstanceKeyProofValidator.TYP, claims);
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

    /**
     * A JWT-SVID with a jti of its own. Without one, two tests minting for the same SPIFFE ID in the same second
     * would mint the same header and payload - the same evidence, as the digest sees it - and the second, with its
     * own instance key, would meet the first's binding in the process-wide store.
     */
    private static String svid(PublicJsonWebKey signingKey, String sub, String audience, long expOffset) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setJwtId(UUID.randomUUID().toString());
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

    // ---- S3b: the evidence is digested, never carried, and bound to its first presenter --------------

    @SuppressWarnings("unchecked")
    private static Map<String, Object> workloadOf(String attestation) throws Exception {
        String payload = new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]), StandardCharsets.UTF_8);
        return (Map<String, Object>) JsonUtil.parseJson(payload).get("workload");
    }

    private static String payloadOf(String attestation) {
        return new String(java.util.Base64.getUrlDecoder().decode(attestation.split("\\.")[1]), StandardCharsets.UTF_8);
    }

    private static long expOf(String jwt) throws Exception {
        return JwtClaims.parse(payloadOf(jwt)).getExpirationTime().getValue();
    }

    /** The events emitted while {@code body} runs, in order. */
    private static List<com.pingidentity.ps.oidf.federation.event.FederationEvent> eventsWhile(ThrowingRunnable body) throws Exception {
        List<com.pingidentity.ps.oidf.federation.event.FederationEvent> events = new java.util.ArrayList<>();
        FederationEvents.reset();
        FederationEvents.configure(events::add);
        try {
            body.run();
        } finally {
            FederationEvents.reset();
        }
        return events;
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /**
     * CAS §4.5, of {@code workload.instance_attestation_sha256}: "The Instance Attestation itself MUST NOT be embedded
     * (Section 9.1)." Decoded from the minted JWT, so nothing the plugin or a token mapping forwards can carry it.
     */
    @Test
    @Requirement("CAS §4.5")
    void theMintedAttestationCarriesTheEvidenceDigestAndNotTheEvidence() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        String attestation = (String) servlet.issue(req).get("attestation");
        String payload = payloadOf(attestation);
        assertFalse(payload.contains(req.svid), "the raw SVID must not appear anywhere in the attestation (F-0002)");
        assertFalse(payload.contains("\"svid\""), payload);
        Map<String, Object> workload = workloadOf(attestation);
        assertEquals(InstanceIdentity.evidenceDigest(req.svid), workload.get("instance_attestation_sha256"));
        assertEquals("spiffe-jwt", workload.get("instance_attestation_type"));
        assertEquals(expOf(req.svid), ((Number) workload.get("instance_attestation_exp")).longValue());
        assertEquals(SPIFFE_ID, workload.get("spiffe_id"));
        assertRoundTrips(attestation);
    }

    @Test
    void aWalletInstanceAttestationIsDigestedNotCarried() throws Exception {
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        servlet.setInstanceValidators(walletRegistry());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        req.svid = wia(WALLET_INSTANCE_ID, publicParams(instanceKey), 600L);
        req.proof = newProof(null);
        req.requestedDetails = List.of();
        String attestation = (String) servlet.issue(req).get("attestation");
        String payload = payloadOf(attestation);
        assertFalse(payload.contains(req.svid), "the raw WIA must not appear in the attestation: it was raw in 0.3.0 too");
        assertFalse(payload.contains("\"instance_attestation\""), payload);
        Map<String, Object> workload = workloadOf(attestation);
        assertEquals(InstanceIdentity.evidenceDigest(req.svid), workload.get("instance_attestation_sha256"));
        assertEquals("wallet-instance-attestation", workload.get("instance_attestation_type"));
        assertEquals(expOf(req.svid), ((Number) workload.get("instance_attestation_exp")).longValue());
    }

    @Test
    void aCloudTokenIsDigestedWithItsOwnEvidenceType() throws Exception {
        servlet.setClientResolver(fixedResolver(gkeConfig()));
        servlet.setJwksCache(fakeJwksCache());
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        req.svid = ksaToken("system:serviceaccount:demo:payment-agent");
        req.proof = newProof(null);
        req.requestedDetails = List.of();
        Map<String, Object> workload = workloadOf((String) servlet.issue(req).get("attestation"));
        assertEquals("gke-sa-token", workload.get("instance_attestation_type"));
        assertEquals(InstanceIdentity.evidenceDigest(req.svid), workload.get("instance_attestation_sha256"));
        assertFalse(workload.containsKey("svid"));
    }

    /**
     * CAS §9.1: "It SHOULD refuse a later presentation by another key or client with {@code instance_attestation_bound}
     * and record it." The record is the audit event, naming the key refused and the key that holds the binding.
     */
    @Test
    @Requirement("CAS §9.1")
    void evidencePresentedWithASecondInstanceKeyIsRefusedAndAudited() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest first = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        servlet.issue(first);

        PublicJsonWebKey thief = ec("thief-1");
        AttestationIssuanceServlet.IssuanceRequest second = new AttestationIssuanceServlet.IssuanceRequest();
        second.clientId = CLIENT_ID;
        second.instanceKey = publicParams(thief);
        second.svid = first.svid; // the very same evidence
        second.proof = proof(thief, ISSUER, UUID.randomUUID().toString(), null);
        List<com.pingidentity.ps.oidf.federation.event.FederationEvent> events = eventsWhile(() -> {
            IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(second));
            assertEquals("instance_attestation_bound", e.error());
            assertEquals(401, e.status());
        });
        assertEquals(1, events.size(), events.toString());
        com.pingidentity.ps.oidf.federation.event.FederationEvent event = events.get(0);
        assertEquals(AttestationIssuanceServlet.EVIDENCE_CONFLICT_EVENT, event.code());
        assertTrue(event.isFailure());
        assertEquals("evidence_bound_elsewhere", event.reason());
        assertEquals(CLIENT_ID, event.subject());
        assertTrue(event.audit(), "a theft signal belongs in the audit log");
        assertEquals(InstanceIdentity.evidenceDigest(first.svid), event.fields().get("evidence_sha256"));
        assertEquals("spiffe-jwt", event.fields().get("evidence_type"));
        assertEquals(Jwks.thumbprint(publicParams(thief)), event.fields().get("presented_jkt"));
        assertEquals(Jwks.thumbprint(publicParams(instanceKey)), event.fields().get("bound_jkt"),
                "the key that holds the binding is named: when a thief presented first, it is the thief's");
        assertEquals(CLIENT_ID, event.fields().get("bound_client"));
        assertEquals(SPIFFE_ID, event.fields().get("instance_subject"));

        // The rightful holder is not disturbed by the attempt.
        AttestationIssuanceServlet.IssuanceRequest again = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        again.svid = first.svid;
        assertNotNull(servlet.issue(again).get("attestation"), "the same evidence with the same key re-attests");
    }

    /**
     * CAS §9.1: the CAS binds each Instance Attestation "only once steps 1 to 6 of Section 4.4 have passed, so a
     * request those steps refuse never holds a binding."
     */
    @Test
    @Requirement("CAS §9.1")
    void aRefusedPresenterDoesNotHoldTheBindingAgainstTheRightfulKey() throws Exception {
        // A WIA names the rightful instance key. Someone holding the WIA but not that key presents it with a key
        // of their own: the key proof verifies (it is their key), the cnf check refuses them - and the binding
        // must not be theirs, or the rightful wallet would be refused as a conflict from then on.
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        servlet.setInstanceValidators(walletRegistry());
        PublicJsonWebKey rightful = ec("rightful-instance");
        String theWia = wia(WALLET_INSTANCE_ID, publicParams(rightful), 600L);

        AttestationIssuanceServlet.IssuanceRequest holderOfTheWiaOnly = new AttestationIssuanceServlet.IssuanceRequest();
        holderOfTheWiaOnly.instanceKey = publicParams(instanceKey);
        holderOfTheWiaOnly.svid = theWia;
        holderOfTheWiaOnly.proof = newProof(null);
        holderOfTheWiaOnly.requestedDetails = List.of();
        assertEquals("invalid_instance_proof", assertThrows(IssuanceException.class, () -> servlet.issue(holderOfTheWiaOnly)).error());

        AttestationIssuanceServlet.IssuanceRequest wallet = new AttestationIssuanceServlet.IssuanceRequest();
        wallet.instanceKey = publicParams(rightful);
        wallet.svid = theWia;
        wallet.proof = proof(rightful, ISSUER, UUID.randomUUID().toString(), null);
        wallet.requestedDetails = List.of();
        assertNotNull(servlet.issue(wallet).get("attestation"), "the rightful key is issued: the refused presenter took no binding");
    }

    /**
     * CAS §9.1: "The binding MUST be keyed on what the Instance Attestation's signature covers and nothing else, so
     * that the same token re-encoded - with trailing whitespace, or another encoding of the same signature - meets
     * the same binding." A JWS verifier accepts one signed token in many strings - trailing whitespace, a stray
     * character or padding in the signature, non-canonical trailing bits, the ECDSA {@code (r, n-s)} twin - and
     * each, presented with a thief's key, must meet the rightful key's binding, not take one of its own.
     */
    @Test
    @Requirement("CAS §9.1")
    void aReEncodedSvidIsTheSameEvidenceAndStaysBoundToItsFirstKey() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest first = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        assertReEncodingsMeetTheBinding(first, "spiffe-jwt");
    }

    @Test
    @Requirement("CAS §9.1")
    void aReEncodedCloudTokenIsTheSameEvidenceAndStaysBoundToItsFirstKey() throws Exception {
        servlet.setClientResolver(fixedResolver(gkeConfig()));
        servlet.setJwksCache(fakeJwksCache());
        AttestationIssuanceServlet.IssuanceRequest first = new AttestationIssuanceServlet.IssuanceRequest();
        first.clientId = CLIENT_ID;
        first.instanceKey = publicParams(instanceKey);
        first.svid = ksaToken("system:serviceaccount:demo:payment-agent");
        first.proof = newProof(null);
        first.requestedDetails = List.of();
        assertReEncodingsMeetTheBinding(first, "gke-sa-token");
    }

    /**
     * CAS §4.5, of {@code workload.instance_attestation_sha256}: "The SHA-256, lower-case hex, of the validated
     * Instance Attestation's JWS Signing Input [RFC7515] - its first two segments, which are what its signature
     * covers - so an auditor holding a captured token can match it."
     */
    @Test
    @Requirement("CAS §4.5")
    void theDigestIsWhatAnAuditorComputesFromTheCapturedEvidence() throws Exception {
        servlet.setClientResolver(fixedResolver(walletConfig(null)));
        servlet.setInstanceValidators(walletRegistry());
        String captured = wia(WALLET_INSTANCE_ID, publicParams(instanceKey), 600L);
        AttestationIssuanceServlet.IssuanceRequest req = new AttestationIssuanceServlet.IssuanceRequest();
        req.instanceKey = publicParams(instanceKey);
        req.svid = captured + " ";
        req.proof = newProof(null);
        req.requestedDetails = List.of();
        Map<String, Object> workload = workloadOf((String) servlet.issue(req).get("attestation"));
        // printf %s "${captured%.*}" | sha256sum
        assertEquals(InstanceIdentity.sha256Hex(captured.substring(0, captured.lastIndexOf('.'))),
                workload.get("instance_attestation_sha256"));
    }

    private void assertReEncodingsMeetTheBinding(AttestationIssuanceServlet.IssuanceRequest first, String evidenceType)
            throws Exception {
        Map<String, Object> workload = workloadOf((String) servlet.issue(first).get("attestation"));
        String digest = (String) workload.get("instance_attestation_sha256");
        assertEquals(evidenceType, workload.get("instance_attestation_type"));
        assertEquals(InstanceIdentity.sha256Hex(first.svid.substring(0, first.svid.lastIndexOf('.'))), digest,
                "the digest covers the header and payload as signed");

        PublicJsonWebKey thief = ec("thief-re-encoder");
        List<String> variants = reEncodings(first.svid);
        for (String variant : variants) {
            assertTrue(!variant.equals(first.svid) && verifiesUnder(variant, bundleKey), "a variant the verifier accepts: " + variant);
            AttestationIssuanceServlet.IssuanceRequest stolen = new AttestationIssuanceServlet.IssuanceRequest();
            stolen.clientId = first.clientId;
            stolen.instanceKey = publicParams(thief);
            stolen.svid = variant;
            stolen.proof = proof(thief, ISSUER, UUID.randomUUID().toString(), null);
            stolen.requestedDetails = List.of();
            List<com.pingidentity.ps.oidf.federation.event.FederationEvent> events = eventsWhile(() -> {
                IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(stolen), variant);
                assertEquals("instance_attestation_bound", e.error(), variant);
            });
            assertEquals(1, events.size(), variant);
            assertEquals(digest, events.get(0).fields().get("evidence_sha256"), variant);
            assertEquals(Jwks.thumbprint(publicParams(thief)), events.get(0).fields().get("presented_jkt"));
            assertEquals(Jwks.thumbprint(publicParams(instanceKey)), events.get(0).fields().get("bound_jkt"));
        }

        // The rightful key presenting a re-encoding is the same presenter with the same evidence.
        AttestationIssuanceServlet.IssuanceRequest again = new AttestationIssuanceServlet.IssuanceRequest();
        again.clientId = first.clientId;
        again.instanceKey = publicParams(instanceKey);
        again.svid = variants.get(variants.size() - 1);
        again.proof = newProof(null);
        again.requestedDetails = List.of();
        assertEquals(digest, workloadOf((String) servlet.issue(again).get("attestation")).get("instance_attestation_sha256"));
    }

    /**
     * Strings a JWS verifier accepts for one ES256 token, none equal to it: trailing space and newline, a stray
     * character and padding in the signature, the last signature character with a different unused low bit, and
     * the ECDSA {@code (r, n-s)} twin.
     */
    private static List<String> reEncodings(String compact) {
        String[] parts = compact.split("\\.");
        String signingInput = parts[0] + "." + parts[1] + ".";
        String sig = parts[2];
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        char last = sig.charAt(sig.length() - 1);
        String nonCanonical = sig.substring(0, sig.length() - 1) + alphabet.charAt(alphabet.indexOf(last) ^ 1);
        byte[] rs = org.jose4j.base64url.Base64Url.decode(sig);
        java.math.BigInteger n = EllipticCurves.P256.getOrder();
        java.math.BigInteger s = new java.math.BigInteger(1, java.util.Arrays.copyOfRange(rs, 32, 64));
        byte[] twinS = n.subtract(s).toByteArray();
        byte[] twin = java.util.Arrays.copyOf(rs, 64);
        java.util.Arrays.fill(twin, 32, 64, (byte) 0);
        int copy = Math.min(32, twinS.length);
        System.arraycopy(twinS, twinS.length - copy, twin, 64 - copy, copy);
        return List.of(
                compact + " ",
                compact + "\n",
                signingInput + sig.substring(0, 10) + "!" + sig.substring(10),
                compact + "==",
                signingInput + nonCanonical,
                signingInput + org.jose4j.base64url.Base64Url.encode(twin));
    }

    private static boolean verifiesUnder(String compact, PublicJsonWebKey key) {
        try {
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(compact);
            jws.setKey(key.getPublicKey());
            return jws.verifySignature();
        } catch (Exception e) {
            return false;
        }
    }

    @Test
    void theSameEvidenceForAnotherClientIsAConflictToo() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest first = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        servlet.issue(first);
        // The same workload, the same key, but the binding store already holds the evidence for another client.
        InMemoryEvidenceBindingStore store = new InMemoryEvidenceBindingStore();
        store.bind(InstanceIdentity.evidenceDigest(first.svid), Jwks.thumbprint(publicParams(instanceKey)), "https://other.example", expOf(first.svid));
        servlet.setEvidenceBindingStore(store);
        AttestationIssuanceServlet.IssuanceRequest again = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        again.svid = first.svid;
        assertEquals("instance_attestation_bound", assertThrows(IssuanceException.class, () -> servlet.issue(again)).error());
    }

    /**
     * CAS §4.6: "{@code temporarily_unavailable} - The CAS cannot check the request now - for example, the store
     * that tracks challenges, proof {@code jti}s or bindings does not answer - and the client may retry later. (503)"
     */
    @Test
    @Requirement("CAS §4.6")
    void aStoreThatCannotAnswerIsTemporarilyUnavailableNotARefusal() throws Exception {
        servlet.setEvidenceBindingStore((digest, jkt, client, exp) -> EvidenceBindingStore.Result.unavailable());
        IssuanceException binding = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("temporarily_unavailable", binding.error());
        assertEquals(503, binding.status());

        servlet.setEvidenceBindingStore(new InMemoryEvidenceBindingStore());
        servlet.setReplayCache((client, jti, ttl) -> AttestationReplayCache.Verdict.STORE_UNAVAILABLE);
        IssuanceException replay = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("temporarily_unavailable", replay.error());

        servlet.setReplayCache(new InMemoryAttestationReplayCache());
        servlet.setChallengeService(new AttestationChallengeService() {
            @Override
            public String issue() {
                return "c";
            }

            @Override
            public Consumption consumeChallenge(String challenge) {
                return Consumption.STORE_UNAVAILABLE;
            }

            @Override
            public long ttlSeconds() {
                return 300L;
            }
        });
        IssuanceException challenge = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof("some-challenge"), List.of())));
        assertEquals("temporarily_unavailable", challenge.error());
    }

    @Test
    void evidenceThatLivesLongerThanThePolicyAllowsIsRefused() throws Exception {
        servlet.setEvidencePolicy(new EvidencePolicy(60L, false));
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
        assertEquals("invalid_svid", e.error());
        assertTrue(e.getMessage().contains(EvidencePolicy.MAX_LIFETIME_ENV), e.getMessage());
    }

    @Test
    void multiAudienceEvidenceIsRefusedWhenThePolicyRequiresOne() throws Exception {
        servlet.setEvidencePolicy(new EvidencePolicy(86400L, true));
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        JwtClaims claims = new JwtClaims();
        claims.setSubject(SPIFFE_ID);
        claims.setAudience(List.of(ISSUER, "https://elsewhere.example.com"));
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        req.svid = signCompact(bundleKey, "ES256", "JWT", claims);
        IssuanceException e = assertThrows(IssuanceException.class, () -> servlet.issue(req));
        assertEquals("invalid_svid", e.error());
        assertTrue(e.getMessage().contains(EvidencePolicy.SINGLE_AUDIENCE_ENV), e.getMessage());
        servlet.setEvidencePolicy(new EvidencePolicy(86400L, false));
        req.proof = newProof(null);
        assertNotNull(servlet.issue(req).get("attestation"), "the same evidence is accepted when the policy does not require one");
    }

    /** CAS §4.5, of {@code workload.instance_attestation_exp}: "The Client Attestation's {@code exp} MUST NOT be later." */
    @Test
    @Requirement("CAS §4.5")
    void theAttestationExpiresNoLaterThanItsEvidence() throws Exception {
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        req.svid = svid(bundleKey, SPIFFE_ID, ISSUER, 30L);
        Map<String, Object> body = servlet.issue(req);
        long expiresIn = ((Number) body.get("expires_in")).longValue();
        assertTrue(expiresIn <= 30L && expiresIn >= 28L, "expires_in follows the evidence: " + expiresIn);
        assertTrue(expOf((String) body.get("attestation")) <= expOf(req.svid));
    }

    @Test
    void aMisconfiguredEvidencePolicyFailsTheRequestNamingTheVariable() throws Exception {
        servlet.setEvidencePolicy(null);
        System.setProperty(EvidencePolicy.MAX_LIFETIME_PROPERTY, "soon");
        try {
            IssuanceException e = assertThrows(IssuanceException.class,
                    () -> servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())));
            assertEquals("server_error", e.error());
            assertTrue(e.getMessage().contains(EvidencePolicy.MAX_LIFETIME_ENV), e.getMessage());
        } finally {
            System.clearProperty(EvidencePolicy.MAX_LIFETIME_PROPERTY);
        }
        servlet.setEvidencePolicy(null);
        assertNotNull(servlet.issue(request(SPIFFE_ID, ISSUER, newProof(null), List.of())).get("attestation"),
                "with the property gone the policy reads its defaults on the next request");
        assertEquals(86400L, servlet.evidencePolicy().maxEvidenceLifetimeSeconds());
    }

    @Test
    void evidenceWithNothingToDigestIsNotBound() throws Exception {
        // A validator for the default evidence type whose identity has no digest: the binding step is skipped,
        // so a second instance key presenting the same evidence is not a conflict.
        com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator digestless = new com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator() {
            @Override
            public String id() {
                return AttestationIssuanceConfig.EVIDENCE_SPIFFE_JWT;
            }

            @Override
            public String format() {
                return "spiffe";
            }

            @Override
            public String title() {
                return "digest-less";
            }

            @Override
            public String description() {
                return "a test validator";
            }

            @Override
            public InstanceIdentity validate(String presented, List<JsonWebKey> bundleKeys, AttestationIssuanceConfig config) {
                return new InstanceIdentity("spiffe", SPIFFE_ID, "banking.demo", null, Map.of("spiffe_id", SPIFFE_ID),
                        NumericDate.now().getValue() + 600);
            }
        };
        servlet.setInstanceValidators(com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators.defaults().with(digestless));
        AttestationIssuanceServlet.IssuanceRequest first = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        servlet.issue(first);
        PublicJsonWebKey other = ec("other-2");
        AttestationIssuanceServlet.IssuanceRequest second = new AttestationIssuanceServlet.IssuanceRequest();
        second.clientId = CLIENT_ID;
        second.instanceKey = publicParams(other);
        second.svid = first.svid;
        second.proof = proof(other, ISSUER, UUID.randomUUID().toString(), null);
        Map<String, Object> workload = workloadOf((String) servlet.issue(second).get("attestation"));
        assertFalse(workload.containsKey("instance_attestation_sha256"));
        assertNotNull(workload.get("instance_attestation_exp"));
    }

    @Test
    void aKeyThatCannotBeThumbprintedIsAnInternalErrorNotAClientOne() throws Exception {
        assertEquals(Jwks.thumbprint(publicParams(instanceKey)), AttestationIssuanceServlet.thumbprintOf(publicParams(instanceKey)));
        assertThrows(IllegalStateException.class, () -> AttestationIssuanceServlet.thumbprintOf(Map.of("kty", "EC", "crv", "P-256")));
        AttestationIssuanceServlet.IssuanceRequest req = request(SPIFFE_ID, ISSUER, newProof(null), List.of());
        req.instanceKey = new LinkedHashMap<>(Map.of("kty", "EC", "crv", "P-256", "x", "AA", "y", "AA"));
        // Through the servlet the key proof fails first: a proof signed by the real key does not verify under a garbage key.
        assertEquals("invalid_instance_proof", assertThrows(IssuanceException.class, () -> servlet.issue(req)).error());
    }
}
