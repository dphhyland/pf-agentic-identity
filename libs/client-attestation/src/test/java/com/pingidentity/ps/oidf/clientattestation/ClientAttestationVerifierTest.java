package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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

class ClientAttestationVerifierTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;
    private AttesterKeyResolver resolver;
    private AttestationChallengeService challengeService;
    private ClientAttestationVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        attesterKey = TestJwts.ec("attester-1");
        instanceKey = TestJwts.ec("instance-1");
        resolver = (iss, chain) -> List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey)));
        challengeService = new InMemoryAttestationChallengeService();
        verifier = newVerifier(false);
    }

    private ClientAttestationVerifier newVerifier(boolean challengeRequired) {
        return newVerifier(challengeRequired, Set.of());
    }

    private ClientAttestationVerifier newVerifier(boolean challengeRequired, Set<String> requiredDisclosedClaims) {
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .addAcceptedAudience(TOKEN_ENDPOINT)
                .expectedHtu(TOKEN_ENDPOINT)
                .challengeRequired(challengeRequired)
                .requiredDisclosedClaims(requiredDisclosedClaims)
                .build();
        return new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), challengeService);
    }

    private String attestation(Map<String, Object> cnfJwk, long expSecondsFromNow) throws Exception {
        return attestation(cnfJwk, expSecondsFromNow, null);
    }

    private String attestation(Map<String, Object> cnfJwk, long expSecondsFromNow, String agentId) throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expSecondsFromNow));
        att.setClaim("cnf", Map.of("jwk", cnfJwk));
        if (agentId != null) {
            att.setClaim("agent_id", agentId);
        }
        return TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);
    }

    private String validAttestation() throws Exception {
        return attestation(TestJwts.publicParams(instanceKey), 600L);
    }

    /** Like {@link #attestation(Map, long)} but with arbitrary extra top-level claims (e.g. {@code workload},
     *  {@code authorization_details}) merged in. */
    private String attestationWithClaims(Map<String, Object> cnfJwk, long expSecondsFromNow,
                                         Map<String, Object> extraClaims) throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expSecondsFromNow));
        att.setClaim("cnf", Map.of("jwk", cnfJwk));
        extraClaims.forEach(att::setClaim);
        return TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);
    }

    private String pop(String audience, String jti, String challenge) throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(audience);
        pop.setJwtId(jti);
        pop.setIssuedAtToNow();
        if (challenge != null) {
            pop.setClaim("challenge", challenge);
        }
        return TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
    }

    private String dpop(PublicJsonWebKey signingKey, String jti, String nonce) throws Exception {
        JwtClaims d = new JwtClaims();
        d.setClaim("htm", "POST");
        d.setClaim("htu", TOKEN_ENDPOINT);
        d.setJwtId(jti);
        d.setIssuedAtToNow();
        if (nonce != null) {
            d.setClaim("nonce", nonce);
        }
        return TestJwts.signWithJwkHeader(signingKey, "ES256", "dpop+jwt", d);
    }

    @Test
    void popModeHappyPath() throws Exception {
        ClientAttestationResult result = verifier.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, result.mode());
        assertEquals(ATTESTER, result.attesterIssuer());
    }

    @Test
    void dpopCombinedModeHappyPath() throws Exception {
        ClientAttestationResult result = verifier.verify(validAttestation(), null, dpop(instanceKey, "d1", null), "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.DPOP, result.mode());
    }

    @Test
    void dpopKeyMustMatchCnf() throws Exception {
        PublicJsonWebKey otherKey = TestJwts.ec("other-1");
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), null, dpop(otherKey, "d1", null), "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    @Test
    void expiredAttestationYieldsUseFresh() throws Exception {
        String expired = attestation(TestJwts.publicParams(instanceKey), -600L);
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(expired, pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.USE_FRESH_ATTESTATION, ex.error());
    }

    @Test
    void bothPopAndDpopRejected() throws Exception {
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), pop(OP_ISSUER, "p1", null), dpop(instanceKey, "d1", null), "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    @Test
    void missingProofRejected() throws Exception {
        assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), null, null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    @Test
    void wrongPopAudienceRejected() throws Exception {
        assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), pop("https://someone-else.example.com", "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    @Test
    void clientIdMismatchRejected() throws Exception {
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, "https://attacker.example.com"));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    @Test
    void privateCnfKeyRejected() throws Exception {
        String att = attestation(TestJwts.privateParams(instanceKey), 600L);
        assertThrows(ClientAttestationException.class,
                () -> verifier.verify(att, pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    @Test
    void replayedPopRejected() throws Exception {
        String att = validAttestation();
        String popJwt = pop(OP_ISSUER, "p1", null);
        verifier.verify(att, popJwt, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(att, popJwt, null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    @Test
    void challengeRequiredButMissingYieldsUseChallenge() throws Exception {
        ClientAttestationVerifier strict = newVerifier(true);
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> strict.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.USE_ATTESTATION_CHALLENGE, ex.error());
    }

    @Test
    void validChallengeAccepted() throws Exception {
        ClientAttestationVerifier strict = newVerifier(true);
        String challenge = challengeService.issue();
        ClientAttestationResult result = strict.verify(validAttestation(), pop(OP_ISSUER, "p1", challenge), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
    }

    @Test
    void staleOrUnknownChallengeRejected() throws Exception {
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), pop(OP_ISSUER, "p1", "never-issued"), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.USE_ATTESTATION_CHALLENGE, ex.error());
    }

    // ---- agent_id (Phase 2.6) ------------------------------------------------------------------------

    @Test
    void agentIdIsAbsentWhenTheAttestationCarriesNone() throws Exception {
        ClientAttestationResult result = verifier.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertNull(result.agentId());
    }

    @Test
    void agentIdIsCarriedThroughToTheResultWhenPresent() throws Exception {
        String att = attestation(TestJwts.publicParams(instanceKey), 600L, "agent-id-1");
        ClientAttestationResult result = verifier.verify(att, pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals("agent-id-1", result.agentId());
    }

    @Test
    void agentIdIsCarriedThroughInDpopModeToo() throws Exception {
        String att = attestation(TestJwts.publicParams(instanceKey), 600L, "agent-id-2");
        ClientAttestationResult result = verifier.verify(att, null, dpop(instanceKey, "d1", null), "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals("agent-id-2", result.agentId());
    }

    /**
     * Pin (Phase 2.6): a present agent_id — even one that is neither the client_id nor anything else in
     * play — has no effect on the sub == client_id / PoP-iss == sub checks. Verification succeeds exactly
     * as it would with no agent_id at all.
     */
    @Test
    void anUnrelatedAgentIdDoesNotAffectNormalVerification() throws Exception {
        String att = attestation(TestJwts.publicParams(instanceKey), 600L, "completely-unrelated-value");
        ClientAttestationResult result = verifier.verify(att, pop(OP_ISSUER, "p1", null), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
    }

    /**
     * Pin (Phase 2.6): a PoP whose 'iss' is set to the agent_id — not the client_id — must still be
     * rejected. Proves the "PoP 'iss' does not match the attestation 'sub'" check is genuinely keyed off
     * clientId/sub and is not accidentally satisfiable via agent_id.
     */
    @Test
    void popIssuerSetToTheAgentIdRatherThanTheClientIdIsStillRejected() throws Exception {
        String agentId = "agent-id-3";
        String att = attestation(TestJwts.publicParams(instanceKey), 600L, agentId);
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(agentId); // deliberately the agent_id, not CLIENT_ID
        pop.setAudience(OP_ISSUER);
        pop.setJwtId("p1");
        pop.setIssuedAtToNow();
        String popJwt = TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);

        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(att, popJwt, null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    // ---- RFC 9396 authorization_details containment, through the full verify() overload -----------------

    @Test
    void rarContainmentGrantsRequestWithinAttestedEntitlement() throws Exception {
        List<Map<String, Object>> entitlement = List.of(Map.of(
                "type", "sales_agent",
                "actions", List.of("read_accounts", "create_opportunity"),
                "sales_regions", List.of("EMEA")));
        String att = attestationWithClaims(TestJwts.publicParams(instanceKey), 600L,
                Map.of("authorization_details", entitlement));
        String requested = "[{\"type\":\"sales_agent\",\"actions\":[\"create_opportunity\"],\"sales_regions\":[\"EMEA\"]}]";

        ClientAttestationResult result = verifier.verify(att, pop(OP_ISSUER, "p1", null), null,
                "POST", TOKEN_ENDPOINT, CLIENT_ID, requested);

        assertEquals(1, result.grantedAuthorizationDetails().size());
        assertEquals(entitlement, result.entitledAuthorizationDetails());
    }

    @Test
    void rarContainmentDeniesRequestExceedingAttestedEntitlement() throws Exception {
        List<Map<String, Object>> entitlement = List.of(Map.of(
                "type", "sales_agent",
                "sales_regions", List.of("EMEA")));
        String att = attestationWithClaims(TestJwts.publicParams(instanceKey), 600L,
                Map.of("authorization_details", entitlement));
        String requested = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"AMER\"]}]";

        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(att, pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID, requested));
        assertEquals(ClientAttestationException.ACCESS_DENIED, ex.error());
    }

    @Test
    void rarContainmentDeniesWhenAttestationAssertsNoEntitlementAtAll() throws Exception {
        String requested = "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]";
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID, requested));
        assertEquals(ClientAttestationException.ACCESS_DENIED, ex.error());
    }

    // ---- required-disclosed-claims policy ------------------------------------------------------------

    @Test
    void requiredWorkloadClaimMissingIsRejected() throws Exception {
        ClientAttestationVerifier strict = newVerifier(false, Set.of("workload"));
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> strict.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INSUFFICIENT_DISCLOSURE, ex.error());
    }

    @Test
    void requiredAuthorizationDetailsClaimMissingIsRejected() throws Exception {
        ClientAttestationVerifier strict = newVerifier(false, Set.of("authorization_details"));
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> strict.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INSUFFICIENT_DISCLOSURE, ex.error());
    }

    @Test
    void requiredWorkloadClaimPresentIsAccepted() throws Exception {
        ClientAttestationVerifier strict = newVerifier(false, Set.of("workload"));
        String att = attestationWithClaims(TestJwts.publicParams(instanceKey), 600L,
                Map.of("workload", Map.of("spiffe_id", "spiffe://example.org/agent")));

        ClientAttestationResult result = strict.verify(att, pop(OP_ISSUER, "p1", null), null,
                "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
        assertEquals("spiffe://example.org/agent", result.workload().get("spiffe_id"));
    }

    @Test
    void requiredAgentIdClaimMissingIsRejected() throws Exception {
        ClientAttestationVerifier strict = newVerifier(false, Set.of("agent_id"));
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> strict.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INSUFFICIENT_DISCLOSURE, ex.error());
    }

    /**
     * Pins a known fail-open gap rather than asserting desired behaviour: the switch in
     * {@code enforceRequiredDisclosures} satisfies any claim name it does not recognise, so a typo
     * ({@code agentid}, {@code agent-id}) silently disables the requirement instead of enforcing it.
     * Every recognised name is covered above; this is the arm that made the {@code agent_id} case
     * invisible until it was added.
     *
     * <p>Left permissive deliberately. The config is built per authentication request from per-client
     * {@code extproperties} (see {@code ClientAttestationUtils.buildConfig}), so rejecting an unknown
     * name would fail that client's authentication at runtime, not fail fast at startup. The verifier
     * now logs a WARN once per distinct unrecognised name so the misconfiguration is visible rather
     * than silent, but the request is still allowed through. If that is ever made fail-closed, this
     * test should invert.
     */
    @Test
    void anUnrecognisedRequiredClaimNameIsCurrentlySatisfiedRatherThanEnforced() throws Exception {
        ClientAttestationVerifier typo = newVerifier(false, Set.of("agentid"));
        ClientAttestationResult result = typo.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null,
                "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId(),
                "an unknown required-claim name is silently satisfied; see the javadoc above");
    }

    // ---- SD-JWT presentation is retired -----------------------------------------------------------

    @Test
    void sdJwtEncodedAttestationIsRejected() throws Exception {
        String sdJwtStyle = validAttestation() + "~disclosure1~disclosure2";
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(sdJwtStyle, pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    // ---- attester trust is enforced, not merely a well-formed signature ----------------------------

    @Test
    void attestationSignedByAnUntrustedKeyIsRejected() throws Exception {
        PublicJsonWebKey imposterKey = TestJwts.ec("imposter-1");
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        // Signed by a key the resolver never returns for this attester issuer.
        String forged = TestJwts.sign(imposterKey, "ES256", "oauth-client-attestation+jwt", att);

        assertThrows(ClientAttestationException.class,
                () -> verifier.verify(forged, pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    @Test
    void attestationMissingCnfClaimIsRejected() throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        String noCnf = TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);

        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(noCnf, pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    // ---- DPoP combined mode: replay and challenge enforcement parity with PoP mode -------------------

    @Test
    void replayedDpopRejected() throws Exception {
        String att = validAttestation();
        String dpopJwt = dpop(instanceKey, "d1", null);
        verifier.verify(att, null, dpopJwt, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> verifier.verify(att, null, dpopJwt, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, ex.error());
    }

    @Test
    void dpopChallengeRequiredButMissingYieldsUseChallenge() throws Exception {
        ClientAttestationVerifier strict = newVerifier(true);
        ClientAttestationException ex = assertThrows(ClientAttestationException.class,
                () -> strict.verify(validAttestation(), null, dpop(instanceKey, "d1", null),
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.USE_ATTESTATION_CHALLENGE, ex.error());
    }

    @Test
    void dpopValidChallengeAccepted() throws Exception {
        ClientAttestationVerifier strict = newVerifier(true);
        String challenge = challengeService.issue();
        ClientAttestationResult result = strict.verify(validAttestation(), null,
                dpop(instanceKey, "d1", challenge), "POST", TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(CLIENT_ID, result.clientId());
    }

    // ---- server misconfiguration fails closed rather than skipping the audience check ----------------

    @Test
    void popModeWithNoConfiguredAudienceIsRejectedAsMisconfigured() throws Exception {
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .expectedHtu(TOKEN_ENDPOINT)
                .build(); // deliberately no accepted audiences configured
        ClientAttestationVerifier misconfigured =
                new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), challengeService);

        assertThrows(ClientAttestationException.class,
                () -> misconfigured.verify(validAttestation(), pop(OP_ISSUER, "p1", null), null,
                        "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }
}
