package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Executable conformance checks for docs/ai-agent-attestation-profile-1_0.md against a config built to
 * satisfy it. The profile fixes what ABCA-10 leaves open; these tests pin the three requirements that
 * are enforceable at the verifier - algorithms (§3), attestation lifetime (§5), and identity claims
 * (§6) - so the profile is a thing CI can fail on rather than prose.
 *
 * <p><strong>These assert the profile-conformant config, not the shipped defaults.</strong> The
 * defaults are deliberately broader (see {@link ClientAttestationConfig#DEFAULT_ASYMMETRIC_ALGORITHMS}
 * and the ceiling being off unless set), so that adopting the profile is an explicit opt-in and no
 * existing deployment changes behaviour. {@link #theShippedDefaultsAreBroaderThanTheProfile()} and
 * {@link #theCeilingIsOffUnlessTheDeploymentSetsIt()} pin that gap deliberately: if someone later
 * narrows the defaults, those two tests fail and this comment gets revisited.
 */
class ProfileConformanceTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String OP_ISSUER = "https://op.example.com";
    private static final String TOKEN_ENDPOINT = OP_ISSUER + "/as/token.oauth2";

    /** §3: the profile narrows ABCA's open algorithm choice to exactly these two. */
    private static final Set<String> PROFILE_ALGORITHMS = Set.of("PS256", "ES256");
    /** §5: an issued attestation's exp SHALL NOT exceed iat + 18 hours. */
    private static final long EIGHTEEN_HOURS = 18L * 60L * 60L;

    private PublicJsonWebKey attesterEc;
    private PublicJsonWebKey attesterRsa;
    private PublicJsonWebKey instanceEc;
    private PublicJsonWebKey instanceRsa;
    private AttesterKeyResolver resolver;
    private ClientAttestationVerifier verifier;

    @BeforeEach
    void setUp() throws Exception {
        attesterEc = TestJwts.ec("attester-ec");
        attesterRsa = TestJwts.rsa("attester-rsa");
        instanceEc = TestJwts.ec("instance-ec");
        instanceRsa = TestJwts.rsa("instance-rsa");
        resolver = (iss, chain) -> List.of(
                JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterEc)),
                JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterRsa)));
        verifier = new ClientAttestationVerifier(resolver, profileConfig(),
                new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
    }

    /** A configuration built to satisfy the profile. Nothing here is a default. */
    private static ClientAttestationConfig profileConfig() {
        return ClientAttestationConfig.builder()
                .attestationAlgorithms(PROFILE_ALGORITHMS)
                .popAlgorithms(PROFILE_ALGORITHMS)
                .dpopAlgorithms(PROFILE_ALGORITHMS)
                .maxAttestationLifetimeSeconds(EIGHTEEN_HOURS)
                .requiredDisclosedClaims(Set.of("agent_id"))
                .addAcceptedAudience(OP_ISSUER)
                .addAcceptedAudience(TOKEN_ENDPOINT)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
    }

    private String attestation(PublicJsonWebKey signer, String alg, PublicJsonWebKey cnfKey,
                               long lifetimeSeconds, String agentId, boolean withIat) throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        long now = NumericDate.now().getValue();
        if (withIat) {
            att.setIssuedAt(NumericDate.fromSeconds(now));
        }
        att.setExpirationTime(NumericDate.fromSeconds(now + lifetimeSeconds));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(cnfKey)));
        if (agentId != null) {
            att.setClaim("agent_id", agentId);
        }
        return TestJwts.sign(signer, alg, "oauth-client-attestation+jwt", att);
    }

    /** A conformant attestation: ES256, 10 minutes, agent_id present. */
    private String conformantAttestation() throws Exception {
        return attestation(attesterEc, "ES256", instanceEc, 600L, "agent-1", true);
    }

    private String pop(PublicJsonWebKey signer, String alg, String jti) throws Exception {
        JwtClaims pop = new JwtClaims();
        pop.setIssuer(CLIENT_ID);
        pop.setAudience(OP_ISSUER);
        pop.setJwtId(jti);
        pop.setIssuedAtToNow();
        return TestJwts.sign(signer, alg, "oauth-client-attestation-pop+jwt", pop);
    }

    private ClientAttestationResult verify(String attestation, String pop) throws Exception {
        return verifier.verify(attestation, pop, null, "POST", TOKEN_ENDPOINT, CLIENT_ID);
    }

    // ---------- §3 Algorithms ----------

    @Test
    void anEs256AttestationAndPopAreAccepted() throws Exception {
        ClientAttestationResult result = verify(conformantAttestation(), pop(instanceEc, "ES256", "p1"));
        assertEquals(CLIENT_ID, result.clientId());
    }

    @Test
    void aPs256AttestationIsAccepted() throws Exception {
        String att = attestation(attesterRsa, "PS256", instanceEc, 600L, "agent-1", true);
        assertEquals(CLIENT_ID, verify(att, pop(instanceEc, "ES256", "p2")).clientId());
    }

    @Test
    void anRs256AttestationIsRejected() throws Exception {
        String att = attestation(attesterRsa, "RS256", instanceEc, 600L, "agent-1", true);
        assertThrows(ClientAttestationException.class, () -> verify(att, pop(instanceEc, "ES256", "p3")));
    }

    @Test
    void anRs256PopIsRejected() throws Exception {
        String att = attestation(attesterEc, "ES256", instanceRsa, 600L, "agent-1", true);
        assertThrows(ClientAttestationException.class, () -> verify(att, pop(instanceRsa, "RS256", "p4")));
    }

    /**
     * Control for {@link #anRs256AttestationIsRejected()}: the very same attestation verifies once
     * RS256 is permitted. Without this, that test would still pass if the rejection came from key
     * resolution or a malformed fixture rather than from the §3 allowlist.
     */
    @Test
    void theRs256RejectionIsTheAllowlistAndNotAnIncidentalFailure() throws Exception {
        String att = attestation(attesterRsa, "RS256", instanceEc, 600L, "agent-1", true);
        ClientAttestationConfig permissive = ClientAttestationConfig.builder()
                .attestationAlgorithms(Set.of("RS256"))
                .popAlgorithms(PROFILE_ALGORITHMS)
                .maxAttestationLifetimeSeconds(EIGHTEEN_HOURS)
                .requiredDisclosedClaims(Set.of("agent_id"))
                .addAcceptedAudience(OP_ISSUER)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        ClientAttestationVerifier permissiveVerifier = new ClientAttestationVerifier(resolver, permissive,
                new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
        assertEquals(CLIENT_ID, permissiveVerifier
                .verify(att, pop(instanceEc, "ES256", "c1"), null, "POST", TOKEN_ENDPOINT, CLIENT_ID).clientId());
    }

    @Test
    void theAllowlistIsExplicitAndCoversAttestationPopAndDpop() {
        ClientAttestationConfig config = profileConfig();
        assertEquals(PROFILE_ALGORITHMS, config.attestationAlgorithms());
        assertEquals(PROFILE_ALGORITHMS, config.popAlgorithms());
        assertEquals(PROFILE_ALGORITHMS, config.dpopAlgorithms());
    }

    @Test
    void theShippedDefaultsAreBroaderThanTheProfile() {
        Set<String> shipped = ClientAttestationConfig.builder().build().attestationAlgorithms();
        assertTrue(shipped.contains("RS256"),
                "defaults are deliberately left broad; the profile is opt-in");
        assertTrue(shipped.containsAll(PROFILE_ALGORITHMS));
        assertTrue(shipped.stream().noneMatch(a -> a.startsWith("HS") || "none".equals(a)),
                "§3.2: no MACs and no 'none', even in the broad default");
    }

    // ---------- §5 Attestation lifetime ----------

    @Test
    void anAttestationInsideTheCeilingIsAccepted() throws Exception {
        String att = attestation(attesterEc, "ES256", instanceEc, EIGHTEEN_HOURS - 60L, "agent-1", true);
        assertEquals(CLIENT_ID, verify(att, pop(instanceEc, "ES256", "p5")).clientId());
    }

    @Test
    void anAttestationExceedingTheCeilingIsRejected() throws Exception {
        String att = attestation(attesterEc, "ES256", instanceEc, EIGHTEEN_HOURS + 3600L, "agent-1", true);
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> verify(att, pop(instanceEc, "ES256", "p6")));
        assertTrue(e.getMessage().contains("ceiling"), e.getMessage());
    }

    @Test
    void anAttestationWithNoIatIsRejectedRatherThanExempted() throws Exception {
        String att = attestation(attesterEc, "ES256", instanceEc, 600L, "agent-1", false);
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> verify(att, pop(instanceEc, "ES256", "p7")));
        assertTrue(e.getMessage().contains("iat"), e.getMessage());
    }

    @Test
    void theCeilingIsOffUnlessTheDeploymentSetsIt() throws Exception {
        ClientAttestationConfig defaults = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .expectedHtu(TOKEN_ENDPOINT)
                .build();
        assertEquals(ClientAttestationConfig.NO_MAX_ATTESTATION_LIFETIME, defaults.maxAttestationLifetimeSeconds());
        ClientAttestationVerifier lenient = new ClientAttestationVerifier(resolver, defaults,
                new InMemoryAttestationReplayCache(), new InMemoryAttestationChallengeService());
        String att = attestation(attesterEc, "ES256", instanceEc, EIGHTEEN_HOURS + 3600L, null, true);
        assertEquals(CLIENT_ID,
                lenient.verify(att, pop(instanceEc, "ES256", "p8"), null, "POST", TOKEN_ENDPOINT, CLIENT_ID).clientId());
    }

    // ---------- §6 sub and agent_id ----------

    @Test
    void anAttestationWithoutAgentIdIsRejected() throws Exception {
        String att = attestation(attesterEc, "ES256", instanceEc, 600L, null, true);
        assertThrows(ClientAttestationException.class, () -> verify(att, pop(instanceEc, "ES256", "p9")));
    }

    @Test
    void anAttestationWithABlankAgentIdIsRejected() throws Exception {
        String att = attestation(attesterEc, "ES256", instanceEc, 600L, "   ", true);
        assertThrows(ClientAttestationException.class, () -> verify(att, pop(instanceEc, "ES256", "p10")));
    }

    @Test
    void subNamesTheAgentTypeAndAgentIdNamesTheInstance() throws Exception {
        ClientAttestationResult result = verify(conformantAttestation(), pop(instanceEc, "ES256", "p11"));
        assertEquals(CLIENT_ID, result.clientId(), "§6.1: sub is the registered client, not the instance");
        assertNotNull(result.agentId(), "§6.2: agent_id is always present");
        assertNotEquals(result.clientId(), result.agentId(),
                "§6: the instance identity is a separate claim from the agent type");
    }
}
