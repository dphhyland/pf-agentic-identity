package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
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
        ClientAttestationConfig config = ClientAttestationConfig.builder()
                .addAcceptedAudience(OP_ISSUER)
                .addAcceptedAudience(TOKEN_ENDPOINT)
                .expectedHtu(TOKEN_ENDPOINT)
                .challengeRequired(challengeRequired)
                .build();
        return new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(), challengeService);
    }

    private String attestation(Map<String, Object> cnfJwk, long expSecondsFromNow) throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expSecondsFromNow));
        att.setClaim("cnf", Map.of("jwk", cnfJwk));
        return TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);
    }

    private String validAttestation() throws Exception {
        return attestation(TestJwts.publicParams(instanceKey), 600L);
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
}
