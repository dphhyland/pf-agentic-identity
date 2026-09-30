package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * What binds a presentation to the server it is presented to: the Client Attestation PoP's {@code aud}, and in DPoP
 * combined mode the proof's {@code htu}. The attestation itself names no audience (ABCA-10 §4), so these are the
 * only thing that stops a PoP or proof minted for one server authenticating at another.
 *
 * <p>ABCA-10 §5.1: "aud: REQUIRED. The aud (audience) claim MUST specify a value that identifies the intended
 * audience of the JWT. When the JWT is presented to an Authorization Server, the [RFC8414] issuer identifier URL
 * of the Authorization Server MUST be used. [...] A Client Attestation PoP JWT is intended for a single audience,
 * Clients MUST generate JWTs for each target." §7.2, item 7: "The audience claim in the Client Attestation PoP JWT
 * identifies the receiving server: when validated by an Authorization Server, it MUST be the issuer identifier URL
 * of the Authorization Server as described in [RFC8414]".
 *
 * <p>RFC 9449 §4.3, item 9: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was
 * received, ignoring any query and fragment parts." How the comparison normalises is {@link HtuComparisonTest}'s.
 */
class ReceivingServerBindingTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String CLIENT_ID = "https://rp.example.com";
    private static final String ISSUER = "https://as.example.com";
    private static final String TOKEN_ENDPOINT = ISSUER + "/as/token.oauth2";
    /** Another server the client talks to, whose token endpoint has PingFederate's path. */
    private static final String OTHER_TOKEN_ENDPOINT = "https://other-bank.example/as/token.oauth2";

    private PublicJsonWebKey attesterKey;
    private PublicJsonWebKey instanceKey;
    private AttesterKeyResolver resolver;

    @BeforeEach
    void setUp() throws Exception {
        attesterKey = TestJwts.ec("attester-1");
        instanceKey = TestJwts.ec("instance-1");
        resolver = (iss, chain) -> List.of(JsonWebKey.Factory.newJwk(TestJwts.publicParams(attesterKey)));
    }

    private ClientAttestationVerifier verifier(ClientAttestationConfig config) {
        return new ClientAttestationVerifier(resolver, config, new InMemoryAttestationReplayCache(),
                new InMemoryAttestationChallengeService());
    }

    /** The configuration the token-endpoint filter builds: the issuer as the audience, the token endpoint as htu. */
    private ClientAttestationVerifier asVerifier() {
        return verifier(ClientAttestationConfig.builder().expectedAudience(ISSUER).expectedHtu(TOKEN_ENDPOINT).build());
    }

    private String attestation() throws Exception {
        JwtClaims att = new JwtClaims();
        att.setIssuer(ATTESTER);
        att.setSubject(CLIENT_ID);
        att.setIssuedAtToNow();
        att.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        att.setClaim("cnf", Map.of("jwk", TestJwts.publicParams(instanceKey)));
        return TestJwts.sign(attesterKey, "ES256", "oauth-client-attestation+jwt", att);
    }

    /** A PoP whose {@code aud} is {@code audience} as given: a String, a List, or absent when null. */
    private String pop(Object audience) throws Exception {
        return pop(audience, true);
    }

    private String pop(Object audience, boolean withIssuer) throws Exception {
        JwtClaims pop = new JwtClaims();
        if (withIssuer) {
            pop.setIssuer(CLIENT_ID);
        }
        if (audience != null) {
            pop.setClaim("aud", audience);
        }
        pop.setJwtId(UUID.randomUUID().toString());
        pop.setIssuedAtToNow();
        return TestJwts.sign(instanceKey, "ES256", "oauth-client-attestation-pop+jwt", pop);
    }

    private String dpop(String htu) throws Exception {
        JwtClaims d = new JwtClaims();
        d.setClaim("htm", "POST");
        d.setClaim("htu", htu);
        d.setJwtId(UUID.randomUUID().toString());
        d.setIssuedAtToNow();
        return TestJwts.signWithJwkHeader(instanceKey, "ES256", "dpop+jwt", d);
    }

    private ClientAttestationException refusedPop(Object audience) {
        return assertThrows(ClientAttestationException.class,
                () -> asVerifier().verify(attestation(), pop(audience), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    // ---- the PoP audience -------------------------------------------------------------------------------------

    @Test
    @Requirement({"ABCA-10 §5.1", "ABCA-10 §7.2(7)"})
    void theIssuerAsAStringIsTheAudience() throws Exception {
        ClientAttestationResult result = asVerifier().verify(attestation(), pop(ISSUER), null, "POST", TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
        assertEquals(ClientAttestationResult.Mode.POP_JWT, result.mode());
    }

    /**
     * The draft asks for "a value" and never says "as a string", and RFC 7519 §4.1.3 writes one audience either way:
     * "In the general case, the "aud" value is an array of case-sensitive strings, each containing a StringOrURI
     * value. In the special case when the JWT has one audience, the "aud" value MAY be a single case-sensitive string
     * containing a StringOrURI value." So the issuer as the one member of an array is the same single audience.
     */
    @Test
    @Requirement({"ABCA-10 §5.1", "RFC7519 §4.1.3"})
    void theIssuerAsTheOneMemberOfAnArrayIsTheSameAudience() throws Exception {
        ClientAttestationResult result = asVerifier().verify(attestation(), pop(List.of(ISSUER)), null, "POST",
                TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
    }

    /**
     * What an OpenID Connect client does with a {@code private_key_jwt} assertion (Core §9 addresses it to the token
     * endpoint), and what this server accepted until 0.4.0. It is not the issuer identifier §7.2 requires.
     */
    @Test
    @Requirement("ABCA-10 §7.2(7)")
    void theTokenEndpointIsNotTheIssuer() {
        ClientAttestationException e = refusedPop(TOKEN_ENDPOINT);

        assertEquals(ClientAttestationException.INVALID_CLIENT, e.error());
        assertTrue(e.getMessage().contains("'aud'"), e.getMessage());
    }

    @Test
    @Requirement("ABCA-10 §7.2(7)")
    void anotherServersIssuerOrTokenEndpointIsRefused() {
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop("https://other-bank.example").error());
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop(OTHER_TOKEN_ENDPOINT).error());
    }

    /**
     * jose4j's audience check passes an array that merely contains an expected value, so these got through it: a PoP
     * addressed to this server and another at once. "A Client Attestation PoP JWT is intended for a single audience".
     */
    @Test
    @Requirement("ABCA-10 §5.1")
    void anArrayNamingASecondAudienceIsRefusedWhicheverComesFirst() {
        assertEquals(ClientAttestationException.INVALID_CLIENT,
                refusedPop(List.of(ISSUER, "https://other-bank.example")).error());
        assertEquals(ClientAttestationException.INVALID_CLIENT,
                refusedPop(List.of("https://other-bank.example", ISSUER)).error());
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop(List.of(ISSUER, TOKEN_ENDPOINT)).error());
    }

    @Test
    @Requirement("ABCA-10 §5.1")
    void theIssuerTwiceIsNotASingleAudience() {
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop(List.of(ISSUER, ISSUER)).error());
    }

    @Test
    @Requirement("ABCA-10 §5.1")
    void aPopWithNoAudienceOrAnEmptyOneIsRefused() {
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop(null).error());
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop(List.of()).error());
    }

    /**
     * RFC 7519 §2: "StringOrURI values are compared as case-sensitive strings with no transformations or
     * canonicalizations applied." A trailing slash or a change of case names another audience.
     */
    @Test
    @Requirement("RFC7519 §2")
    void theIssuerIsComparedExactly() {
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop(ISSUER + "/").error());
        assertEquals(ClientAttestationException.INVALID_CLIENT, refusedPop("https://AS.example.com").error());
    }

    /**
     * The PoP's claims are {@code aud}, {@code jti}, {@code iat} and an optional {@code challenge} (§5.1); the
     * draft's own example carries no {@code iss}. One that has none is not refused for it.
     */
    @Test
    @Requirement("ABCA-10 §5.1")
    void aPopWithoutAnIssuerIsAccepted() throws Exception {
        ClientAttestationResult result = asVerifier().verify(attestation(), pop(ISSUER, false), null, "POST",
                TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(CLIENT_ID, result.clientId());
    }

    /**
     * The rule holds on its own, not only behind jose4j's audience check (which already refuses a single other
     * audience before this runs), so a change to how the PoP is parsed cannot quietly drop it.
     */
    @Test
    @Requirement("ABCA-10 §7.2(7)")
    void theSoleAudienceRuleStandsOnItsOwn() throws Exception {
        JwtClaims other = new JwtClaims();
        other.setAudience("https://other-bank.example");
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> ClientAttestationVerifier.requireSoleAudience(other, ISSUER));
        assertEquals(ClientAttestationVerifier.WRONG_POP_AUDIENCE, e.getMessage());

        JwtClaims issuer = new JwtClaims();
        issuer.setAudience(ISSUER);
        ClientAttestationVerifier.requireSoleAudience(issuer, ISSUER);
    }

    @Test
    void aBlankExpectedAudienceIsNoAudienceAndPopModeIsRefusedAsAMisconfiguration() {
        ClientAttestationVerifier blank = verifier(ClientAttestationConfig.builder().expectedAudience("  ").build());

        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> blank.verify(attestation(), pop(ISSUER), null, "POST", TOKEN_ENDPOINT, CLIENT_ID));
        assertTrue(e.getMessage().contains("no expected PoP audience"), e.getMessage());
    }

    // ---- the DPoP htu -----------------------------------------------------------------------------------------

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void aCombinedModeProofNamingTheConfiguredEndpointAuthenticates() throws Exception {
        ClientAttestationResult result = asVerifier().verify(attestation(), null, dpop(TOKEN_ENDPOINT), "POST",
                TOKEN_ENDPOINT, CLIENT_ID);

        assertEquals(ClientAttestationResult.Mode.DPOP, result.mode());
    }

    /**
     * The configured URL decides, whatever the caller passes as the request's URI - which is where a request URL
     * rebuilt from a forged {@code Host} header would arrive.
     */
    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theConfiguredEndpointWinsOverTheRequestUriArgument() throws Exception {
        ClientAttestationException e = assertThrows(ClientAttestationException.class,
                () -> asVerifier().verify(attestation(), null, dpop(OTHER_TOKEN_ENDPOINT), "POST",
                        OTHER_TOKEN_ENDPOINT, CLIENT_ID));
        assertEquals(ClientAttestationException.INVALID_CLIENT, e.error());
        assertTrue(e.getMessage().contains("htu"), e.getMessage());

        ClientAttestationResult result = asVerifier().verify(attestation(), null, dpop(TOKEN_ENDPOINT), "POST",
                OTHER_TOKEN_ENDPOINT, CLIENT_ID);
        assertEquals(ClientAttestationResult.Mode.DPOP, result.mode());
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void withNoConfiguredEndpointTheRequestUriArgumentIsTheEndpoint() throws Exception {
        ClientAttestationVerifier v = verifier(ClientAttestationConfig.builder().expectedAudience(ISSUER).build());

        assertEquals(ClientAttestationResult.Mode.DPOP,
                v.verify(attestation(), null, dpop(TOKEN_ENDPOINT), "POST", TOKEN_ENDPOINT, CLIENT_ID).mode());
        assertThrows(ClientAttestationException.class,
                () -> v.verify(attestation(), null, dpop(OTHER_TOKEN_ENDPOINT), "POST", TOKEN_ENDPOINT, CLIENT_ID));
    }

    /**
     * {@code DpopProofValidator} skips the {@code htu} comparison when it is given no URL. Through the verifier that
     * would let a proof minted for any server authenticate here, so no URL at all is a misconfiguration.
     */
    @Test
    void withNoEndpointAnywhereCombinedModeIsRefusedAsAMisconfiguration() {
        ClientAttestationVerifier v = verifier(ClientAttestationConfig.builder().expectedAudience(ISSUER).build());

        ClientAttestationException none = assertThrows(ClientAttestationException.class,
                () -> v.verify(attestation(), null, dpop(TOKEN_ENDPOINT), "POST", null, CLIENT_ID));
        assertTrue(none.getMessage().contains("no expected DPoP htu"), none.getMessage());
        ClientAttestationException blank = assertThrows(ClientAttestationException.class,
                () -> v.verify(attestation(), null, dpop(TOKEN_ENDPOINT), "POST", " ", CLIENT_ID));
        assertTrue(blank.getMessage().contains("no expected DPoP htu"), blank.getMessage());
    }

    /** The request's method decides {@code htm}; with none, the configured method (POST) does. */
    @Test
    @Requirement("RFC9449 §4.3(8)")
    void theHtmIsTheRequestsMethodOrTheConfiguredOne() throws Exception {
        assertEquals(ClientAttestationResult.Mode.DPOP,
                asVerifier().verify(attestation(), null, dpop(TOKEN_ENDPOINT), null, TOKEN_ENDPOINT, CLIENT_ID).mode());
        assertEquals(ClientAttestationResult.Mode.DPOP,
                asVerifier().verify(attestation(), null, dpop(TOKEN_ENDPOINT), " ", TOKEN_ENDPOINT, CLIENT_ID).mode());
        assertThrows(ClientAttestationException.class,
                () -> asVerifier().verify(attestation(), null, dpop(TOKEN_ENDPOINT), "PUT", TOKEN_ENDPOINT, CLIENT_ID));
    }
}
