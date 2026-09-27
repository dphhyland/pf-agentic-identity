package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The access token, its confirmation and its act claim. */
class AccessTokenRefusalTest {
    private Fixture f;
    private DelegatedTokenValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        this.f = new Fixture();
        this.validator = this.f.builder(new InMemoryReplayStore()).build();
    }

    private DelegatedTokenValidator.RsException refused(DelegatedTokenValidator v, String token) throws Exception {
        String proof = this.f.proof(token);
        return assertThrows(DelegatedTokenValidator.RsException.class,
                () -> v.validate(Fixture.dpop(token, List.of(proof))));
    }

    private DelegatedTokenValidator.RsException refused(String token) throws Exception {
        return this.refused(this.validator, token);
    }

    // ---- typ -----------------------------------------------------------------------------------------------------

    /**
     * RFC 9068 §4 (no RFC9068 prefix is declared for @Requirement yet; F-0227): "The resource server MUST verify that
     * the "typ" header value is "at+jwt" or "application/at+jwt" and reject tokens carrying any other value."
     */
    @Test
    void aTokenOfAnotherTypeIsRefused() throws Exception {
        assertEquals("invalid_token", this.refused(this.f.token(this.f.claims(), j -> j.setHeader("typ", "JWT"))).error());
        DelegatedTokenValidator.RsException e = this.refused(
                this.f.token(this.f.claims(), j -> j.getHeaders().setObjectHeaderValue("typ", null)));
        assertTrue(e.getMessage().contains("typ is absent"), e.getMessage());
    }

    @Test
    void theApplicationFormOfTheTypeIsAccepted() throws Exception {
        String token = this.f.token(this.f.claims(), j -> j.setHeader("typ", "application/AT+JWT"));
        assertEquals(Fixture.HUMAN, this.validator.validate(Fixture.dpop(token, List.of(this.f.proof(token)))).subject());
    }

    /** PingFederate's token manager omits typ when its "Type Header Value" is blank: ABSENT is that deployment. */
    @Test
    void aDeploymentWithoutTypRequiresItAbsent() throws Exception {
        DelegatedTokenValidator v = this.f.builder(new InMemoryReplayStore()).accessTokenType(AccessTokenType.ABSENT).build();
        String untyped = this.f.token(this.f.claims(), j -> j.getHeaders().setObjectHeaderValue("typ", null));
        assertEquals(Fixture.HUMAN, v.validate(Fixture.dpop(untyped, List.of(this.f.proof(untyped)))).subject());
        assertEquals("invalid_token", this.refused(v, this.f.token()).error());
    }

    // ---- kid and keys --------------------------------------------------------------------------------------------

    /** The kid is matched exactly: no kid is no key, and there is no falling back to trying every key. */
    @Test
    void aTokenWithoutKidIsRefused() throws Exception {
        DelegatedTokenValidator.RsException e = this.refused(
                this.f.token(this.f.claims(), j -> j.getHeaders().setObjectHeaderValue("kid", null)));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("carries no kid"), e.getMessage());
    }

    @Test
    void aKidTwoPublishedKeysShareIsRefused() throws Exception {
        PublicJsonWebKey twin = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        twin.setKeyId("pf-1");
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(List.of(Fixture.publicOnly(this.f.asKey), Fixture.publicOnly(twin)))
                .replayStore(new InMemoryReplayStore()).build();
        assertTrue(this.refused(v, this.f.token()).getMessage().contains("more than one"));
    }

    @Test
    void aKeyThatIsNotForTheTokensAlgorithmIsRefused() throws Exception {
        PublicJsonWebKey rsa = RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("pf-1");
        DelegatedTokenValidator rsaKeyed = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(List.of(Fixture.publicOnly(rsa))).replayStore(new InMemoryReplayStore()).build();
        assertTrue(this.refused(rsaKeyed, this.f.token()).getMessage().contains("is not for ES256"));

        JsonWebKey labelled = Fixture.publicOnly(this.f.asKey);
        labelled.setAlgorithm("ES384");
        DelegatedTokenValidator mislabelled = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(List.of(labelled)).replayStore(new InMemoryReplayStore()).build();
        assertTrue(this.refused(mislabelled, this.f.token()).getMessage().contains("is not for ES256"));
    }

    @Test
    void anRsaSignedTokenVerifiesAgainstAnRsaKey() throws Exception {
        PublicJsonWebKey rsa = RsaJwkGenerator.generateJwk(2048);
        rsa.setKeyId("pf-rsa");
        rsa.setAlgorithm("PS256");
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(List.of(Fixture.publicOnly(rsa))).replayStore(new InMemoryReplayStore()).build();
        String token = this.f.token(this.f.claims(), j -> {
            j.setAlgorithmHeaderValue("PS256");
            j.setKeyIdHeaderValue("pf-rsa");
            j.setKey(rsa.getPrivateKey());
        });
        assertEquals(Fixture.HUMAN, v.validate(Fixture.dpop(token, List.of(this.f.proof(token)))).subject());
    }

    @Test
    void keysThatCannotBeReadAreA503() throws Exception {
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(kid -> {
                    throw new IOException("the JWKS is down");
                }).replayStore(new InMemoryReplayStore()).build();
        DelegatedTokenValidator.RsException e = this.refused(v, this.f.token());
        assertEquals(503, e.status());
        assertNull(e.error());
    }

    @Test
    void aSignatureThatCannotBeCheckedIsRefused() throws Exception {
        String token = this.f.token();
        String broken = token.substring(0, token.lastIndexOf('.') + 1) + "AAAA";
        assertEquals("invalid_token", this.refused(broken).error());
        assertEquals("invalid_token", this.refused("not.a.jws").error());
    }

    @Test
    void aPayloadThatIsNotClaimsIsRefused() throws Exception {
        org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
        jws.setPayload("[1,2,3]");
        jws.setKey(this.f.asKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue("pf-1");
        jws.setHeader("typ", "at+jwt");
        assertTrue(this.refused(jws.getCompactSerialization()).getMessage().contains("not valid JWT claims"));
    }

    // ---- time --------------------------------------------------------------------------------------------------

    @Test
    void aTokenNotValidYetIsRefused() throws Exception {
        JwtClaims claims = this.f.claims();
        claims.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("not valid yet"));
        claims.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 30));  // inside the skew
        String token = this.f.token(claims);
        assertEquals(Fixture.HUMAN, this.validator.validate(Fixture.dpop(token, List.of(this.f.proof(token)))).subject());
    }

    @Test
    void aTokenWithoutExpOrWithMalformedTimesIsRefused() throws Exception {
        JwtClaims noExp = this.f.claims();
        noExp.unsetClaim("exp");
        assertTrue(this.refused(this.f.token(noExp)).getMessage().contains("expired"));
        JwtClaims textExp = this.f.claims();
        textExp.setClaim("exp", "tomorrow");
        assertTrue(this.refused(this.f.token(textExp)).getMessage().contains("malformed"));
    }

    // ---- act -----------------------------------------------------------------------------------------------------

    /** RFC 8693 §4.1: "The "act" claim value is a JSON object, and members in the JSON object are claims that identify the actor." */
    @Test
    @Requirement("RFC8693 §4.1")
    void aMalformedActIsRefused() throws Exception {
        JwtClaims claims = this.f.claims();
        claims.setClaim("act", List.of("agent"));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("not an RFC 8693 actor chain"));
        claims.setClaim("act", Map.of("scope", "no actor named"));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("not an RFC 8693 actor chain"));
    }

    @Test
    @Requirement("RFC8693 §4.1")
    void aChainDeeperThanTheCapIsRefused() throws Exception {
        Map<String, Object> act = Map.of("sub", "leaf");
        for (int i = 0; i < ActChain.MAX_CHAIN_DEPTH; i++) {
            act = Map.of("sub", "hop-" + i, "act", act);
        }
        JwtClaims claims = this.f.claims();
        claims.setClaim("act", act);
        assertEquals("invalid_token", this.refused(this.f.token(claims)).error());
    }

    // ---- cnf -----------------------------------------------------------------------------------------------------

    @Test
    void aCnfWithNeitherMethodOrABadMemberIsRefused() throws Exception {
        JwtClaims claims = this.f.claims();
        claims.setClaim("cnf", Map.of("jwk", Map.of()));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("neither jkt nor x5t#S256"));
        claims.setClaim("cnf", Map.of("jkt", 42));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("jkt is not a string"));
        claims.setClaim("cnf", Map.of("jkt", ""));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("jkt is not a string"));
        claims.setClaim("cnf", "jkt");
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("not sender-constrained"));
    }

    // ---- mTLS ----------------------------------------------------------------------------------------------------

    private static X509Certificate certificate(byte[] der) throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(der);
        return cert;
    }

    private static String x5t(byte[] der) throws Exception {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(der));
    }

    private String certificateBound(String x5t) throws Exception {
        JwtClaims claims = this.f.claims();
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("x5t#S256", x5t);
        claims.setClaim("cnf", cnf);
        return this.f.token(claims);
    }

    private static DelegatedTokenValidator.Presentation bearer(String token, X509Certificate cert) {
        return new DelegatedTokenValidator.Presentation(DelegatedTokenValidator.Scheme.BEARER, token, null, "GET",
                Fixture.URL, cert);
    }

    @Test
    void aCertificateBoundTokenOverTheSameCertificateIsAccepted() throws Exception {
        byte[] der = {1, 2, 3, 4};
        DelegatedTokenValidator v = this.f.builder(new InMemoryReplayStore()).mtls(true).build();
        DelegatedTokenValidator.Result result = v.validate(bearer(this.certificateBound(x5t(der)), certificate(der)));
        assertEquals(Fixture.HUMAN, result.subject());
        assertNull(result.dpopJti());
    }

    /**
     * RFC 8705 §3 (no RFC8705 prefix is declared for @Requirement yet; F-0227): "The protected resource MUST obtain,
     * from its TLS implementation layer, the client certificate used for mutual TLS and MUST verify that the
     * certificate matches the certificate associated with the access token. If they do not match, the resource
     * access attempt MUST be rejected with an error, per [RFC6750], using an HTTP 401 status code and the
     * "invalid_token" error code."
     */
    @Test
    void aCertificateBoundTokenOverAnotherCertificateOrNoneIsRefused() throws Exception {
        DelegatedTokenValidator v = this.f.builder(new InMemoryReplayStore()).mtls(true).build();
        String token = this.certificateBound(x5t(new byte[] {1, 2, 3, 4}));
        DelegatedTokenValidator.RsException other = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> v.validate(bearer(token, certificate(new byte[] {9}))));
        assertEquals("invalid_token", other.error());
        assertEquals(401, other.status());
        assertTrue(assertThrows(DelegatedTokenValidator.RsException.class, () -> v.validate(bearer(token, null)))
                .getMessage().contains("no client certificate"));
        assertTrue(assertThrows(DelegatedTokenValidator.RsException.class,
                () -> v.validate(bearer(this.certificateBound("!!not base64url!!"), certificate(new byte[] {1}))))
                .getMessage().contains("not base64url"));
        X509Certificate unencodable = mock(X509Certificate.class);
        when(unencodable.getEncoded()).thenThrow(new CertificateEncodingException("no"));
        assertTrue(assertThrows(DelegatedTokenValidator.RsException.class, () -> v.validate(bearer(token, unencodable)))
                .getMessage().contains("could not be encoded"));
    }

    /** A token bound both ways needs both: the DPoP proof and the certificate. */
    @Test
    void aTokenBoundToBothNeedsBoth() throws Exception {
        byte[] der = {5, 6};
        JwtClaims claims = this.f.claims();
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("jkt", Fixture.thumbprint(this.f.clientKey));
        cnf.put("x5t#S256", x5t(der));
        claims.setClaim("cnf", cnf);
        String token = this.f.token(claims);
        String proof = this.f.proof(token);
        assertTrue(assertThrows(DelegatedTokenValidator.RsException.class,
                () -> this.validator.validate(Fixture.dpop(token, List.of(proof)))).getMessage().contains("no client certificate"));
        DelegatedTokenValidator.Result result = this.validator.validate(new DelegatedTokenValidator.Presentation(
                DelegatedTokenValidator.Scheme.DPOP, token, List.of(this.f.proof(token)), "GET", Fixture.URL, certificate(der)));
        assertEquals(Fixture.HUMAN, result.subject());
    }

    @Test
    void anUnboundTokenAsBearerIsRefused() throws Exception {
        DelegatedTokenValidator v = this.f.builder(new InMemoryReplayStore()).mtls(true).dpop(false).build();
        JwtClaims claims = this.f.claims();
        claims.setClaim("cnf", Map.of("jwk", Map.of()));
        assertThrows(DelegatedTokenValidator.RsException.class, () -> v.validate(bearer(this.f.token(claims), null)));
        JwtClaims otherMember = this.f.claims();
        Map<String, Object> cnf = new HashMap<>();
        cnf.put("x5t#S256", null);
        cnf.put("jkt", null);
        cnf.put("kid", "x");
        otherMember.setClaim("cnf", cnf);
        assertThrows(DelegatedTokenValidator.RsException.class, () -> v.validate(bearer(this.f.token(otherMember), null)));
    }

    @Test
    void aSchemeTheResourceDoesNotTakeCarriesNoError() throws Exception {
        DelegatedTokenValidator.RsException bearer = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> this.validator.validate(bearer(this.f.token(), null)));
        assertNull(bearer.error());
        assertEquals(401, bearer.status());
        DelegatedTokenValidator mtlsOnly = this.f.builder(new InMemoryReplayStore()).mtls(true).dpop(false).build();
        assertNull(this.refused(mtlsOnly, this.f.token()).error());
        assertTrue(mtlsOnly.acceptsMtls() && !mtlsOnly.acceptsDpop());
    }

    @Test
    void noTokenIsInvalidToken() throws Exception {
        assertEquals("invalid_token", assertThrows(DelegatedTokenValidator.RsException.class,
                () -> this.validator.validate(null, "proof", "GET", Fixture.URL)).error());
        assertEquals("invalid_token", assertThrows(DelegatedTokenValidator.RsException.class,
                () -> this.validator.validate(" ", null, "GET", Fixture.URL)).error());
    }

    // ---- what the caller must supply -------------------------------------------------------------------------------

    @Test
    void theMethodAndUriAreRequired() {
        assertThrows(IllegalArgumentException.class, () -> this.validator.validate("t", "p", null, Fixture.URL));
        assertThrows(IllegalArgumentException.class, () -> this.validator.validate("t", "p", " ", Fixture.URL));
        assertThrows(IllegalArgumentException.class, () -> this.validator.validate("t", "p", "GET", null));
        assertThrows(IllegalArgumentException.class, () -> this.validator.validate("t", "p", "GET", ""));
    }

    @Test
    void theBuilderRefusesWhatCannotBeSafe() throws Exception {
        DelegatedTokenValidator.Builder b = this.f.builder(new InMemoryReplayStore());
        assertThrows(IllegalArgumentException.class, () -> b.tokenAlgorithms(Set.of("HS256")));
        assertThrows(IllegalArgumentException.class, () -> b.proofAlgorithms(Set.of("none")));
        assertThrows(IllegalArgumentException.class, () -> b.proofAlgorithms(Set.of()));
        assertThrows(IllegalArgumentException.class, () -> b.clockSkew(Duration.ofMinutes(10)));
        assertThrows(IllegalArgumentException.class, () -> b.clockSkew(Duration.ofSeconds(-1)));
        assertThrows(IllegalArgumentException.class, () -> b.proofMaxAge(Duration.ofHours(2)));
        assertThrows(IllegalArgumentException.class, () -> b.proofMaxAge(Duration.ZERO));
        assertThrows(IllegalStateException.class, () -> b.dpop(false).build());
        assertThrows(IllegalStateException.class, () -> DelegatedTokenValidator.builder("i", "a")
                .replayStore(new InMemoryReplayStore()).build());
        DelegatedTokenValidator tuned = this.f.builder(new InMemoryReplayStore()).tokenAlgorithms(Set.of("ES256"))
                .proofAlgorithms(Set.of("ES256", "PS256")).clockSkew(Duration.ofSeconds(5))
                .proofMaxAge(Duration.ofSeconds(30)).build();
        assertEquals(Set.of("ES256", "PS256"), tuned.proofAlgorithms());
        String token = this.f.token();
        assertEquals(Fixture.HUMAN, tuned.validate(Fixture.dpop(token, List.of(this.f.proof(token)))).subject());
    }
}
