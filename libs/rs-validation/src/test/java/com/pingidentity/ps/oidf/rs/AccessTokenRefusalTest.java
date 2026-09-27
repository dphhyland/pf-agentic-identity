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

    /**
     * Local policy, not an RFC requirement: RFC 7515 §4.1.4 says of "kid": "Use of this Header Parameter is OPTIONAL."
     * This validator matches it exactly - no kid names no key, and there is no falling back to trying every key.
     */
    @Test
    void aTokenWithoutKidIsRefused() throws Exception {
        DelegatedTokenValidator.RsException e = this.refused(
                this.f.token(this.f.claims(), j -> j.getHeaders().setObjectHeaderValue("kid", null)));
        assertEquals("invalid_token", e.error());
        assertTrue(e.getMessage().contains("carries no kid"), e.getMessage());
    }

    /**
     * An empty kid is refused as local policy, as a missing one is (RFC 7515 §4.1.4 makes "kid" optional; this
     * validator requires it). A missing alg:
     *
     * <p>RFC 7515 §4.1.1, of "alg": "This Header Parameter MUST be present and MUST be understood and processed by
     * implementations."
     */
    @Test
    @Requirement("RFC7515 §4.1.1")
    void anEmptyKidOrAMissingAlgIsRefused() throws Exception {
        assertTrue(this.refused(this.f.token(this.f.claims(), j -> j.setKeyIdHeaderValue(""))).getMessage()
                .contains("carries no kid"));
        java.util.Base64.Encoder b64 = java.util.Base64.getUrlEncoder().withoutPadding();
        String noAlg = b64.encodeToString("{\"typ\":\"at+jwt\",\"kid\":\"pf-1\"}".getBytes(java.nio.charset.StandardCharsets.UTF_8))
                + "." + b64.encodeToString(this.f.claims().toJson().getBytes(java.nio.charset.StandardCharsets.UTF_8)) + ".AAAA";
        assertTrue(this.refused(noAlg).getMessage().contains("algorithm null is not permitted"));
    }

    /**
     * A key of the right type on the wrong curve: jose4j refuses to verify with it, and that is a refusal too.
     *
     * <p>RFC 7515 §4.1.1: "The JWS Signature value is not valid if the "alg" value does not represent a supported
     * algorithm or if there is not a key for use with that algorithm associated with the party that digitally signed or
     * MACed the content."
     */
    @Test
    @Requirement("RFC7515 §4.1.1")
    void aKeyThatCannotVerifyTheAlgorithmIsRefused() throws Exception {
        PublicJsonWebKey p384 = EcJwkGenerator.generateJwk(EllipticCurves.P384);
        p384.setKeyId("pf-1");
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(List.of(Fixture.publicOnly(p384))).replayStore(new InMemoryReplayStore()).build();
        assertTrue(this.refused(v, this.f.token()).getMessage().contains("could not be verified"));
    }

    /**
     * RFC 7519 §4.1.3: "Each principal intended to process the JWT MUST identify itself with a value in the audience
     * claim."
     *
     * <p>RFC 9068 §4: "The resource server MUST validate that the "aud" claim contains a resource indicator value
     * corresponding to an identifier the resource server expects for itself. The JWT access token MUST be rejected if
     * "aud" does not contain a resource indicator of the current resource server as a valid audience."
     */
    @Test
    @Requirement("RFC7519 §4.1.3")
    void aTokenWithoutAudienceIsRefused() throws Exception {
        JwtClaims claims = this.f.claims();
        claims.unsetClaim("aud");
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("audience"));
    }

    /**
     * Local policy, not an RFC requirement: a kid that names two published keys names no one key, so the token is
     * refused rather than tried against both.
     */
    @Test
    void aKidTwoPublishedKeysShareIsRefused() throws Exception {
        PublicJsonWebKey twin = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        twin.setKeyId("pf-1");
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .keys(List.of(Fixture.publicOnly(this.f.asKey), Fixture.publicOnly(twin)))
                .replayStore(new InMemoryReplayStore()).build();
        assertTrue(this.refused(v, this.f.token()).getMessage().contains("more than one"));
    }

    /**
     * RFC 7515 §4.1.1: "The JWS Signature value is not valid if the "alg" value does not represent a supported
     * algorithm or if there is not a key for use with that algorithm associated with the party that digitally signed or
     * MACed the content."
     */
    @Test
    @Requirement("RFC7515 §4.1.1")
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

    /**
     * Local policy: when the keys cannot be read the answer is not known, so the refusal is a 503 without an RFC 6750
     * error, not an invalid_token.
     */
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

    /**
     * RFC 9068 §4: "The resource server MUST validate the signature of all incoming JWT access tokens according to
     * [RFC7515] using the algorithm specified in the JWT "alg" Header Parameter."
     *
     * <p>RFC 7515 §5.2: "If any of the listed steps fails, then the signature or MAC cannot be validated."
     *
     * <p>RFC 7519 §7.2: "If any of the listed steps fail, then the JWT MUST be rejected -- that is, treated by the
     * application as an invalid input."
     */
    @Test
    @Requirement({"RFC7515 §5.2", "RFC7519 §7.2"})
    void aSignatureThatCannotBeCheckedIsRefused() throws Exception {
        String token = this.f.token();
        String broken = token.substring(0, token.lastIndexOf('.') + 1) + "AAAA";
        assertEquals("invalid_token", this.refused(broken).error());
        assertEquals("invalid_token", this.refused("not.a.jws").error());
    }

    /**
     * RFC 7519 §7.2, step 10: "Verify that the resulting octet sequence is a UTF-8-encoded representation of a
     * completely valid JSON object conforming to RFC 7159 [RFC7159]; let the JWT Claims Set be this JSON object." And:
     * "If any of the listed steps fail, then the JWT MUST be rejected".
     */
    @Test
    @Requirement("RFC7519 §7.2")
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

    /**
     * RFC 7519 §4.1.5: "The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for
     * processing." Inside the clock skew it passes: "Implementers MAY provide for some small leeway, usually no more
     * than a few minutes, to account for clock skew."
     */
    @Test
    @Requirement("RFC7519 §4.1.5")
    void aTokenNotValidYetIsRefused() throws Exception {
        JwtClaims claims = this.f.claims();
        claims.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 600));
        assertTrue(this.refused(this.f.token(claims)).getMessage().contains("not valid yet"));
        claims.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 30));  // inside the skew
        String token = this.f.token(claims);
        assertEquals(Fixture.HUMAN, this.validator.validate(Fixture.dpop(token, List.of(this.f.proof(token)))).subject());
    }

    /**
     * RFC 9068 §4: "The current time MUST be before the time represented by the "exp" claim."
     *
     * <p>RFC 7519 §4.1.4: "Its value MUST be a number containing a NumericDate value."
     */
    @Test
    @Requirement("RFC7519 §4.1.4")
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

    /**
     * RFC 8693 §4.1: "The "act" claim value is a JSON object, and members in the JSON object are claims that identify
     * the actor."
     *
     * <p>The depth cap itself is local policy: RFC 8693 sets no limit, and ActChain.MAX_CHAIN_DEPTH bounds the work a
     * hostile token can cause.
     */
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

    /**
     * RFC 9449 §6.1: "The value of the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK
     * SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access token is
     * bound."
     *
     * <p>A cnf that is not an object, or names neither jkt nor x5t#S256, is refused as local policy: this resource has
     * no bearer mode, so a token it cannot tie to a sender is not accepted.
     */
    @Test
    @Requirement("RFC9449 §6.1")
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

    /**
     * Local policy: this resource has no bearer mode, so under the Bearer scheme only a certificate-bound token (RFC
     * 8705 §3) is accepted, and a cnf with no member it checks is refused.
     */
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

    /**
     * RFC 6750 §3.1: "If the request lacks any authentication information (e.g., the client was unaware that
     * authentication is necessary or attempted using an unsupported authentication method), the resource server SHOULD
     * NOT include an error code or other error information."
     */
    @Test
    @Requirement("RFC6750 §3.1")
    void aSchemeTheResourceDoesNotTakeCarriesNoError() throws Exception {
        DelegatedTokenValidator.RsException bearer = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> this.validator.validate(bearer(this.f.token(), null)));
        assertNull(bearer.error());
        assertEquals(401, bearer.status());
        DelegatedTokenValidator mtlsOnly = this.f.builder(new InMemoryReplayStore()).mtls(true).dpop(false).build();
        assertNull(this.refused(mtlsOnly, this.f.token()).error());
        assertTrue(mtlsOnly.acceptsMtls() && !mtlsOnly.acceptsDpop());
    }

    /**
     * RFC 6750 §3.1, invalid_token: "The access token provided is expired, revoked, malformed, or invalid for other
     * reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code."
     *
     * <p>The filter answers a request with no Authorization header before it gets here, without an error
     * (ResourceServerFilterTest.noCredentialsIsAChallengeWithoutAnError); a blank token that reaches the validator is
     * malformed.
     */
    @Test
    @Requirement("RFC6750 §3.1")
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
