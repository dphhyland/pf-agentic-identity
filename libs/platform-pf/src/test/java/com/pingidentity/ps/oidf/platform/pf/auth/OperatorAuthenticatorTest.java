package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.rs.AccessTokenType;
import com.pingidentity.ps.oidf.rs.DelegatedTokenValidator;
import com.pingidentity.ps.oidf.rs.InMemoryReplayStore;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The authenticator in jwt mode against a local JWKS: the happy path, and every refusal with its status, its
 * challenges and its event.
 */
class OperatorAuthenticatorTest {
    private final OperatorFixture f;

    OperatorAuthenticatorTest() throws Exception {
        this.f = new OperatorFixture();
    }

    @AfterEach
    void close() {
        this.f.close();
    }

    private OperatorAuthenticator.Refused refused(OperatorAuthenticator a, OperatorFixture.Request r,
                                                  OperatorRoute route) {
        return assertInstanceOf(OperatorAuthenticator.Refused.class, a.authenticate(r.mock(), route));
    }

    private static String challenge(OperatorAuthenticator.Refused r, String scheme) {
        return r.challenges().stream().filter(c -> c.startsWith(scheme + " ")).findFirst().orElse(null);
    }

    // ---- the happy path ---------------------------------------------------------------------------------------------

    /**
     * RFC 9449 §7.1: the resource server checks the proof with the token - its key's thumbprint against
     * {@code cnf.jkt}, its {@code ath} against this token, {@code htm} and {@code htu} against this request.
     */
    @Test
    @Requirement("RFC9449 §7.1")
    void aDpopBoundTokenWithTheRoutesScopeAndItsProofIsLetThroughAsItsSubject() throws Exception {
        String token = this.f.token("oidf.admin.read oidf.admin.entities");
        OperatorFixture.Request r = this.f.dpop(token, "POST");
        r.actorHeader = "Alice\nfrom ops";
        OperatorAuthenticator.Decision d = this.f.jwt().authenticate(r.mock(), OperatorFixture.UPDATE);
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class, d).operator();
        assertEquals(OperatorFixture.CLIENT, operator.actor());
        assertEquals(OperatorFixture.CLIENT, operator.clientId());
        assertEquals(List.of("oidf.admin.read", "oidf.admin.entities"), operator.scopes());
        assertEquals("dpop", operator.binding());
        assertEquals("Alice_from ops", operator.claimedLabel());
        assertSame(operator, r.attributes.get(OperatorAuthenticator.OPERATOR_ATTRIBUTE));
        Event e = this.f.last();
        assertEquals(OperatorAuthenticator.AUTHORISED, e.code());
        assertTrue(e.audit());
        assertEquals(OperatorFixture.CLIENT, e.subject());
        assertEquals("hosted-entities.update", e.fields().get("route"));
        assertEquals("oidf.admin.entities", e.fields().get("scope"));
        assertEquals(OperatorFixture.CLIENT, e.fields().get("actor"));
        assertEquals(OperatorFixture.ADDRESS, e.fields().get("client_address"));
        assertEquals("dpop", e.fields().get("binding"));
        assertFalse(e.fields().get("claimed_label").contains("\n"), "the label is log-safe");
    }

    /** The actor is the token's subject, never the header: a header naming someone else changes nothing. */
    @Test
    void theActorIsTheTokensSubjectNeverTheHeader() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorFixture.Request r = this.f.dpop(token, "GET");
        r.actorHeader = "x".repeat(300);
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.f.jwt().authenticate(r.mock(), OperatorFixture.READ)).operator();
        assertEquals(OperatorFixture.CLIENT, operator.actor());
        assertEquals(OperatorAuthenticator.CLAIMED_LABEL_LIMIT, operator.claimedLabel().length());
    }

    @Test
    void aTokenWithoutASubjectActsAsItsClientAndOneWithNeitherIsRefused() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.unsetClaim("sub");
        String token = this.f.token(claims);
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.f.jwt().authenticate(this.f.dpop(token, "GET").mock(), OperatorFixture.READ)).operator();
        assertEquals(OperatorFixture.CLIENT, operator.actor());

        claims.unsetClaim("client_id");
        String nobody = this.f.token(claims);
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), this.f.dpop(nobody, "GET"), OperatorFixture.READ);
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
        claims.setClaim("client_id", 42);
        String numeric = this.f.token(claims);
        assertEquals(401, this.refused(this.f.jwt(), this.f.dpop(numeric, "GET"), OperatorFixture.READ).status());
    }

    @Test
    void theClientIdIsNullWhenTheTokenCarriesNone() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.unsetClaim("client_id");
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class, this.f.jwt()
                .authenticate(this.f.dpop(this.f.token(claims), "GET").mock(), OperatorFixture.READ)).operator();
        assertNull(operator.clientId());
        assertNull(operator.claimedLabel());
        assertEquals(OperatorFixture.CLIENT, OperatorAuthenticator.actorOf(new DelegatedTokenValidator.Result(
                "", null, null, List.of(), Map.of("client_id", OperatorFixture.CLIENT), null,
                DelegatedTokenValidator.Binding.DPOP)));
        assertNull(OperatorAuthenticator.actorOf(new DelegatedTokenValidator.Result(null, null, null, List.of(),
                Map.of("client_id", ""), null, DelegatedTokenValidator.Binding.DPOP)));
    }

    // ---- the token's claims -----------------------------------------------------------------------------------------

    /** RFC 6750 §3.1 invalid_token: "The access token provided is expired, revoked, malformed, or invalid". */
    @Test
    @Requirement("RFC6750 §3.1")
    void aTokenFromAnotherIssuerIsInvalid() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.setIssuer("https://other.example.com");
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), this.f.dpop(this.f.token(claims), "GET"),
                OperatorFixture.READ);
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
        assertTrue(challenge(r, "DPoP").contains("error=\"invalid_token\""), r.challenges().toString());
        assertFalse(challenge(r, "Bearer").contains("error="), "the error goes in the scheme the client used");
        Event e = this.f.last();
        assertEquals(OperatorAuthenticator.REFUSED, e.code());
        assertEquals(Event.Outcome.FAILURE, e.outcome());
        assertEquals("invalid_token", e.reason());
        assertEquals("401", e.fields().get("status"));
        assertEquals("hosted-entities.list", e.fields().get("route"));
        assertNull(e.fields().get("actor"), "no actor is recorded for a token that was not believed");
    }

    @Test
    @Requirement("RFC6750 §3.1")
    void aTokenForAnotherAudienceIsInvalid() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.setAudience("https://another-resource.example.com");
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), this.f.dpop(this.f.token(claims), "GET"),
                OperatorFixture.READ);
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
    }

    @Test
    @Requirement("RFC6750 §3.1")
    void anExpiredTokenAndOneNotYetValidAreInvalid() throws Exception {
        JwtClaims expired = this.f.claims("oidf.admin.read");
        expired.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() - 3600));
        assertEquals(401, this.refused(this.f.jwt(), this.f.dpop(this.f.token(expired), "GET"),
                OperatorFixture.READ).status());
        JwtClaims early = this.f.claims("oidf.admin.read");
        early.setNotBefore(NumericDate.fromSeconds(NumericDate.now().getValue() + 3600));
        assertEquals(401, this.refused(this.f.jwt(), this.f.dpop(this.f.token(early), "GET"),
                OperatorFixture.READ).status());
    }

    /**
     * RFC 6750 §3.1 insufficient_scope: "The request requires higher privileges than provided by the access token.
     * The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include the "scope"
     * attribute with the scope necessary to access the protected resource."
     */
    @Test
    @Requirement("RFC6750 §3.1")
    void aTokenWithoutTheRoutesScopeIsForbiddenAndTheChallengeNamesTheScope() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), this.f.dpop(token, "POST"), OperatorFixture.UPDATE);
        assertEquals(403, r.status());
        assertEquals("insufficient_scope", r.reason());
        assertTrue(challenge(r, "DPoP").contains("error=\"insufficient_scope\""));
        assertTrue(challenge(r, "DPoP").contains("scope=\"oidf.admin.entities\""));
        Event e = this.f.last();
        assertEquals(OperatorFixture.CLIENT, e.fields().get("actor"), "a refused scope names who asked");
        assertEquals("403", e.fields().get("status"));
    }

    @Test
    void aTokenNotSignedByPingFederateOrOfAnotherTypeIsInvalid() throws Exception {
        PublicJsonWebKey other = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        other.setKeyId(this.f.asKey.getKeyId());
        org.jose4j.jws.JsonWebSignature jws = new org.jose4j.jws.JsonWebSignature();
        jws.setPayload(this.f.claims("oidf.admin.read").toJson());
        jws.setKey(other.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(other.getKeyId());
        jws.setHeader("typ", "at+jwt");
        String forged = jws.getCompactSerialization();
        assertEquals(401, this.refused(this.f.jwt(), this.f.dpop(forged, "GET"), OperatorFixture.READ).status());
        // A manager configured with no typ header: the default at+jwt refuses its tokens, none accepts them.
        jws.setKey(this.f.asKey.getPrivateKey());
        jws.getHeaders().setObjectHeaderValue("typ", null);
        String untyped = jws.getCompactSerialization();
        assertEquals(401, this.refused(this.f.jwt(), this.f.dpop(untyped, "GET"), OperatorFixture.READ).status());
        Map<String, String> env = this.f.jwtSettings();
        env.put(OperatorAuthConfig.ACCESS_TOKEN_TYP, "none");
        assertInstanceOf(OperatorAuthenticator.Authorised.class, this.f.authenticator(env, DeploymentProfile.PRODUCTION)
                .authenticate(this.f.dpop(untyped, "GET").mock(), OperatorFixture.READ));
    }

    @Test
    void theTypSettingMapsOntoRsValidationsTypes() {
        assertSame(AccessTokenType.RFC9068, OperatorAuthenticator.accessTokenType(null));
        assertSame(AccessTokenType.RFC9068, OperatorAuthenticator.accessTokenType(" "));
        assertSame(AccessTokenType.RFC9068, OperatorAuthenticator.accessTokenType("AT+JWT"));
        assertSame(AccessTokenType.ABSENT, OperatorAuthenticator.accessTokenType("None"));
        assertTrue(OperatorAuthenticator.accessTokenType("JWT").accepts("jwt"));
        assertFalse(OperatorAuthenticator.accessTokenType("JWT").accepts("at+jwt"));
    }

    // ---- the binding ------------------------------------------------------------------------------------------------

    /**
     * RFC 9449 §7.2: a protected resource that supports only DPoP "MUST reject" an unbound bearer token and answers
     * with the DPoP challenge; production accepts nothing bound to nothing.
     */
    @Test
    @Requirement("RFC9449 §7.1")
    void anUnboundTokenIsRefusedInProductionWithTheDpopChallenge() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.unsetClaim("cnf");
        String token = this.f.token(claims);
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), OperatorFixture.bearer(token), OperatorFixture.READ);
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
        assertTrue(challenge(r, "DPoP").startsWith("DPoP algs=\"ES256 PS256 RS256\""), r.challenges().toString());
        assertTrue(challenge(r, "Bearer").contains("error=\"invalid_token\""), "the client used Bearer");
    }

    @Test
    void anUnboundTokenIsLetThroughInDevelopmentAsBoundToNothing() throws Exception {
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.unsetClaim("cnf");
        String token = this.f.token(claims);
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.f.authenticator(this.f.jwtSettings(), DeploymentProfile.DEVELOPMENT)
                        .authenticate(OperatorFixture.bearer(token).mock(), OperatorFixture.READ)).operator();
        assertEquals("none", operator.binding());
        assertEquals("none", this.f.last().fields().get("binding"));
    }

    /** RFC 9449 §4.3: "The htm claim matches the HTTP method of the current request." */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofForAnotherMethodIsRefused() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorFixture.Request r = this.f.dpop(token, "GET");
        r.method = "DELETE";
        OperatorAuthenticator.Refused refused = this.refused(this.f.jwt(), r, OperatorFixture.READ);
        assertEquals(401, refused.status());
        assertEquals("invalid_dpop_proof", refused.reason());
        // RFC 9110 §9.1: "The method token is case-sensitive" - a proof for "get" is not one for GET.
        OperatorFixture.Request lower = new OperatorFixture.Request();
        lower.authorization.add("DPoP " + token);
        lower.dpop.add(this.f.proof(token, "get"));
        assertEquals("invalid_dpop_proof", this.refused(this.f.jwt(), lower, OperatorFixture.READ).reason());
    }

    /**
     * RFC 9449 §4.3: "The htu claim matches the HTTP URI value for the HTTP request in which the JWT was received" -
     * the configured base URL and the request's path, never the Host header.
     */
    @Test
    @Requirement("RFC9449 §4.3")
    void aProofForAnotherUrlIsRefusedAndTheHostHeaderCannotMakeOneMatch() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorFixture.Request r = new OperatorFixture.Request();
        r.authorization.add("DPoP " + token);
        r.host = "attacker.example";
        r.dpop.add(this.f.proof(token, "GET", "https://attacker.example" + OperatorFixture.PATH, c -> { }));
        assertEquals("invalid_dpop_proof", this.refused(this.f.jwt(), r, OperatorFixture.READ).reason());
        OperatorFixture.Request other = new OperatorFixture.Request();
        other.authorization.add("DPoP " + token);
        other.uri = "/federation-admin/keys";
        other.dpop.add(this.f.proof(token, "GET"));
        assertEquals("invalid_dpop_proof", this.refused(this.f.jwt(), other, OperatorFixture.READ).reason());
    }

    /** RFC 9449 §7.1: the ath claim is the hash of the access token presented with the proof. */
    @Test
    @Requirement("RFC9449 §7.1")
    void aProofForAnotherTokenIsRefused() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorFixture.Request r = new OperatorFixture.Request();
        r.authorization.add("DPoP " + token);
        String other = OperatorFixture.ath("another-token");
        r.dpop.add(this.f.proof(token, "GET", OperatorFixture.BASE + OperatorFixture.PATH, c -> c.setClaim("ath", other)));
        assertEquals("invalid_dpop_proof", this.refused(this.f.jwt(), r, OperatorFixture.READ).reason());
    }

    /** RFC 9449 §11.1: a proof is used once; the second presentation of the same proof is refused. */
    @Test
    @Requirement("RFC9449 §11.1")
    void aReplayedProofIsRefused() throws Exception {
        OperatorAuthenticator a = this.f.jwt();
        OperatorFixture.Request r = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
        assertInstanceOf(OperatorAuthenticator.Authorised.class, a.authenticate(r.mock(), OperatorFixture.READ));
        OperatorAuthenticator.Refused again = this.refused(a, r, OperatorFixture.READ);
        assertEquals(401, again.status());
        assertEquals("invalid_dpop_proof", again.reason());
    }

    /** RFC 9449 §6.1: the proof's key must be the one whose thumbprint the token's cnf.jkt names. */
    @Test
    @Requirement("RFC9449 §6.1")
    void aProofByAnotherKeyIsRefused() throws Exception {
        String token = this.f.token("oidf.admin.read");
        PublicJsonWebKey stranger = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        OperatorFixture.Request r = new OperatorFixture.Request();
        r.authorization.add("DPoP " + token);
        r.dpop.add(OperatorFixture.proof(stranger, token, "GET", OperatorFixture.BASE + OperatorFixture.PATH, c -> { }));
        OperatorAuthenticator.Refused refused = this.refused(this.f.jwt(), r, OperatorFixture.READ);
        assertEquals(401, refused.status());
        assertEquals("invalid_token", refused.reason(), "the proof is sound; the token is not bound to its key");
    }

    @Test
    void aDpopBoundTokenSentAsBearerIsRefused() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), OperatorFixture.bearer(token), OperatorFixture.READ);
        assertEquals(401, r.status());
        assertEquals("invalid_token", r.reason());
    }

    /** RFC 8705 §3: a certificate-bound token is accepted over the connection whose certificate it names. */
    @Test
    @Requirement("RFC8705 §3")
    void aCertificateBoundTokenIsAcceptedWhereTheContainerPresentsTheCertificate() throws Exception {
        byte[] der = "operator certificate".getBytes(StandardCharsets.UTF_8);
        String x5t = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(der));
        JwtClaims claims = this.f.claims("oidf.admin.read");
        claims.setClaim("cnf", Map.of("x5t#S256", x5t));
        String token = this.f.token(claims);
        OperatorFixture.Request r = OperatorFixture.bearer(token);
        r.certificates = new java.security.cert.X509Certificate[] {OperatorFixture.certificate(der)};
        Operator operator = assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.f.jwt().authenticate(r.mock(), OperatorFixture.READ)).operator();
        assertEquals("mtls", operator.binding());

        OperatorFixture.Request none = OperatorFixture.bearer(token);
        none.certificates = new java.security.cert.X509Certificate[0];
        assertEquals(401, this.refused(this.f.jwt(), none, OperatorFixture.READ).status());
        OperatorFixture.Request other = OperatorFixture.bearer(token);
        other.certificates = new java.security.cert.X509Certificate[] {OperatorFixture.certificate(new byte[] {1})};
        assertEquals(401, this.refused(this.f.jwt(), other, OperatorFixture.READ).status());
    }

    // ---- the request's form -----------------------------------------------------------------------------------------

    /**
     * RFC 6750 §3.1: "If the request lacks any authentication information (e.g., the client was unaware that
     * authentication is necessary or attempted using an unsupported authentication method), the resource server
     * SHOULD NOT include an error code or other error information."
     */
    @Test
    @Requirement("RFC6750 §3.1")
    void noCredentialsOrAnotherSchemeIsAChallengeWithNoError() throws Exception {
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), new OperatorFixture.Request(), OperatorFixture.READ);
        assertEquals(401, r.status());
        assertEquals("no_credentials", r.reason());
        assertEquals(2, r.challenges().size());
        r.challenges().forEach(c -> assertFalse(c.contains("error="), c));
        assertEquals("Bearer realm=\"" + OperatorFixture.BASE + "\"", challenge(r, "Bearer"));

        OperatorFixture.Request basic = new OperatorFixture.Request();
        basic.authorization.add("Basic dXNlcjpwYXNz");
        OperatorAuthenticator.Refused b = this.refused(this.f.jwt(), basic, OperatorFixture.READ);
        assertEquals(401, b.status());
        b.challenges().forEach(c -> assertFalse(c.contains("error="), c));
    }

    /**
     * RFC 6750 §3.1 invalid_request: "The request is missing a required parameter, includes an unsupported parameter
     * or parameter value, repeats the same parameter, uses more than one method for including an access token, or is
     * otherwise malformed. The resource server SHOULD respond with the HTTP 400 (Bad Request) status code."
     */
    @Test
    @Requirement("RFC6750 §3.1")
    void twoTokensATokenInTheQueryOrCredentialsThatAreNotToken68AreABadRequest() throws Exception {
        String token = this.f.token("oidf.admin.read");
        OperatorFixture.Request two = this.f.dpop(token, "GET");
        two.authorization.add("Bearer " + token);
        OperatorAuthenticator.Refused r = this.refused(this.f.jwt(), two, OperatorFixture.READ);
        assertEquals(400, r.status());
        assertEquals("invalid_request", r.reason());
        assertTrue(challenge(r, "DPoP").contains("error=\"invalid_request\""), "an ambiguous request: both");
        assertTrue(challenge(r, "Bearer").contains("error=\"invalid_request\""), "an ambiguous request: both");

        OperatorFixture.Request query = this.f.dpop(token, "GET");
        query.query = "x=1&access_token=" + token;
        assertEquals(400, this.refused(this.f.jwt(), query, OperatorFixture.READ).status());
        OperatorFixture.Request otherQuery = this.f.dpop(token, "GET");
        otherQuery.query = "my_access_token=1";
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.f.jwt().authenticate(otherQuery.mock(), OperatorFixture.READ));

        OperatorFixture.Request bare = new OperatorFixture.Request();
        bare.authorization.add("DPoP");
        assertEquals(400, this.refused(this.f.jwt(), bare, OperatorFixture.READ).status());
        OperatorFixture.Request spaced = new OperatorFixture.Request();
        spaced.authorization.add("DPoP a b");
        assertEquals(400, this.refused(this.f.jwt(), spaced, OperatorFixture.READ).status());
    }

    @Test
    void theSchemeNameIsCaseInsensitive() {
        assertEquals(DelegatedTokenValidator.Scheme.DPOP, OperatorAuthenticator.scheme("dpop"));
        assertEquals(DelegatedTokenValidator.Scheme.BEARER, OperatorAuthenticator.scheme("BEARER"));
        assertNull(OperatorAuthenticator.scheme("Basic"));
    }

    // ---- unavailable ------------------------------------------------------------------------------------------------

    @Test
    void anAuthenticatorThatIsNotConfiguredAnswersEveryRequest503() throws Exception {
        Map<String, String> env = this.f.jwtSettings();
        env.remove(OperatorAuthConfig.AUDIENCE);
        OperatorAuthenticator a = this.f.authenticator(env, DeploymentProfile.PRODUCTION);
        OperatorAuthenticator.Refused r = this.refused(a, this.f.dpop(this.f.token("oidf.admin.read"), "GET"),
                OperatorFixture.READ);
        assertEquals(503, r.status());
        assertEquals("not_configured", r.reason());
        assertEquals(List.of(), r.challenges());
        assertEquals("503", this.f.last().fields().get("status"));
    }

    @Test
    void anIssuerThatCannotBeReadIs503() throws Exception {
        OperatorAuthConfig config = OperatorFixture.config(this.f.jwtSettings(), DeploymentProfile.DEVELOPMENT);
        String token = this.f.token("oidf.admin.read");
        OperatorAuthenticator throwing = OperatorAuthenticator.from(config, null, request -> {
            throw new IllegalStateException("PingFederate is starting");
        }, this.f.clock);
        assertEquals("issuer_unavailable", this.refused(throwing, this.f.dpop(token, "GET"), OperatorFixture.READ).reason());
        OperatorAuthenticator linkage = OperatorAuthenticator.from(config, null, request -> {
            throw new NoClassDefFoundError("com/pingidentity/sdk/Something");
        }, this.f.clock);
        assertEquals(503, this.refused(linkage, this.f.dpop(token, "GET"), OperatorFixture.READ).status());
        OperatorAuthenticator empty = OperatorAuthenticator.from(config, null, request -> "", this.f.clock);
        assertEquals(503, this.refused(empty, this.f.dpop(token, "GET"), OperatorFixture.READ).status());
        OperatorAuthenticator none = OperatorAuthenticator.from(config, null, request -> null, this.f.clock);
        assertEquals(503, this.refused(none, this.f.dpop(token, "GET"), OperatorFixture.READ).status());
    }

    @Test
    void keysThatCannotBeFetchedAre503AndCountNoFailure() throws Exception {
        Map<String, String> env = this.f.jwtSettings();
        env.put(OperatorAuthConfig.JWKS_URL, "http://127.0.0.1:1/pf/JWKS");
        OperatorAuthenticator a = this.f.authenticator(env, DeploymentProfile.PRODUCTION);
        for (int i = 0; i < 12; i++) {
            OperatorAuthenticator.Refused r = this.refused(a, this.f.dpop(this.f.token("oidf.admin.read"), "GET"),
                    OperatorFixture.READ);
            assertEquals(503, r.status(), "an outage is not the caller's failure, so it is never a 429");
            assertEquals("unavailable", r.reason());
        }
    }

    // ---- the response -----------------------------------------------------------------------------------------------

    @Test
    void authoriseAnswersARefusalItselfAndLetsAnAuthorisedRequestGoOn() throws Exception {
        HttpServletResponse response = mock(HttpServletResponse.class);
        OperatorAuthenticator a = this.f.jwt();
        assertTrue(a.authorise(this.f.dpop(this.f.token("oidf.admin.read"), "GET").mock(), response,
                OperatorFixture.READ));
        verify(response, never()).setStatus(org.mockito.ArgumentMatchers.anyInt());

        HttpServletResponse refused = mock(HttpServletResponse.class);
        assertFalse(a.authorise(new OperatorFixture.Request().mock(), refused, OperatorFixture.READ));
        verify(refused).setStatus(401);
        verify(refused).setHeader("Cache-Control", "no-store");
        verify(refused).addHeader(org.mockito.ArgumentMatchers.eq("WWW-Authenticate"),
                org.mockito.ArgumentMatchers.startsWith("DPoP algs="));
        verify(refused).addHeader(org.mockito.ArgumentMatchers.eq("WWW-Authenticate"),
                org.mockito.ArgumentMatchers.startsWith("Bearer realm="));
        verify(refused, never()).setHeader(org.mockito.ArgumentMatchers.eq("Retry-After"),
                org.mockito.ArgumentMatchers.anyString());
        verify(refused).setContentLength(0);
    }

    @Test
    void textInAChallengeIsCutAndKeptToTheCharactersRfc6750Allows() {
        assertEquals("a?b?c?d", OperatorAuthenticator.headerSafe("a\"b\\c\nd"));
        assertEquals(200, OperatorAuthenticator.headerSafe("x".repeat(500)).length());
        assertEquals("", OperatorAuthenticator.headerSafe(null));
        assertEquals("caf?", OperatorAuthenticator.headerSafe("café"));
        assertEquals("?", OperatorAuthenticator.headerSafe("\u007f"));
    }

    @Test
    void aClaimedLabelIsCutMadeLogSafeOrAbsent() {
        assertNull(OperatorAuthenticator.claimedLabel(null));
        assertNull(OperatorAuthenticator.claimedLabel("   "));
        assertEquals("alice", OperatorAuthenticator.claimedLabel(" alice "));
        assertEquals(128, OperatorAuthenticator.claimedLabel("y".repeat(129)).length());
    }

    @Test
    void theHelpersSayWhatTheLimitsUse() {
        assertEquals(1L, OperatorAuthenticator.retryAfter(Duration.ZERO));
        assertEquals(1L, OperatorAuthenticator.retryAfter(Duration.ofMillis(1)));
        assertEquals(60L, OperatorAuthenticator.retryAfter(Duration.ofMillis(59_001)));
        assertEquals("-", OperatorAuthenticator.failureKey(null));
        assertEquals("-", OperatorAuthenticator.failureKey(""));
        assertEquals("192.0.2.1", OperatorAuthenticator.failureKey("192.0.2.1"));
        assertEquals(43, OperatorAuthenticator.digest("operator").length());
    }

    @Test
    void theReplayStoreIsThisJvmsWithoutRedis() throws Exception {
        // Two authenticators with their own stores do not share proofs: each node is its own (decision 9).
        OperatorAuthenticator a = this.f.jwt();
        OperatorAuthenticator b = this.f.jwt();
        OperatorFixture.Request r = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
        assertInstanceOf(OperatorAuthenticator.Authorised.class, a.authenticate(r.mock(), OperatorFixture.READ));
        assertInstanceOf(OperatorAuthenticator.Authorised.class, b.authenticate(r.mock(), OperatorFixture.READ));
        assertTrue(new InMemoryReplayStore().firstUse("k", Duration.ofSeconds(1)));
    }
}
