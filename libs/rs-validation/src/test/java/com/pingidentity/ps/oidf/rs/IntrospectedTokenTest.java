package com.pingidentity.ps.oidf.rs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.auth.ClientAuthentication;
import com.pingidentity.ps.oidf.platform.auth.TokenIntrospector;
import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.json.Json;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The validator over an introspection endpoint (RFC 7662) instead of the authorisation server's keys, and a bearer
 * token bound to nothing, which only development accepts.
 */
class IntrospectedTokenTest {
    private static final String TOKEN = "opaque-reference-token";

    private final Fixture f;
    private HttpServer server;
    private final AtomicReference<String> answer = new AtomicReference<>();
    private final AtomicInteger status = new AtomicInteger(200);

    IntrospectedTokenTest() throws Exception {
        this.f = new Fixture();
    }

    @BeforeEach
    void start() throws Exception {
        this.answer.set(Json.write(this.active()));
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.createContext("/introspect", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] out = this.answer.get().getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(this.status.get(), out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    /** An active answer for a DPoP-bound token, shaped as PingFederate 13.1.3 gives it for a JWT token. */
    private Map<String, Object> active() throws Exception {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("active", true);
        m.put("sub", "operator-client");
        m.put("client_id", "operator-client");
        m.put("aud", Fixture.AUDIENCE);
        m.put("iss", Fixture.ISSUER);
        m.put("scope", "oidf.admin.read");
        m.put("token_type", "DPoP");
        m.put("exp", NumericDate.now().getValue() + 300);
        m.put("cnf", Map.of("jkt", Fixture.thumbprint(this.f.clientKey)));
        return m;
    }

    private void answer(Map<String, Object> members) {
        this.answer.set(Json.write(members));
    }

    private TokenIntrospector introspector() {
        OutboundHttp http = OutboundHttp.builder(AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build())
                .build();
        return TokenIntrospector.builder(http,
                URI.create("http://127.0.0.1:" + this.server.getAddress().getPort() + "/introspect"),
                ClientAuthentication.clientSecretBasic("rs", () -> "secret")).build();
    }

    private DelegatedTokenValidator validator() {
        return DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE).introspection(this.introspector())
                .replayStore(new InMemoryReplayStore()).build();
    }

    private DelegatedTokenValidator.Result dpop(DelegatedTokenValidator v) throws Exception {
        return v.validate(Fixture.dpop(TOKEN, List.of(this.f.proof(TOKEN))));
    }

    private DelegatedTokenValidator.RsException refused(DelegatedTokenValidator v) {
        return assertThrows(DelegatedTokenValidator.RsException.class, () -> this.dpop(v));
    }

    /**
     * RFC 9449 §6.2: "the resource server uses the data of the introspection response to validate the access token
     * binding itself locally" - the proof's key against {@code cnf.jkt}, its {@code ath} against the opaque token.
     */
    @Test
    @Requirement("RFC9449 §6.2")
    void anActiveDpopBoundAnswerAndItsProofAreAccepted() throws Exception {
        DelegatedTokenValidator.Result r = this.dpop(this.validator());
        assertEquals("operator-client", r.subject());
        assertEquals(List.of("oidf.admin.read"), r.scopes());
        assertEquals(DelegatedTokenValidator.Binding.DPOP, r.binding());
        assertFalse(r.isDelegated());
        // A proof for another token is refused: ath binds the proof to this one.
        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> this.validator().validate(Fixture.dpop(TOKEN, List.of(this.f.proof("another-token")))));
        assertEquals("invalid_dpop_proof", e.error());
    }

    /**
     * RFC 7662 §2.2 makes {@code iss} and {@code exp} OPTIONAL, and PingFederate 13.1.3 leaves {@code iss} out for a
     * reference token (the rig, 2026-09-29): an answer without them is the configured server's word that the token is
     * active.
     */
    @Test
    @Requirement("RFC7662 §2.2")
    void aReferenceTokenAnswerWithoutIssOrExpIsAccepted() throws Exception {
        Map<String, Object> m = this.active();
        m.remove("iss");
        m.remove("exp");
        m.put("token_type", "dpop");
        this.answer(m);
        assertEquals("operator-client", this.dpop(this.validator()).subject());
    }

    /** RFC 7662 §2.2: "active REQUIRED. Boolean indicator of whether or not the presented token is currently active". */
    @Test
    @Requirement("RFC7662 §2.2")
    void anInactiveTokenIsInvalidToken() {
        this.answer.set("{\"active\":false}");
        DelegatedTokenValidator.RsException e = this.refused(this.validator());
        assertEquals("invalid_token", e.error());
        assertEquals(401, e.status());
        assertEquals("the authorisation server says the access token is not active", e.getMessage());
    }

    @Test
    void anEndpointWithNoAnswerIsUnavailable() {
        this.status.set(500);
        DelegatedTokenValidator.RsException e = this.refused(this.validator());
        assertNull(e.error());
        assertEquals(503, e.status());
        assertTrue(e.getMessage().startsWith("the authorisation server's introspection endpoint is unavailable"));
    }

    @Test
    void theAnswersClaimsAreCheckedAsAJwtsAre() throws Exception {
        Map<String, Object> m = this.active();
        m.put("iss", "https://other.example");
        this.answer(m);
        assertEquals("access token issuer is not the expected AS", this.refused(this.validator()).getMessage());
        m = this.active();
        m.put("aud", "https://other.example");
        this.answer(m);
        assertEquals("access token audience is not this resource", this.refused(this.validator()).getMessage());
        m = this.active();
        m.remove("aud");
        this.answer(m);
        assertEquals("access token audience is not this resource", this.refused(this.validator()).getMessage());
        m = this.active();
        m.put("exp", NumericDate.now().getValue() - 3600);
        this.answer(m);
        assertEquals("access token has expired", this.refused(this.validator()).getMessage());
        m = this.active();
        m.put("nbf", NumericDate.now().getValue() + 3600);
        this.answer(m);
        assertEquals("access token is not valid yet (nbf)", this.refused(this.validator()).getMessage());
        m = this.active();
        m.remove("cnf");
        this.answer(m);
        assertEquals("access token carries no cnf, so it is not sender-constrained",
                this.refused(this.validator()).getMessage());
    }

    /** RFC 9449 §6.2: "If the token_type member is included in the introspection response, it MUST contain the value DPoP." */
    @Test
    @Requirement("RFC9449 §6.2")
    void aDpopBindingWithAnotherTokenTypeContradictsItself() throws Exception {
        Map<String, Object> m = this.active();
        m.put("token_type", "Bearer");
        this.answer(m);
        DelegatedTokenValidator.RsException e = this.refused(this.validator());
        assertEquals("invalid_token", e.error());
        assertEquals("the introspection answer binds the token to a DPoP key but gives its token_type as Bearer",
                e.getMessage());
        m.remove("token_type");
        this.answer(m);
        assertEquals(DelegatedTokenValidator.Binding.DPOP, this.dpop(this.validator()).binding());
    }

    @Test
    void anAnswerThatCannotBeClaimsIsInvalidToken() throws Exception {
        // A number Json reads but will not write back: the answer cannot become claims.
        this.answer.set(this.answer.get().replace("{\"active\":true", "{\"active\":true,\"pad\":1e999"));
        assertEquals("the introspection answer's members are not valid JWT claims",
                this.refused(this.validator()).getMessage());
    }

    @Test
    void keysOrIntrospectionAndNotBoth() throws Exception {
        assertThrows(IllegalStateException.class, () -> this.f.builder(new InMemoryReplayStore())
                .introspection(this.introspector()).build());
        assertThrows(IllegalStateException.class, () -> DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .replayStore(new InMemoryReplayStore()).build());
    }

    // ---- unbound, development only --------------------------------------------------------------------------------

    private static DelegatedTokenValidator.Presentation bearer(String token, X509Certificate certificate) {
        return new DelegatedTokenValidator.Presentation(DelegatedTokenValidator.Scheme.BEARER, token, null, "GET",
                Fixture.URL, certificate);
    }

    @Test
    void developmentAcceptsATokenBoundToNothingAsABearerToken() throws Exception {
        Map<String, Object> m = this.active();
        m.remove("cnf");
        m.remove("token_type");
        this.answer(m);
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .introspection(this.introspector()).replayStore(new InMemoryReplayStore())
                .allowUnbound(DeploymentProfile.DEVELOPMENT).build();
        assertTrue(v.acceptsUnbound());
        assertTrue(v.acceptsBearer());
        assertFalse(v.acceptsMtls());
        DelegatedTokenValidator.Result r = v.validate(bearer(TOKEN, null));
        assertEquals(DelegatedTokenValidator.Binding.NONE, r.binding());
        assertNull(r.dpopJti());
        // Sent as DPoP it is still refused: there is no key to prove.
        assertEquals("access token carries no cnf, so it is not sender-constrained",
                assertThrows(DelegatedTokenValidator.RsException.class, () -> this.dpop(v)).getMessage());
        // A cnf that names nothing is refused either way.
        m.put("cnf", Map.of());
        this.answer(m);
        assertEquals("access token cnf carries neither jkt nor x5t#S256",
                assertThrows(DelegatedTokenValidator.RsException.class, () -> v.validate(bearer(TOKEN, null))).getMessage());
    }

    /** RFC 9449 §7.2: "such a protected resource MUST reject a DPoP-bound access token received as a bearer token". */
    @Test
    @Requirement("RFC9449 §7.2")
    void developmentStillRefusesADpopBoundTokenSentAsBearer() {
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .introspection(this.introspector()).replayStore(new InMemoryReplayStore())
                .allowUnbound(DeploymentProfile.DEVELOPMENT).build();
        DelegatedTokenValidator.RsException e = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> v.validate(bearer(TOKEN, null)));
        assertEquals("a DPoP-bound access token was sent as a bearer token", e.getMessage());
    }

    @Test
    void productionRefusesToBuildAValidatorThatAcceptsUnboundTokens() {
        DelegatedTokenValidator.Builder b = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .introspection(this.introspector()).replayStore(new InMemoryReplayStore());
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> b.allowUnbound(DeploymentProfile.PRODUCTION).build());
        assertTrue(e.getMessage().startsWith("a token bound to nothing is accepted only under OIDF_DEPLOYMENT_PROFILE"));
        // The process's own profile: these tests run with none set, which is production.
        assertThrows(IllegalStateException.class, () -> DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .introspection(this.introspector()).replayStore(new InMemoryReplayStore()).allowUnbound().build());
        // Without unbound or mTLS a bearer token is a scheme this resource does not take: no error code.
        DelegatedTokenValidator dpopOnly = this.validator();
        assertFalse(dpopOnly.acceptsBearer());
        DelegatedTokenValidator.RsException none = assertThrows(DelegatedTokenValidator.RsException.class,
                () -> dpopOnly.validate(bearer(TOKEN, null)));
        assertNull(none.error());
    }

    @Test
    void anMtlsBoundTokenReportsItsBinding() throws Exception {
        byte[] der = {7, 7, 7};
        X509Certificate certificate = mock(X509Certificate.class);
        when(certificate.getEncoded()).thenReturn(der);
        Map<String, Object> m = this.active();
        m.put("cnf", Map.of("x5t#S256", Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(der))));
        m.remove("token_type");
        this.answer(m);
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .introspection(this.introspector()).replayStore(new InMemoryReplayStore()).mtls(true).build();
        assertEquals(DelegatedTokenValidator.Binding.MTLS, v.validate(bearer(TOKEN, certificate)).binding());
    }

    @Test
    void theFilterOffersABearerChallengeWhenUnboundTokensAreAccepted() {
        DelegatedTokenValidator v = DelegatedTokenValidator.builder(Fixture.ISSUER, Fixture.AUDIENCE)
                .introspection(this.introspector()).replayStore(new InMemoryReplayStore())
                .allowUnbound(DeploymentProfile.DEVELOPMENT).build();
        List<String> challenges = new ResourceServerFilter(v, Fixture.BASE)
                .challenges(null, new DelegatedTokenValidator.RsException(null, 401, "no credentials"));
        assertEquals(List.of("DPoP algs=\"ES256 PS256 RS256\"", "Bearer realm=\"https://rs.example.com\""), challenges);
    }
}
