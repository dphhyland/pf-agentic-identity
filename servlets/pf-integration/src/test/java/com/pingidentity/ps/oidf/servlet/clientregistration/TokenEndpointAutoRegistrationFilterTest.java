package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.PfRequestScope;
import com.pingidentity.ps.oidf.pf.testkit.AuditCapture;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The token-endpoint filter: automatic registration (OpenID Federation §12.1) and the registration lifetime
 * (§12.3) in front of PingFederate's client authentication. What it decides is {@link RegistrationService#admit}'s;
 * what these tests pin is which client a request names, and what the caller is told when the answer is no.
 *
 * <p>Ported from pf-oidf-modules (2026-08-15) when that repo was reduced to the demo.
 */
class TokenEndpointAutoRegistrationFilterTest {

    private static final String CLIENT_ID = "https://rp.example.com/e/agent-42";
    private static final String OP_ISSUER = "https://as.example.com";
    private static final List<String> TRUST_CHAIN = List.of("leafJwt", "anchorJwt");
    private static final Function<HttpServletRequest, String> FIXED_ISSUER = req -> OP_ISSUER;
    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String ANCHOR_JWKS_PROP = "oidf.federation.trust.anchor.jwks";

    private final RegistrationService service = mock(RegistrationService.class);
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final StringWriter body = new StringWriter();

    @BeforeEach
    @AfterEach
    void resetRuntimeConfig() throws Exception {
        System.clearProperty(HOST_PROP);
        System.clearProperty(ANCHOR_JWKS_PROP);
        System.clearProperty(RegistrationExpirySweeper.OWNER_PROPERTY);
        FederationRuntimeConfig.resetForTests();
    }

    @BeforeEach
    void captureTheBody() throws Exception {
        when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
    }

    private TokenEndpointAutoRegistrationFilter filter(boolean failClosed) {
        return new TokenEndpointAutoRegistrationFilter(this.service, FIXED_ISSUER, failClosed);
    }

    private Map<String, Object> answered() {
        try {
            return JsonUtil.parseJson(this.body.toString());
        } catch (Exception e) {
            throw new AssertionError("not JSON: " + this.body, e);
        }
    }

    /** A client_assertion JWT carrying {@code trustChain} in its {@code trust_chain} header (none when empty). */
    private static String clientAssertion(List<?> trustChain, String sub) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        JwtClaims claims = new JwtClaims();
        claims.setSubject(sub);
        claims.setIssuer(sub);
        claims.setAudience(OP_ISSUER);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setExpirationTimeMinutesInTheFuture(5.0f);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        if (!trustChain.isEmpty()) {
            jws.setHeader("trust_chain", trustChain);
        }
        return jws.getCompactSerialization();
    }

    // ---- init: the anchor's keys are pinned, or the filter does not start ---------------------------

    @Test
    @Requirement("OIDFED §4")
    void withoutPinnedAnchorKeysNothingIsRegisteredButTheWebAppKeepsServing() throws Exception {
        System.setProperty(HOST_PROP, "https://anchor.example");
        TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter();

        // Init must not fail: this web app also serves the entity's own .well-known, which a
        // self-anchored PF has to publish before its keys can be captured and pinned.
        assertDoesNotThrow(() -> filter.init(mock(FilterConfig.class)));

        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, CLIENT_ID));
        filter.doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verifyNoInteractions(this.request);
    }

    @Test
    void refusesToStartWhenThePinnedKeysAreNotAUsableKeySet() {
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\":[]}");

        ServletException e = assertThrows(ServletException.class,
                () -> new TokenEndpointAutoRegistrationFilter().init(mock(FilterConfig.class)));
        assertTrue(e.getMessage().contains("no keys"), e.getMessage());
    }

    @Test
    void refusesToStartWithNoTrustControllerAtAll() {
        ServletException e = assertThrows(ServletException.class,
                () -> new TokenEndpointAutoRegistrationFilter().init(mock(FilterConfig.class)));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.HOST_ENV), e.getMessage());
    }

    @Test
    void startsWhenTheTrustControllersKeysArePinned() throws Exception {
        EllipticCurveJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\":[" + anchor.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");

        assertDoesNotThrow(() -> new TokenEndpointAutoRegistrationFilter().init(mock(FilterConfig.class)));
    }

    @Test
    void anInjectedServiceIsKeptThroughInit() throws Exception {
        TokenEndpointAutoRegistrationFilter filter = this.filter(true);
        filter.init(mock(FilterConfig.class));
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        filter.doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of(), OP_ISSUER);
    }

    // ---- which client the request names ---------------------------------------------------------------

    @Test
    @Requirement("OIDFED §12.1(4.1)")
    void theClientIsTheAssertionsSubjectAndItsChainTheHint() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, CLIENT_ID));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, TRUST_CHAIN, OP_ISSUER);
        verify(this.chain).doFilter(this.request, this.response);
    }

    /** An assertion with no chain is an ordinary private_key_jwt: its client is still looked at, for its expiry. */
    @Test
    void anAssertionWithoutAChainNamesItsClientWithNoHint() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(List.of(), CLIENT_ID));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of(), OP_ISSUER);
        verify(this.chain).doFilter(this.request, this.response);
    }

    @Test
    void onlyTheStringsOfAChainHeaderAreKept() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(List.of("one", 2, "three"), CLIENT_ID));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of("one", "three"), OP_ISSUER);
    }

    @Test
    void withoutAnAssertionTheClientIsItsClientIdParameter() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of(), OP_ISSUER);
    }

    @Test
    void anAssertionThatIsNotAJwtFallsBackToClientId() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn("not-a-jwt");
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of(), OP_ISSUER);
    }

    @Test
    void anAssertionWithABlankSubjectFallsBackToClientId() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, " "));
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, TRUST_CHAIN, OP_ISSUER);
    }

    /** No subject and no client_id: nothing names a client, so nothing reaches the registration service. */
    @Test
    void aRequestNamingNoClientPassesUntouched() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, ""));
        when(this.request.getParameter("client_id")).thenReturn("  ");

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verifyNoInteractions(this.service);
    }

    @Test
    void aResponseThatIsNotHttpPassesUntouched() throws Exception {
        ServletResponse plainResponse = mock(ServletResponse.class);
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        this.filter(true).doFilter(this.request, plainResponse, this.chain);

        verify(this.chain).doFilter(this.request, plainResponse);
        verifyNoInteractions(this.service);
    }

    @Test
    void anAssertionWithNoSubjectFallsBackToClientId() throws Exception {
        String noSubject = com.pingidentity.ps.oidf.federation.testkit.Statements.spec("JWT").claim("iss", CLIENT_ID)
                .unsigned().sign(null, java.time.Clock.systemUTC());
        when(this.request.getParameter("client_assertion")).thenReturn(noSubject);
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of(), OP_ISSUER);
    }

    @Test
    void aBlankAssertionIsNoAssertion() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn("   ");
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.service).admit(CLIENT_ID, List.of(), OP_ISSUER);
    }

    @Test
    void aRequestThatIsNotHttpPassesUntouched() throws Exception {
        ServletRequest plain = mock(ServletRequest.class);
        ServletResponse plainResponse = mock(ServletResponse.class);

        this.filter(true).doFilter(plain, plainResponse, this.chain);

        verify(this.chain).doFilter(plain, plainResponse);
        verifyNoInteractions(this.service);
    }

    // ---- what the caller is told ----------------------------------------------------------------------

    @Test
    @Requirement({"RFC6749 §5.2", "OIDFED §12.3(1)"})
    void aRegistrationThatCannotStandIsInvalidClient() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(new RegistrationRejectedException(401, "invalid_client",
                "the client's federation registration has expired", RegistrationRejectedException.Kind.TRUST, null));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(401);
        verify(this.response).setContentType("application/json");
        verify(this.response).setHeader("Cache-Control", "no-store");
        assertEquals("invalid_client", this.answered().get("error"));
        assertEquals("the client's federation registration has expired", this.answered().get("error_description"));
        verify(this.chain, never()).doFilter(any(), any());
    }

    @Test
    void aServerTooBusyToRegisterSaysWhenToRetry() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(RegistrationRejectedException.busy("busy"));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(503);
        verify(this.response).setHeader("Retry-After", "2");
        assertEquals("temporarily_unavailable", this.answered().get("error"));
    }

    @Test
    void anInitParamThatDoesNotParseStopsTheFilterStarting() throws Exception {
        EllipticCurveJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\":[" + anchor.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");
        FilterConfig config = mock(FilterConfig.class);
        when(config.getInitParameter("trustChainEntryMaxAgeSeconds")).thenReturn("a minute");

        ServletException e = assertThrows(ServletException.class, () -> new TokenEndpointAutoRegistrationFilter().init(config));
        assertTrue(e.getMessage().contains("trustChainEntryMaxAgeSeconds"), e.getMessage());

        when(config.getInitParameter("trustChainEntryMaxAgeSeconds")).thenReturn("0");
        ServletException zero = assertThrows(ServletException.class, () -> new TokenEndpointAutoRegistrationFilter().init(config));
        assertTrue(zero.getMessage().contains("must be positive"), "it used to mean 60, quietly: " + zero.getMessage());
    }

    @Test
    @Requirement("OIDFED §10.5")
    void aFederationThatCannotBeReachedIsTemporarilyUnavailable() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(new RegistrationRejectedException(503,
                "temporarily_unavailable", "cannot check the chain right now", RegistrationRejectedException.Kind.TRANSPORT, null));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(503);
        verify(this.response).setHeader("Retry-After", "15");
        assertEquals("temporarily_unavailable", this.answered().get("error"));
        verify(this.chain, never()).doFilter(any(), any());
    }

    /** A failed registration is a failed client authentication at this endpoint, whatever §8.9 code it carried. */
    @Test
    void aRefusedFirstRegistrationIsInvalidClientToo() throws Exception {
        when(this.request.getParameter("client_assertion")).thenReturn(clientAssertion(TRUST_CHAIN, CLIENT_ID));
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(new RegistrationRejectedException(400,
                "invalid_client_metadata", "does not advertise automatic"));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(401);
        assertEquals("invalid_client", this.answered().get("error"));
        assertEquals("does not advertise automatic", this.answered().get("error_description"));
    }

    @Test
    void anUnexpectedFailureIsAServerErrorThatSaysNothingOfItself() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(new IllegalStateException("store at 10.0.0.7 refused"));

        this.filter(true).doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(500);
        assertEquals("server_error", this.answered().get("error"));
        assertFalse(this.body.toString().contains("10.0.0.7"), this.body.toString());
        verify(this.chain, never()).doFilter(any(), any());
    }

    // ---- fail-open: the 0.2.0 behaviour, on request ---------------------------------------------------

    @Test
    void failOpenPassesARefusalOnToPingFederate() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(new RegistrationRejectedException(401, "invalid_client", "expired"));

        this.filter(false).doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verify(this.response, never()).setStatus(anyInt());
    }

    @Test
    void failOpenPassesAnUnexpectedFailureOnToPingFederate() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.service.admit(anyString(), anyList(), anyString())).thenThrow(new IllegalStateException("boom"));

        this.filter(false).doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verify(this.response, never()).setStatus(anyInt());
    }

    @Test
    void failOpenIsReadFromTheDeploymentAtInit() throws Exception {
        EllipticCurveJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\":[" + anchor.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");
        System.setProperty("oidf.auto.registration.fail.closed", "false");
        try {
            FederationRuntimeConfig.resetForTests();
            TokenEndpointAutoRegistrationFilter filter = new TokenEndpointAutoRegistrationFilter();
            filter.init(mock(FilterConfig.class));

            assertFalse(filter.isFailClosed());
        } finally {
            System.clearProperty("oidf.auto.registration.fail.closed");
        }
    }

    // ---- whose request an audit record names ------------------------------------------------------------

    @Test
    void whatTheRegistrationAuditsCarriesTheCallersAddressAndTheScopeEndsWithTheRequest() throws Exception {
        try (AuditCapture audit = AuditCapture.install()) {
            when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
            when(this.request.getRemoteAddr()).thenReturn("203.0.113.7");
            when(this.service.admit(anyString(), anyList(), anyString())).thenAnswer(call -> {
                FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("invalid_trust_chain").subject(CLIENT_ID).audit().emit();
                throw new RegistrationRejectedException(401, "invalid_client", "the trust chain did not validate",
                        RegistrationRejectedException.Kind.TRUST, null);
            });

            this.filter(true).doFilter(this.request, this.response, this.chain);

            verify(this.response).setStatus(401);
            assertEquals("203.0.113.7", audit.only(FederationEvents.REGISTRATION_REFUSED).remoteAddress());
            assertNull(PfRequestScope.current());
        }
    }

    @Test
    void pingFederatesHandlingIsInsideTheScopeAndAFailureThereStillEndsIt() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(CLIENT_ID);
        when(this.request.getRemoteAddr()).thenReturn("203.0.113.7");
        AtomicReference<PfRequestScope.Context> during = new AtomicReference<>();
        doAnswer(call -> {
            during.set(PfRequestScope.current());
            throw new IOException("the client went away");
        }).when(this.chain).doFilter(this.request, this.response);

        assertThrows(IOException.class, () -> this.filter(true).doFilter(this.request, this.response, this.chain));

        assertEquals("203.0.113.7", during.get().remoteAddress());
        assertNull(PfRequestScope.current(), "a pooled thread must not carry this caller's address into its next request");
    }

    // ---- the client id a request names, directly --------------------------------------------------------

    @Test
    void clientIdOfPrefersTheAssertionsSubject() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn("https://other.example");

        assertEquals(CLIENT_ID, TokenEndpointAutoRegistrationFilter.clientIdOf(this.request, clientAssertion(List.of(), CLIENT_ID)));
        assertEquals("https://other.example", TokenEndpointAutoRegistrationFilter.clientIdOf(this.request, null));
        assertEquals("https://other.example", TokenEndpointAutoRegistrationFilter.clientIdOf(this.request, ""));
        when(this.request.getParameter("client_id")).thenReturn(null);
        assertNull(TokenEndpointAutoRegistrationFilter.clientIdOf(this.request, null));
        verify(this.service, never()).admit(eq(CLIENT_ID), anyList(), anyString());
    }
}
