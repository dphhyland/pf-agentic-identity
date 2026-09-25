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
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.PfRequestScope;
import com.pingidentity.ps.oidf.pf.testkit.AuditCapture;
import com.pingidentity.ps.oidf.servlet.oauth.FederationErrorPage;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
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
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * The filter in front of PingFederate's authorization and PAR endpoints (OpenID Federation 1.0 §12.1.1). What it
 * decides is {@link RegistrationService}'s; these tests pin which requests it touches at all, what it hands over as
 * proof, and how a refusal is answered: JSON at PAR, a page - never a redirect - at the authorization endpoint.
 */
class FrontChannelAutoRegistrationFilterTest {

    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://op.example.com";

    private final RegistrationService service = mock(RegistrationService.class);
    private final RegistrationService.Channel channel = mock(RegistrationService.Channel.class);
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final StringWriter body = new StringWriter();
    private final RequestObject.ReplayGuard replay = (client, jti, ttl) -> true;

    @BeforeEach
    void wire() throws Exception {
        when(this.response.getWriter()).thenReturn(new PrintWriter(this.body));
        when(this.service.frontChannel(anyString(), anyString(), anyString(), any(), any(), any(), any())).thenReturn(this.channel);
        when(this.request.getRequestURI()).thenReturn("/as/authorization.oauth2");
        when(this.request.getMethod()).thenReturn("GET");
    }

    @BeforeEach
    @AfterEach
    void resetConfig() {
        FederationRuntimeConfig.resetForTests();
        System.clearProperty("oidf.federation.trust.controller.host");
        System.clearProperty("oidf.federation.trust.anchor.jwks");
        System.clearProperty("oidf.auto.registration.front.channel");
        System.clearProperty("oidf.federation.error.page");
    }

    private FrontChannelAutoRegistrationFilter filter(boolean failClosed, AutoRegistrationSettings settings) {
        return new FrontChannelAutoRegistrationFilter(this.service, r -> OP, settings, failClosed, this.replay, FederationErrorPage.builtIn());
    }

    private FrontChannelAutoRegistrationFilter filter() {
        return this.filter(true, AutoRegistrationSettings.DEFAULTS);
    }

    private void par() {
        when(this.request.getRequestURI()).thenReturn("/as/par.oauth2");
        when(this.request.getMethod()).thenReturn("POST");
    }

    private static String signed(Map<String, Object> claims, List<String> trustChain) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(claims));
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        if (trustChain != null) {
            jws.setHeader("trust_chain", trustChain);
        }
        return jws.getCompactSerialization();
    }

    private void refusedWith(RegistrationRejectedException e) throws Exception {
        when(this.service.admit(anyString(), anyList(), anyString(), any())).thenThrow(e);
    }

    // ---- which requests are touched -----------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §12.1.1.1.2(1)", "OIDFED §12.1.1.1.2(2)"})
    void anRpsRequestObjectIsHandedOverWithTheChainItCarries() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getParameter("request")).thenReturn(signed(Map.of("iss", RP), List.of("leaf", "statement")));

        this.filter().doFilter(this.request, this.response, this.chain);

        ArgumentCaptor<RequestObject> proof = ArgumentCaptor.forClass(RequestObject.class);
        verify(this.service).frontChannel(eq("authorization"), eq(RP), eq(OP), proof.capture(), isNull(), eq(this.replay),
                eq(AutoRegistrationSettings.DEFAULTS));
        assertEquals(RequestObject.Kind.REQUEST_OBJECT, proof.getValue().kind());
        verify(this.service).admit(RP, List.of("leaf", "statement"), OP, this.channel);
        verify(this.chain).doFilter(this.request, this.response);
    }

    @Test
    @Requirement("OIDFED §12.1.1.2(2)")
    void atParAClientAssertionIsTheProofAndItsSubjectTheClient() throws Exception {
        this.par();
        when(this.request.getParameter("client_assertion")).thenReturn(signed(Map.of("sub", RP, "iss", RP), null));

        this.filter().doFilter(this.request, this.response, this.chain);

        ArgumentCaptor<RequestObject> proof = ArgumentCaptor.forClass(RequestObject.class);
        verify(this.service).frontChannel(eq("par"), eq(RP), eq(OP), proof.capture(), isNull(), any(), any());
        assertEquals(RequestObject.Kind.CLIENT_ASSERTION, proof.getValue().kind());
        verify(this.service).admit(RP, List.of(), OP, this.channel);
    }

    @Test
    void aRequestWithoutProofIsStillAskedAbout() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.service).frontChannel(eq("authorization"), eq(RP), eq(OP), isNull(), isNull(), any(), any());
        verify(this.chain).doFilter(this.request, this.response);
    }

    @Test
    void anUnreadableProofIsHandedOverAsItsError() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getParameter("request")).thenReturn("not.a.jwt.at-all");

        this.filter().doFilter(this.request, this.response, this.chain);

        ArgumentCaptor<RegistrationRejectedException> unreadable = ArgumentCaptor.forClass(RegistrationRejectedException.class);
        verify(this.service).frontChannel(anyString(), anyString(), anyString(), isNull(), unreadable.capture(), any(), any());
        assertEquals("invalid_request_object", unreadable.getValue().error());
    }

    @Test
    void aClientIdThatIsNotAnEntityIdentifierIsLeftToPingFederate() throws Exception {
        for (String clientId : List.of("my-client", "http://rp.example.com", "https://rp.example.com?x=1", "https://" + "a".repeat(2048))) {
            HttpServletRequest other = mock(HttpServletRequest.class);
            when(other.getRequestURI()).thenReturn("/as/authorization.oauth2");
            when(other.getParameter("client_id")).thenReturn(clientId);

            this.filter().doFilter(other, this.response, this.chain);

            verify(this.chain).doFilter(other, this.response);
        }
        verifyNoInteractions(this.service);
    }

    @Test
    void aRequestNamingNoClientIsLeftToPingFederate() throws Exception {
        this.par();
        when(this.request.getParameter("client_assertion")).thenReturn("garbage");

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verifyNoInteractions(this.service);
    }

    @Test
    void aPushedRequestUriWasRegisteredForWhenItWasPushed() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getParameter("request_uri")).thenReturn(FrontChannelAutoRegistrationFilter.PAR_REQUEST_URI_PREFIX + "abc");

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verifyNoInteractions(this.service);
    }

    @Test
    void parTakesPostOnlyAndSaysSoItself() throws Exception {
        when(this.request.getRequestURI()).thenReturn("/as/par.oauth2");
        when(this.request.getMethod()).thenReturn("GET");
        when(this.request.getParameter("client_id")).thenReturn(RP);

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verifyNoInteractions(this.service);
    }

    @Test
    void somethingThatIsNotHttpOrAFilterWithNoServiceIsLeftAlone() throws Exception {
        ServletRequest plain = mock(ServletRequest.class);
        ServletResponse plainResponse = mock(ServletResponse.class);
        this.filter().doFilter(plain, plainResponse, this.chain);
        verify(this.chain).doFilter(plain, plainResponse);
        this.filter().doFilter(this.request, plainResponse, this.chain);
        verify(this.chain).doFilter(this.request, plainResponse);

        FrontChannelAutoRegistrationFilter unstarted = new FrontChannelAutoRegistrationFilter();
        unstarted.doFilter(this.request, this.response, this.chain);
        verify(this.chain).doFilter(this.request, this.response);
        verifyNoInteractions(this.service);
    }

    // ---- how a refusal is answered ----------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §12.1.3(3)", "OIDFED §12.1.3(4)"})
    void atParARefusalIsJsonWithItsFederationError() throws Exception {
        this.par();
        when(this.request.getParameter("client_id")).thenReturn(RP);
        this.refusedWith(new RegistrationRejectedException(400, "invalid_trust_chain", "no route to a trusted anchor",
                RegistrationRejectedException.Kind.TRUST, null));

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(400);
        verify(this.response).setContentType("application/json");
        assertEquals("invalid_trust_chain", JsonUtil.parseJson(this.body.toString()).get("error"));
        verify(this.chain, never()).doFilter(any(), any());
    }

    @Test
    @Requirement({"OIDFED §12.1.3(2)", "OIDFED §12.1.3(3)"})
    void atTheAuthorizationEndpointARefusalIsAPageNeverARedirect() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getParameter("redirect_uri")).thenReturn(RP + "/cb");
        this.refusedWith(new RegistrationRejectedException(400, "invalid_metadata", "<script>no</script>",
                RegistrationRejectedException.Kind.TRUST, null));

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(400);
        verify(this.response).setContentType("text/html;charset=UTF-8");
        verify(this.response, never()).sendRedirect(anyString());
        verify(this.response, never()).setHeader(eq("Location"), anyString());
        assertTrue(this.body.toString().contains("invalid_metadata"));
        assertTrue(this.body.toString().contains("&lt;script&gt;"), "the description is escaped");
        assertFalse(this.body.toString().contains(RP + "/cb"), "the RP's redirect_uri appears nowhere");
        verify(this.chain, never()).doFilter(any(), any());
    }

    @Test
    void aRetryableRefusalSaysWhenToRetry() throws Exception {
        this.par();
        when(this.request.getParameter("client_id")).thenReturn(RP);
        this.refusedWith(RegistrationRejectedException.busy("busy"));
        this.filter().doFilter(this.request, this.response, this.chain);
        verify(this.response).setHeader("Retry-After", "2");
        verify(this.response).setStatus(503);

        HttpServletResponse second = mock(HttpServletResponse.class);
        when(second.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        org.mockito.Mockito.doThrow(new RegistrationRejectedException(503, "temporarily_unavailable", "unreachable",
                RegistrationRejectedException.Kind.TRANSPORT, null)).when(this.service).admit(anyString(), anyList(), anyString(), any());
        this.filter().doFilter(this.request, second, this.chain);
        verify(second).setHeader("Retry-After", "15");
    }

    @Test
    void anUnexpectedFailureIsAServerErrorThatSaysNothingOfItself() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.service.admit(anyString(), anyList(), anyString(), any())).thenThrow(new IllegalStateException("db at 10.0.0.9"));

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(500);
        assertTrue(this.body.toString().contains("server_error"));
        assertFalse(this.body.toString().contains("10.0.0.9"));
    }

    @Test
    void passthroughLeavesAnAuthorizationRefusalToPingFederate() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        this.refusedWith(RegistrationRejectedException.request(400, "invalid_request", "no proof"));
        AutoRegistrationSettings passthrough = new AutoRegistrationSettings(true, false, true, "openid", false, true, 65_536, 8, 2_000L, null);

        this.filter(true, passthrough).doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verify(this.response, never()).setStatus(anyInt());
    }

    @Test
    void failOpenPassesEveryRefusalOn() throws Exception {
        this.par();
        when(this.request.getParameter("client_id")).thenReturn(RP);
        this.refusedWith(RegistrationRejectedException.request(401, "invalid_client", "forged"));

        this.filter(false, AutoRegistrationSettings.DEFAULTS).doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
        verify(this.response, never()).setStatus(anyInt());
    }

    // ---- whose request an audit record names ------------------------------------------------------------

    @Test
    void whatTheRegistrationAuditsCarriesTheCallersAddressAndTheScopeEndsWithTheRequest() throws Exception {
        try (AuditCapture audit = AuditCapture.install()) {
            this.par();
            when(this.request.getParameter("client_id")).thenReturn(RP);
            when(this.request.getRemoteAddr()).thenReturn("198.51.100.30");
            when(this.service.admit(anyString(), anyList(), anyString(), any())).thenAnswer(call -> {
                FederationEvents.event(FederationEvents.REGISTRATION_REFUSED).failure("invalid_trust_chain").subject(RP).audit().emit();
                throw new RegistrationRejectedException(400, "invalid_trust_chain", "no route to a trusted anchor",
                        RegistrationRejectedException.Kind.TRUST, null);
            });

            this.filter().doFilter(this.request, this.response, this.chain);

            verify(this.response).setStatus(400);
            assertEquals("198.51.100.30", audit.only(FederationEvents.REGISTRATION_REFUSED).remoteAddress());
            assertNull(PfRequestScope.current());
        }
    }

    @Test
    void pingFederatesHandlingIsInsideTheScopeAndAFailureThereStillEndsIt() throws Exception {
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getRemoteAddr()).thenReturn("198.51.100.30");
        AtomicReference<PfRequestScope.Context> during = new AtomicReference<>();
        doAnswer(call -> {
            during.set(PfRequestScope.current());
            throw new ServletException("PingFederate failed");
        }).when(this.chain).doFilter(this.request, this.response);

        assertThrows(ServletException.class, () -> this.filter().doFilter(this.request, this.response, this.chain));

        assertEquals("198.51.100.30", during.get().remoteAddress());
        assertNull(PfRequestScope.current(), "a pooled thread must not carry this caller's address into its next request");
    }

    // ---- init ------------------------------------------------------------------------------------------

    @Test
    void offMeansOff() throws Exception {
        System.setProperty("oidf.auto.registration.front.channel", "false");
        FrontChannelAutoRegistrationFilter filter = new FrontChannelAutoRegistrationFilter();

        filter.init(mock(FilterConfig.class));
        filter.doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
    }

    @Test
    void withoutPinnedAnchorKeysNothingIsRegisteredButTheWebAppKeepsServing() throws Exception {
        System.setProperty("oidf.federation.trust.controller.host", "https://anchor.example");
        FrontChannelAutoRegistrationFilter filter = new FrontChannelAutoRegistrationFilter();

        assertDoesNotThrow(() -> filter.init(mock(FilterConfig.class)));
        filter.doFilter(this.request, this.response, this.chain);

        verify(this.chain).doFilter(this.request, this.response);
    }

    @Test
    void anErrorPageThatCannotBeReadStopsTheFilterStarting() throws Exception {
        pinAnchor();
        System.setProperty("oidf.federation.error.page", "/nonexistent/oidf-error.html");

        ServletException e = assertThrows(ServletException.class, () -> new FrontChannelAutoRegistrationFilter().init(mock(FilterConfig.class)));
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.FEDERATION_ERROR_PAGE_ENV), e.getMessage());
    }

    @Test
    void anUnusableConfigurationStopsTheFilterStarting() throws Exception {
        pinAnchor();
        FilterConfig config = mock(FilterConfig.class);
        when(config.getInitParameter("subordinateStatementCacheMaxEntries")).thenReturn("lots");

        ServletException e = assertThrows(ServletException.class, () -> new FrontChannelAutoRegistrationFilter().init(config));
        assertTrue(e.getMessage().contains("subordinateStatementCacheMaxEntries"), e.getMessage());
    }

    @Test
    void startsWhenTheAnchorIsPinned() throws Exception {
        pinAnchor();
        FrontChannelAutoRegistrationFilter filter = new FrontChannelAutoRegistrationFilter();

        assertDoesNotThrow(() -> filter.init(mock(FilterConfig.class)));
        this.filter().init(mock(FilterConfig.class));
        filter.destroy();
    }

    private static void pinAnchor() throws Exception {
        EllipticCurveJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        System.setProperty("oidf.federation.trust.controller.host", "https://anchor.example");
        System.setProperty("oidf.federation.trust.anchor.jwks", "{\"keys\":[" + anchor.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");
        FederationRuntimeConfig.resetForTests();
    }

    @Test
    void clientIdOfReadsTheParameterThenTheAssertion() throws Exception {
        assertNull(FrontChannelAutoRegistrationFilter.clientIdOf(this.request, null));
        assertEquals(RP, FrontChannelAutoRegistrationFilter.clientIdOf(this.request, signed(Map.of("sub", RP), null)));
        when(this.request.getParameter("client_id")).thenReturn(" ");
        assertEquals(RP, FrontChannelAutoRegistrationFilter.clientIdOf(this.request, signed(Map.of("sub", RP), null)));
        assertNull(FrontChannelAutoRegistrationFilter.clientIdOf(this.request, " "));
        when(this.request.getParameter("client_id")).thenReturn(RP);
        assertEquals(RP, FrontChannelAutoRegistrationFilter.clientIdOf(this.request, signed(Map.of("sub", "https://other.example"), null)));
    }

    @Test
    void withNoTrustControllerAtAllTheFilterDoesNotStart() {
        ServletException e = assertThrows(ServletException.class, () -> new FrontChannelAutoRegistrationFilter().init(mock(FilterConfig.class)));
        assertTrue(e.getMessage().contains("automatic registration"), e.getMessage());
    }

    @Test
    void aRequestUriByReferenceIsNeverFollowedHere() throws Exception {
        when(this.request.getRequestURI()).thenReturn(null);
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getParameter("request_uri")).thenReturn(RP + "/request.jwt");
        when(this.request.getParameter("request")).thenReturn(" ");

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.service).frontChannel(eq("authorization"), eq(RP), eq(OP), isNull(), isNull(), any(), any());
    }

    @Test
    void aBlankAssertionAtParIsNoProof() throws Exception {
        this.par();
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.request.getParameter("client_assertion")).thenReturn("  ");

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.service).frontChannel(eq("par"), eq(RP), eq(OP), isNull(), isNull(), any(), any());
    }

    @Test
    void anUnexpectedFailureAtParIsAServerErrorInJson() throws Exception {
        this.par();
        when(this.request.getParameter("client_id")).thenReturn(RP);
        when(this.service.admit(anyString(), anyList(), anyString(), any())).thenThrow(new IllegalStateException("boom"));

        this.filter().doFilter(this.request, this.response, this.chain);

        verify(this.response).setStatus(500);
        assertEquals("server_error", JsonUtil.parseJson(this.body.toString()).get("error"));
    }
}
