/*
 * S-9's floor on the registration and attestation surfaces: an init that fails returns, records its reason, and the
 * gate answers the component's own traffic 503 without calling the chain or the servlet.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.servlet.GateTesting;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SurfaceGateTest {

    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain chain = mock(FilterChain.class);

    @BeforeEach
    @AfterEach
    void reset() throws Exception {
        System.clearProperty("oidf.federation.trust.controller.host");
        System.clearProperty("oidf.federation.trust.anchor.jwks");
        FederationRuntimeConfig.resetForTests();
        java.lang.reflect.Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
    }

    private void assertUnavailable(ByteArrayOutputStream answer) throws Exception {
        verify(this.response).setStatus(503);
        assertTrue(GateTesting.text(answer).startsWith("{\"error\":\"temporarily_unavailable\""), GateTesting.text(answer));
    }

    @Test
    void theFrontChannelFilterWithNoTrustControllerAnswersFederationClients503() throws Exception {
        FrontChannelAutoRegistrationFilter filter = new FrontChannelAutoRegistrationFilter();
        assertDoesNotThrow(() -> filter.init(mock(FilterConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, GateTesting.part("FrontChannelAutoRegistrationFilter").state());
        assertTrue(GateTesting.part("FrontChannelAutoRegistrationFilter").reason().contains(FederationRuntimeConfig.HOST_ENV),
                GateTesting.part("FrontChannelAutoRegistrationFilter").reason());

        ByteArrayOutputStream answer = GateTesting.body(this.response);
        when(this.request.getParameter("client_id")).thenReturn("https://rp.example");
        filter.doFilter(this.request, this.response, this.chain);
        this.assertUnavailable(answer);
        verify(this.chain, never()).doFilter(any(), any());

        // PingFederate's own client goes on to PingFederate.
        HttpServletRequest own = mock(HttpServletRequest.class);
        when(own.getParameter("client_id")).thenReturn("an-ordinary-client");
        filter.doFilter(own, this.response, this.chain);
        verify(this.chain).doFilter(own, this.response);
    }

    @Test
    void theAttestationFilterWithNoBridgeKeyAnswersAttestationTraffic503() throws Exception {
        ClientAttestationAuthFilter filter = new ClientAttestationAuthFilter();
        assertDoesNotThrow(() -> filter.init(null));
        assertEquals(ComponentState.FAILED_CONFIG, GateTesting.part("ClientAttestationAuthFilter").state());
        assertTrue(GateTesting.part("ClientAttestationAuthFilter").reason().contains("OIDF_ATTESTATION_AUTH_ENABLED=false"),
                GateTesting.part("ClientAttestationAuthFilter").reason());

        ByteArrayOutputStream answer = GateTesting.body(this.response);
        when(this.request.getHeader("OAuth-Client-Attestation")).thenReturn("a.b.c");
        filter.doFilter(this.request, this.response, this.chain);
        this.assertUnavailable(answer);
        verify(this.chain, never()).doFilter(any(), any());

        // A request with no attestation is passed on untouched, as the healthy filter passes it.
        HttpServletRequest plain = mock(HttpServletRequest.class);
        filter.doFilter(plain, this.response, this.chain);
        verify(this.chain).doFilter(plain, this.response);
    }

    @Test
    void explicitRegistrationThatDidNotStartAnswers503AndNeverRuns() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter(RegistrationConfiguration.SUBORDINATE_CACHE_MAX_ENTRIES_PARAM)).thenReturn("lots");
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet();
        assertDoesNotThrow(() -> servlet.init(config));
        assertEquals(ComponentState.FAILED_CONFIG, GateTesting.part("OpenIdRegistrationServlet").state());

        ByteArrayOutputStream answer = GateTesting.body(this.response);
        servlet.service(this.request, this.response);
        this.assertUnavailable(answer);
        verify(this.request, never()).getMethod();
    }

    @Test
    void aFilterWithNothingToRegisterWithPassesEverythingOn() throws Exception {
        // Never initialised (no part, so no gate) and no registration service: PingFederate's own endpoint as it was.
        new TokenEndpointAutoRegistrationFilter().doFilter(this.request, this.response, this.chain);
        verify(this.chain).doFilter(this.request, this.response);

        FederationRuntimeConfig.AutoRegistrationSettings settings = new FederationRuntimeConfig.AutoRegistrationSettings(true, false,
                true, "openid", false, true, 65_536, 8, 2_000L, null);
        HttpServletRequest other = mock(HttpServletRequest.class);
        new FrontChannelAutoRegistrationFilter(null, r -> "https://op.example", settings, true, (client, jti, ttl) -> true,
                com.pingidentity.ps.oidf.servlet.oauth.FederationErrorPage.builtIn()).doFilter(other, this.response, this.chain);
        verify(this.chain).doFilter(other, this.response);
    }
}
