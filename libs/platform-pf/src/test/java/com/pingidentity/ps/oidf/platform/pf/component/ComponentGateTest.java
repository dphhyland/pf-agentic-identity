/*
 * S-9's fail-closed floor: what a surface answers while its component is not serving.
 */
package com.pingidentity.ps.oidf.platform.pf.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class ComponentGateTest {

    private final ComponentParts parts = new ComponentParts(new ComponentRegistry(), Clock.systemUTC());
    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final ByteArrayOutputStream body = new ByteArrayOutputStream();

    ComponentGateTest() throws Exception {
        when(this.response.getOutputStream()).thenReturn(new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener listener) {
            }

            @Override
            public void write(int b) {
                ComponentGateTest.this.body.write(b);
            }
        });
    }

    private ComponentParts.Part part(ComponentState state) {
        ComponentParts.Part part = this.parts.begin("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter");
        switch (state) {
            case READY -> part.ready();
            case DEGRADED -> part.degraded("the anchor's keys are not pinned");
            case FAILED_CONFIG -> part.failedConfig("no trust controller");
            case FAILED_DEPENDENCY -> part.failedDependency("the store is down");
            case REFUSED -> part.refused("a forbidden setting");
            case DISABLED -> part.disabled();
            default -> { }
        }
        return part;
    }

    private String body() {
        return this.body.toString(StandardCharsets.UTF_8);
    }

    private static String jwt(String header, String claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString(claims.getBytes(StandardCharsets.UTF_8))
                + ".c2ln";
    }

    @Test
    void aServingComponentsSurfacesServe() throws Exception {
        for (ComponentState state : new ComponentState[] {ComponentState.READY, ComponentState.DEGRADED}) {
            ComponentParts.Part part = this.part(state);
            assertFalse(ComponentGate.servlet(part, this.response));
            assertFalse(ComponentGate.filter(part, this.request, this.response, this.chain, ComponentGate::everyRequest));
        }
        verifyNoInteractions(this.chain);
        verify(this.response, never()).setStatus(any(Integer.class));
    }

    @Test
    void noPartMeansInitNeverRanAndTheGateStandsAside() throws Exception {
        assertFalse(ComponentGate.servlet(null, this.response));
        assertFalse(ComponentGate.filter(null, this.request, this.response, this.chain, ComponentGate::everyRequest));
        verifyNoInteractions(this.chain, this.response);
    }

    @Test
    void aServletWhoseComponentIsNotServingAnswers503AndNeverRuns() throws Exception {
        for (ComponentState state : new ComponentState[] {ComponentState.STARTING, ComponentState.FAILED_CONFIG,
                ComponentState.FAILED_DEPENDENCY, ComponentState.REFUSED}) {
            this.body.reset();
            ServletOutputStream out = this.response.getOutputStream();
            HttpServletResponse response = mock(HttpServletResponse.class);
            when(response.getOutputStream()).thenReturn(out);
            assertTrue(ComponentGate.servlet(this.part(state), response), state.name());
            verify(response).setStatus(503);
            verify(response).setContentType("application/json");
            verify(response).setHeader("Cache-Control", "no-store");
            assertEquals("{\"error\":\"temporarily_unavailable\",\"error_description\":\"AUTO_REGISTRATION is not available\"}", this.body());
        }
    }

    @Test
    void aDisabledServletAnswers404AsAWarWithoutItWould() throws Exception {
        assertTrue(ComponentGate.servlet(this.part(ComponentState.DISABLED), this.response));
        verify(this.response).setStatus(404);
        assertEquals("{\"error\":\"not_found\",\"error_description\":\"no such endpoint\"}", this.body());
    }

    @Test
    void aDisabledPartIsOffWhateverItsComponentsOtherPartsAreDoing() throws Exception {
        ComponentParts.Part front = this.parts.begin("AUTO_REGISTRATION", "FrontChannelAutoRegistrationFilter");
        front.disabled();
        this.parts.begin("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter").failedConfig("no trust controller");
        assertTrue(ComponentGate.filter(front, this.request, this.response, this.chain, ComponentGate::everyRequest));
        verify(this.chain).doFilter(this.request, this.response);
    }

    @Test
    void aPartThatStartedServesWhileASiblingHasFailedButNotWhileOneIsRefused() throws Exception {
        ComponentParts.Part entity = this.parts.begin("FEDERATION", "OpenIdFederationServlet");
        entity.ready();
        ComponentParts.Part registration = this.parts.begin("FEDERATION", "OpenIdRegistrationServlet");
        registration.failedConfig("the anchor's keys are not pinned");
        assertFalse(ComponentGate.servlet(entity, this.response), "the Entity Configuration keeps serving");
        assertTrue(ComponentGate.servlet(registration, this.response));
        verify(this.response).setStatus(503);

        registration.refused("a forbidden setting");
        ServletOutputStream out = this.response.getOutputStream();
        HttpServletResponse refused = mock(HttpServletResponse.class);
        when(refused.getOutputStream()).thenReturn(out);
        assertTrue(ComponentGate.servlet(entity, refused), "a violation refuses the whole component");
        verify(refused).setStatus(503);
    }

    @Test
    void aDisabledComponentsFilterPassesEveryRequestOn() throws Exception {
        assertTrue(ComponentGate.filter(this.part(ComponentState.DISABLED), this.request, this.response, this.chain,
                ComponentGate::everyRequest));
        verify(this.chain).doFilter(this.request, this.response);
        verify(this.response, never()).setStatus(any(Integer.class));
    }

    @Test
    void aFailedComponentsFilterAnswersItsOwnTraffic503AndPassesTheRestOn() throws Exception {
        ComponentParts.Part part = this.part(ComponentState.FAILED_CONFIG);
        assertTrue(ComponentGate.filter(part, this.request, this.response, this.chain, r -> true));
        verify(this.response).setStatus(503);
        verify(this.chain, never()).doFilter(any(), any());
        assertTrue(this.body().contains("\"temporarily_unavailable\""), this.body());

        HttpServletRequest other = mock(HttpServletRequest.class);
        assertTrue(ComponentGate.filter(part, other, this.response, this.chain, r -> false));
        verify(this.chain).doFilter(other, this.response);
    }

    @Test
    void aRequestThatIsNotHttpIsPassedOn() throws Exception {
        ServletRequest plain = mock(ServletRequest.class);
        ServletResponse plainResponse = mock(ServletResponse.class);
        ComponentParts.Part part = this.part(ComponentState.FAILED_CONFIG);
        assertTrue(ComponentGate.filter(part, plain, plainResponse, this.chain, r -> true));
        verify(this.chain).doFilter(plain, plainResponse);
        assertTrue(ComponentGate.filter(part, this.request, plainResponse, this.chain, r -> true));
        verify(this.chain).doFilter(this.request, plainResponse);
    }

    @Test
    void attestationTrafficCarriesTheAttestationOrItsProof() {
        assertFalse(ComponentGate.attestationTraffic(this.request));
        when(this.request.getHeader("OAuth-Client-Attestation")).thenReturn(" ");
        assertFalse(ComponentGate.attestationTraffic(this.request));
        when(this.request.getHeader("OAuth-Client-Attestation-PoP")).thenReturn("a.b.c");
        assertTrue(ComponentGate.attestationTraffic(this.request));
        when(this.request.getHeader("OAuth-Client-Attestation")).thenReturn("a.b.c");
        when(this.request.getHeader("OAuth-Client-Attestation-PoP")).thenReturn(null);
        assertTrue(ComponentGate.attestationTraffic(this.request));
    }

    @Test
    void federationClientTrafficNamesAnEntityIdentifierOrCarriesATrustChain() {
        // PingFederate's own client, by id and by an assertion about it.
        when(this.request.getParameter("client_id")).thenReturn("an-ordinary-client");
        assertFalse(ComponentGate.federationClientTraffic(this.request));
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"an-ordinary-client\"}"));
        assertFalse(ComponentGate.federationClientTraffic(this.request));

        // A trust_chain header, whoever it names.
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\",\"trust_chain\":[]}", "{\"sub\":\"x\"}"));
        assertTrue(ComponentGate.federationClientTraffic(this.request));

        // An assertion whose sub is an Entity Identifier.
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"https://rp.example\"}"));
        assertTrue(ComponentGate.federationClientTraffic(this.request));
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":42}"));
        assertFalse(ComponentGate.federationClientTraffic(this.request));
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("[1]", "[2]"));
        assertFalse(ComponentGate.federationClientTraffic(this.request));

        // An assertion that cannot be read is judged by client_id.
        when(this.request.getParameter("client_assertion")).thenReturn("not a jwt");
        assertFalse(ComponentGate.federationClientTraffic(this.request));
        when(this.request.getParameter("client_id")).thenReturn("https://rp.example");
        assertTrue(ComponentGate.federationClientTraffic(this.request));

        when(this.request.getParameter("client_assertion")).thenReturn(null);
        when(this.request.getParameter("client_id")).thenReturn(null);
        assertFalse(ComponentGate.federationClientTraffic(this.request));
    }

    @Test
    void anEntityIdentifierIsAnHttpsUrlWithAHost() {
        assertTrue(ComponentGate.entityIdentifier("https://rp.example"));
        assertTrue(ComponentGate.entityIdentifier(" HTTPS://rp.example/path "));
        assertFalse(ComponentGate.entityIdentifier("http://rp.example"));
        assertFalse(ComponentGate.entityIdentifier("https:///no-host"));
        assertFalse(ComponentGate.entityIdentifier("urn:client:1"));
        assertFalse(ComponentGate.entityIdentifier("client-1"));
        assertFalse(ComponentGate.entityIdentifier("https://bad host"));
    }

    @Test
    void aJwtPartIsReadOnlyWhenItIsAJsonObject() {
        assertNull(ComponentGate.jwtPart("a.b", 0));
        assertNull(ComponentGate.jwtPart("!!!.b.c", 0));
        assertNull(ComponentGate.jwtPart(jwt("\"text\"", "{}"), 0));
        assertEquals("RS256", ComponentGate.jwtPart(jwt("{\"alg\":\"RS256\"}", "{}"), 0).get("alg"));
    }
}
