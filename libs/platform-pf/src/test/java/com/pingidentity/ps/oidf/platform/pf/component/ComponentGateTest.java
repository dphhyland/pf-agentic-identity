/*
 * S-9's per-surface rules (S9b): what each kind of surface answers while its component is disabled or failed.
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

    private static String b64u(String json) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    private static String jwt(String header, String claims) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(header.getBytes(StandardCharsets.UTF_8)) + "." + b64.encodeToString(claims.getBytes(StandardCharsets.UTF_8))
                + ".c2ln";
    }

    private HttpServletResponse fresh() throws Exception {
        this.body.reset();
        ServletOutputStream out = this.response.getOutputStream();
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(response.getOutputStream()).thenReturn(out);
        return response;
    }

    private static final ComponentState[] FAILED = {ComponentState.STARTING, ComponentState.FAILED_CONFIG,
            ComponentState.FAILED_DEPENDENCY, ComponentState.REFUSED};

    /** A store in which the named clients are federation clients, the ordinary ones are not, and nothing else exists. */
    private static ComponentGate.FederationClients store(java.util.Set<String> federation, java.util.Set<String> ordinary) {
        return id -> federation.contains(id) ? Boolean.TRUE : ordinary.contains(id) ? Boolean.FALSE : null;
    }

    private static final ComponentGate.FederationClients NOBODY = id -> null;

    /** Rules for a filter that authenticates at every endpoint and refuses a client named "required". */
    private static final ComponentGate.AttestationRules RULES = new ComponentGate.AttestationRules() {
        @Override
        public boolean authenticates(HttpServletRequest request) {
            return !"/as/authorization.oauth2".equals(request.getRequestURI());
        }

        @Override
        public boolean refusedWithoutAttestation(HttpServletRequest request, HttpServletResponse response) {
            if ("required".equals(request.getParameter("client_id"))) {
                response.setStatus(401);
                return true;
            }
            return false;
        }
    };

    @Test
    void aServingComponentsSurfacesServe() throws Exception {
        for (ComponentState state : new ComponentState[] {ComponentState.READY, ComponentState.DEGRADED}) {
            ComponentParts.Part part = this.part(state);
            assertFalse(ComponentGate.federationEndpoint(part, this.response));
            assertFalse(ComponentGate.oauthEndpoint(part, this.response));
            assertFalse(ComponentGate.filter(part, this.request, this.response, this.chain, ComponentGate::everyRequest));
            assertFalse(ComponentGate.autoRegistration(part, this.request, this.response, this.chain, NOBODY));
            assertFalse(ComponentGate.attestation(part, this.request, this.response, this.chain, RULES));
            assertTrue(ComponentGate.emits(part));
        }
        verifyNoInteractions(this.chain);
        verify(this.response, never()).setStatus(any(Integer.class));
    }

    @Test
    void noPartMeansInitNeverRanAndTheGateStandsAside() throws Exception {
        assertFalse(ComponentGate.federationEndpoint(null, this.response));
        assertFalse(ComponentGate.oauthEndpoint(null, this.response));
        assertFalse(ComponentGate.filter(null, this.request, this.response, this.chain, ComponentGate::everyRequest));
        assertFalse(ComponentGate.autoRegistration(null, this.request, this.response, this.chain, NOBODY));
        assertFalse(ComponentGate.attestation(null, this.request, this.response, this.chain, RULES));
        assertTrue(ComponentGate.emits(null));
        verifyNoInteractions(this.chain, this.response);
    }

    @Test
    void aFailedEndpointAnswers503WithTheErrorBodyAndNeverRuns() throws Exception {
        for (ComponentState state : FAILED) {
            HttpServletResponse response = this.fresh();
            assertTrue(ComponentGate.federationEndpoint(this.part(state), response), state.name());
            verify(response).setStatus(503);
            verify(response).setContentType("application/json");
            verify(response).setHeader("Cache-Control", "no-store");
            assertEquals("{\"error\":\"temporarily_unavailable\",\"error_description\":\"AUTO_REGISTRATION is not available\"}", this.body());

            response = this.fresh();
            assertTrue(ComponentGate.oauthEndpoint(this.part(state), response), state.name());
            verify(response).setStatus(503);
            assertEquals("{\"error\":\"temporarily_unavailable\",\"error_description\":\"AUTO_REGISTRATION is not available\"}", this.body());
        }
    }

    @Test
    void aDisabledFederationEndpointAnswers404NotFoundAndAnOAuthOne404WithNoBody() throws Exception {
        assertTrue(ComponentGate.federationEndpoint(this.part(ComponentState.DISABLED), this.response));
        verify(this.response).setStatus(404);
        assertEquals("{\"error\":\"not_found\",\"error_description\":\"no such endpoint\"}", this.body());

        HttpServletResponse response = this.fresh();
        assertTrue(ComponentGate.oauthEndpoint(this.part(ComponentState.DISABLED), response));
        verify(response).setStatus(404);
        verify(response).setContentLength(0);
        verify(response).setHeader("Cache-Control", "no-store");
        assertEquals("", this.body());
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
        assertFalse(ComponentGate.federationEndpoint(entity, this.response), "the Entity Configuration keeps serving");
        assertTrue(ComponentGate.federationEndpoint(registration, this.response));
        verify(this.response).setStatus(503);

        registration.refused("a forbidden setting");
        HttpServletResponse refused = this.fresh();
        assertTrue(ComponentGate.federationEndpoint(entity, refused), "a violation refuses the whole component");
        verify(refused).setStatus(503);
    }

    @Test
    void theGateReadsThePublishedViewOfTheLatestRegistration() {
        ComponentParts.Part first = this.part(ComponentState.FAILED_CONFIG);
        assertEquals(ComponentState.FAILED_CONFIG, first.gateView().state());
        this.parts.begin("AUTO_REGISTRATION", "TokenEndpointAutoRegistrationFilter").ready();
        // A later registration of the same part is what the earlier handle's gate sees, as status() does.
        assertEquals(ComponentState.READY, first.gateView().state());
        assertFalse(first.gateView().componentRefused());
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
        assertTrue(ComponentGate.autoRegistration(part, plain, plainResponse, this.chain, NOBODY));
        verify(this.chain, org.mockito.Mockito.times(2)).doFilter(plain, plainResponse);
        assertTrue(ComponentGate.autoRegistration(part, this.request, plainResponse, this.chain, NOBODY));
        verify(this.chain, org.mockito.Mockito.times(2)).doFilter(this.request, plainResponse);
        assertTrue(ComponentGate.attestation(part, plain, plainResponse, this.chain, RULES));
        verify(this.chain, org.mockito.Mockito.times(3)).doFilter(plain, plainResponse);
        assertTrue(ComponentGate.attestation(part, this.request, plainResponse, this.chain, RULES));
        verify(this.chain, org.mockito.Mockito.times(3)).doFilter(this.request, plainResponse);
    }

    @Test
    void automaticRegistrationDisabledRefusesAFederationClient401AndPassesTheRest() throws Exception {
        ComponentParts.Part part = this.part(ComponentState.DISABLED);
        ComponentGate.FederationClients clients = store(java.util.Set.of("https://rp.example"), java.util.Set.of("https://app.example"));
        when(this.request.getParameter("client_id")).thenReturn("https://rp.example");
        assertTrue(ComponentGate.autoRegistration(part, this.request, this.response, this.chain, clients));
        verify(this.response).setStatus(401);
        assertTrue(this.body().startsWith("{\"error\":\"invalid_client\""), this.body());
        verify(this.chain, never()).doFilter(any(), any());

        // PingFederate's own clients - one with a plain id, one whose id happens to be an https URL - go on.
        for (String id : new String[] {"an-ordinary-client", "https://app.example"}) {
            HttpServletRequest own = mock(HttpServletRequest.class);
            when(own.getParameter("client_id")).thenReturn(id);
            assertTrue(ComponentGate.autoRegistration(part, own, this.response, this.chain, clients));
            verify(this.chain).doFilter(own, this.response);
        }
    }

    @Test
    void automaticRegistrationFailedAnswersAFederationClient503AndPassesTheRest() throws Exception {
        ComponentGate.FederationClients clients = store(java.util.Set.of(), java.util.Set.of("https://app.example"));
        for (ComponentState state : FAILED) {
            ComponentParts.Part part = this.part(state);
            HttpServletResponse response = this.fresh();
            HttpServletRequest unknown = mock(HttpServletRequest.class);
            when(unknown.getParameter("client_id")).thenReturn("https://rp.example");
            assertTrue(ComponentGate.autoRegistration(part, unknown, response, this.chain, clients), state.name());
            verify(response).setStatus(503);

            HttpServletRequest own = mock(HttpServletRequest.class);
            when(own.getParameter("client_id")).thenReturn("https://app.example");
            assertTrue(ComponentGate.autoRegistration(part, own, response, this.chain, clients));
            verify(this.chain).doFilter(own, response);
        }
    }

    @Test
    void aStoreThatCannotAnswerIs503WhetherDisabledOrFailed() throws Exception {
        ComponentGate.FederationClients broken = id -> {
            throw new IllegalStateException("the client manager is down");
        };
        when(this.request.getParameter("client_id")).thenReturn("https://rp.example");
        for (ComponentState state : new ComponentState[] {ComponentState.DISABLED, ComponentState.FAILED_CONFIG}) {
            HttpServletResponse response = this.fresh();
            assertTrue(ComponentGate.autoRegistration(this.part(state), this.request, response, this.chain, broken));
            verify(response).setStatus(503);
        }
        verify(this.chain, never()).doFilter(any(), any());
    }

    @Test
    void theFederationClientSignals() {
        ComponentGate.FederationClients clients = store(java.util.Set.of("https://rp.example"), java.util.Set.of("https://app.example"));
        // PingFederate's own client, by id and by an assertion about it: no lookup for an id that is not a URL.
        ComponentGate.FederationClients never = id -> {
            throw new AssertionError("looked up " + id);
        };
        when(this.request.getParameter("client_id")).thenReturn("an-ordinary-client");
        assertEquals(ComponentGate.Named.ORDINARY, ComponentGate.namesFederationClient(this.request, never));
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"an-ordinary-client\"}"));
        assertEquals(ComponentGate.Named.ORDINARY, ComponentGate.namesFederationClient(this.request, never));

        // A trust_chain header, whoever it names.
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\",\"trust_chain\":[]}", "{\"sub\":\"x\"}"));
        assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, never));

        // An assertion whose sub is a stored federation client, an unknown Entity Identifier, an ordinary https client.
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"https://rp.example\"}"));
        assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, clients));
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"https://new.example\"}"));
        assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, clients));
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{\"sub\":\"https://app.example\"}"));
        assertEquals(ComponentGate.Named.ORDINARY, ComponentGate.namesFederationClient(this.request, clients));
        // The same federation assertion in the standard base64 alphabet, padded, as jose4j (and so a healthy filter) reads it.
        String standard = "{\"sub\":\"https://rp.example\",\"n\":\"???\"}";
        String std = Base64.getEncoder().encodeToString(standard.getBytes(StandardCharsets.UTF_8));
        assertTrue(std.contains("/") || std.contains("+"), std);
        when(this.request.getParameter("client_assertion")).thenReturn(b64u("{\"alg\":\"RS256\"}") + "." + std + ".sig");
        assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, clients));

        // An assertion without a sub is judged by client_id.
        when(this.request.getParameter("client_assertion")).thenReturn(jwt("{\"alg\":\"RS256\"}", "{}"));
        assertEquals(ComponentGate.Named.ORDINARY, ComponentGate.namesFederationClient(this.request, never));

        // An assertion the gate cannot read is the component's traffic, whatever client_id says: it fails closed.
        for (String unreadable : new String[] {jwt("{\"alg\":\"RS256\"}", "{\"sub\":42}"), jwt("[1]", "{\"sub\":\"x\"}"),
                jwt("{\"alg\":\"RS256\"}", "[2]"), "not a jwt"}) {
            when(this.request.getParameter("client_assertion")).thenReturn(unreadable);
            assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, never), unreadable);
        }

        // No assertion: client_id, then the attestation's sub, decide.
        when(this.request.getParameter("client_assertion")).thenReturn(null);
        when(this.request.getParameter("client_id")).thenReturn("https://rp.example");
        assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, clients));
        when(this.request.getParameter("client_id")).thenReturn(null);
        assertEquals(ComponentGate.Named.ORDINARY, ComponentGate.namesFederationClient(this.request, never));
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.enumeration(
                java.util.List.of(jwt("{\"alg\":\"ES256\"}", "{\"sub\":\"https://rp.example\"}"))));
        assertEquals(ComponentGate.Named.FEDERATION, ComponentGate.namesFederationClient(this.request, clients));

        // A store that cannot answer, for any name that needs it.
        when(this.request.getParameter("client_id")).thenReturn("https://app.example");
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(null);
        assertEquals(ComponentGate.Named.UNKNOWN, ComponentGate.namesFederationClient(this.request, id -> {
            throw new Exception("down");
        }));
    }

    @Test
    void theAttestedClientIsTheSubOfTheOneAttestation() {
        assertNull(ComponentGate.attestedClient(this.request));
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.emptyEnumeration());
        assertNull(ComponentGate.attestedClient(this.request));
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.enumeration(java.util.List.of(" ")));
        assertNull(ComponentGate.attestedClient(this.request));
        String one = jwt("{\"alg\":\"ES256\"}", "{\"sub\":\"https://rp.example\"}");
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.enumeration(java.util.List.of(one, one)));
        assertNull(ComponentGate.attestedClient(this.request));
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.enumeration(
                java.util.List.of(jwt("{\"alg\":\"ES256\"}", "{\"sub\":7}"))));
        assertNull(ComponentGate.attestedClient(this.request));
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.enumeration(java.util.List.of("x.y.z")));
        assertNull(ComponentGate.attestedClient(this.request));
        when(this.request.getHeaders("OAuth-Client-Attestation")).thenReturn(java.util.Collections.enumeration(java.util.List.of(one)));
        assertEquals("https://rp.example", ComponentGate.attestedClient(this.request));
    }

    @Test
    void attestationDisabledTellsAClientThatSendsOneThatThisServerDoesNotAcceptThem() throws Exception {
        ComponentParts.Part part = this.part(ComponentState.DISABLED);
        when(this.request.getHeader("OAuth-Client-Attestation")).thenReturn("a.b.c");
        when(this.request.getHeader("Authorization")).thenReturn("Basic Y2xpZW50OnNlY3JldA==");
        assertTrue(ComponentGate.attestation(part, this.request, this.response, this.chain, RULES));
        verify(this.response).setStatus(401);
        verify(this.response).setHeader("WWW-Authenticate", "Basic");
        assertTrue(this.body().startsWith("{\"error\":\"invalid_client\""), this.body());
        verify(this.chain, never()).doFilter(any(), any());
    }

    @Test
    void attestationFailedAnswersAttestationTraffic503() throws Exception {
        for (ComponentState state : FAILED) {
            HttpServletResponse response = this.fresh();
            HttpServletRequest attested = mock(HttpServletRequest.class);
            when(attested.getHeader("OAuth-Client-Attestation-PoP")).thenReturn("a.b.c");
            assertTrue(ComponentGate.attestation(this.part(state), attested, response, this.chain, RULES), state.name());
            verify(response).setStatus(503);
            verify(response, never()).setHeader(org.mockito.ArgumentMatchers.eq("WWW-Authenticate"), any());
        }
        verify(this.chain, never()).doFilter(any(), any());
    }

    @Test
    void attestationDisabledOrFailedRefusesAClientThatRequiresOneAndPassesTheRest() throws Exception {
        for (ComponentState state : new ComponentState[] {ComponentState.DISABLED, ComponentState.FAILED_CONFIG}) {
            ComponentParts.Part part = this.part(state);
            HttpServletResponse response = this.fresh();
            HttpServletRequest required = mock(HttpServletRequest.class);
            when(required.getParameter("client_id")).thenReturn("required");
            assertTrue(ComponentGate.attestation(part, required, response, this.chain, RULES));
            verify(response).setStatus(401);
            verify(this.chain, never()).doFilter(required, response);

            HttpServletRequest ordinary = mock(HttpServletRequest.class);
            when(ordinary.getParameter("client_id")).thenReturn("ordinary");
            assertTrue(ComponentGate.attestation(part, ordinary, response, this.chain, RULES));
            verify(this.chain).doFilter(ordinary, response);

            // Where the filter authenticates nobody - the authorization endpoint - even attestation headers pass on.
            HttpServletRequest browser = mock(HttpServletRequest.class);
            when(browser.getRequestURI()).thenReturn("/as/authorization.oauth2");
            when(browser.getHeader("OAuth-Client-Attestation")).thenReturn("a.b.c");
            when(browser.getParameter("client_id")).thenReturn("required");
            assertTrue(ComponentGate.attestation(part, browser, response, this.chain, RULES));
            verify(this.chain).doFilter(browser, response);
        }
    }

    @Test
    void aChallengeNamesOnlyASchemeThatIsAToken() {
        HttpServletResponse response = mock(HttpServletResponse.class);
        when(this.request.getHeader("Authorization")).thenReturn(null);
        ComponentGate.challenge(this.request, response);
        when(this.request.getHeader("Authorization")).thenReturn("B@d\u0000Scheme x");
        ComponentGate.challenge(this.request, response);
        when(this.request.getHeader("Authorization")).thenReturn("x".repeat(33) + " y");
        ComponentGate.challenge(this.request, response);
        verify(response, never()).setHeader(any(), any());
        when(this.request.getHeader("Authorization")).thenReturn("  DPoP abc");
        ComponentGate.challenge(this.request, response);
        verify(response).setHeader("WWW-Authenticate", "DPoP");
    }

    @Test
    void aDisabledOrFailedComponentOnlyStopsTheEmission() {
        assertFalse(ComponentGate.emits(this.part(ComponentState.DISABLED)));
        for (ComponentState state : FAILED) {
            assertFalse(ComponentGate.emits(this.part(state)), state.name());
        }
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
        String padded = Base64.getEncoder().encodeToString("{\"a\":\"bc\"}".getBytes(StandardCharsets.UTF_8));
        assertTrue(padded.endsWith("="), padded);
        assertEquals("bc", ComponentGate.jwtPart(padded.substring(0, 4) + "\n" + padded.substring(4) + ".e30.c", 0).get("a"));
    }
}
