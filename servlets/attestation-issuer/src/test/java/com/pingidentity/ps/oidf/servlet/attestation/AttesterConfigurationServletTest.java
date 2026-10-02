/*
 * The /.well-known/client-attester document advertises the issuance contract.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

class AttesterConfigurationServletTest {

    private static final String BUNDLE = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\","
            + "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\","
            + "\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"kid\":\"bundle-1\"}]}";

    private static AttestationIssuanceConfig demoConfig() throws IssuanceException {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, "https://attester.example.com");
        props.put(AttestationIssuanceConfig.P_BUNDLE, BUNDLE);
        props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, "gke.banking.demo");
        props.put(AttestationIssuanceConfig.P_ENTITLEMENT,
                "[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]");
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"spiffe_id\":\"spiffe://gke.banking.demo/ns/demo/sa/payment-agent\","
                + "\"entitlement\":[{\"type\":\"sales_agent\",\"sales_regions\":[\"EMEA\"]}]}]");
        return AttestationIssuanceConfig.fromProperties(props);
    }

    /**
     * RFC 8414 §3 (read 2026-10-01): the metadata is at "a path formed by inserting a well-known URI string into the
     * authorization server's issuer identifier between the host component and the path component, if any", after "any
     * terminating "/" MUST be removed".
     */
    @Test
    @Requirement("RFC8414 §3")
    void theAuthorizationServersMetadataIsWhereRfc8414PutsIt() {
        assertEquals("https://pf.example.com/.well-known/oauth-authorization-server",
                AttesterConfigurationServlet.authorizationServerMetadata("https://pf.example.com"));
        assertEquals("https://pf.example.com:9031/.well-known/oauth-authorization-server",
                AttesterConfigurationServlet.authorizationServerMetadata("https://pf.example.com:9031/"));
        assertEquals("https://example.com/.well-known/oauth-authorization-server/issuer1",
                AttesterConfigurationServlet.authorizationServerMetadata("https://example.com/issuer1/"));
        for (String notAnIssuer : new String[] {null, "https://pf.example.com/?q=1", "https://pf.example.com/#f", "urn:example:as",
                "/relative", "https://pf example.com"}) {
            assertNull(AttesterConfigurationServlet.authorizationServerMetadata(notAnIssuer), String.valueOf(notAnIssuer));
        }
        Map<String, Object> noPointer = AttesterConfigurationServlet.metadata("https://pf.example.com", true, false, "urn:example:as");
        assertFalse(noPointer.containsKey("authorization_servers"), "no issuer the client could fetch metadata for, so no pointer");
    }

    @Test
    @Requirement("CAS §4.3")
    void globalDocumentAdvertisesEndpointsAndProofRequirements() {
        Map<String, Object> m = AttesterConfigurationServlet.metadata("https://pf.example.com", true, false);

        assertEquals("https://pf.example.com/federation/attestation", m.get("attestation_endpoint"));
        assertEquals("https://pf.example.com/federation/attestation/challenge", m.get("challenge_endpoint"),
                "the attester's own challenge endpoint, not the authorization server's");
        assertEquals("https://pf.example.com/as/token.oauth2", m.get("token_endpoint"));
        assertEquals(List.of("attest_jwt_client_auth"), m.get("token_endpoint_auth_methods_supported"));
        assertEquals(Boolean.TRUE, m.get("challenge_required"));
        // The advertised set is the registry's, not a list restated here — that is the point of the
        // registry. Assert the identity, plus that the known built-ins are all present.
        assertEquals(InstanceAttestationValidators.defaults().ids(), m.get("evidence_types_supported"));
        @SuppressWarnings("unchecked")
        List<String> advertised = (List<String>) m.get("evidence_types_supported");
        assertTrue(advertised.containsAll(List.of("spiffe-jwt", "gke-sa-token", "gcp-id-token",
                "eks-sa-token", "aws-sts-web-identity", "wallet-instance-attestation")));
        assertEquals("https://pf.example.com/federation/attester-configuration",
                m.get("client_configuration_endpoint"));
        assertEquals("oauth-attestation-instance-proof+jwt", m.get("instance_proof_typ"));
        assertEquals("oauth-client-attestation+jwt", m.get("attestation_typ"));
        assertEquals(300L, m.get("instance_proof_max_age_seconds"));

        @SuppressWarnings("unchecked")
        List<String> algs = (List<String>) m.get("instance_proof_signing_alg_values_supported");
        assertTrue(algs.contains("ES256"));
        assertFalse(algs.contains("none"), "no unsigned algorithms advertised");
        // No client-specific fields without ?client_id.
        assertNull(m.get("issuer"));
        assertNull(m.get("evidence_audience"));
    }

    @Test
    void agentIdSupportedReflectsTheGivenFlagInEitherDirection() {
        assertEquals(Boolean.FALSE,
                AttesterConfigurationServlet.metadata("https://pf.example.com", true, false).get("agent_id_supported"));
        assertEquals(Boolean.TRUE,
                AttesterConfigurationServlet.metadata("https://pf.example.com", true, true).get("agent_id_supported"));
    }

    @Test
    void clientViewCarriesAudienceTrustDomainAndTypeNamesOnly() throws Exception {
        Map<String, Object> m = AttesterConfigurationServlet.clientMetadata(demoConfig());

        assertEquals("https://attester.example.com", m.get("issuer"));
        assertEquals("https://attester.example.com", m.get("evidence_audience"));
        assertEquals("spiffe-jwt", m.get("evidence_type"));
        assertEquals("gke.banking.demo", m.get("spiffe_trust_domain"));
        assertEquals(300L, m.get("attestation_ttl_seconds"));
        assertEquals(List.of("sales_agent"), m.get("authorization_details_types"));
        // The ceiling, bindings, and signing config must not leak.
        String json = JsonUtil.toJson(m);
        assertFalse(json.contains("sales_regions"), "entitlement ceiling not exposed");
        assertFalse(json.contains("spiffe://"), "bindings not exposed");
        assertFalse(json.contains("signing"), "signing config not exposed");
    }

    /** A resolver whose by-id lookup always fails and whose attestation list is empty. */
    private static IssuanceClientResolver throwingResolver() {
        return new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.invalidClient("unknown client: " + clientId);
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of();
            }
        };
    }

    private static HttpServletRequest baseRequest(String uri) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRequestURI()).thenReturn(uri);
        when(req.getScheme()).thenReturn("http");
        when(req.getServerName()).thenReturn("pingfederate");
        when(req.getServerPort()).thenReturn(9080);
        when(req.getContextPath()).thenReturn("");
        return req;
    }

    @Test
    void unknownClientYields404OnTheConfigurationEndpoint() throws Exception {
        AttesterConfigurationServlet servlet = new AttesterConfigurationServlet();
        servlet.setClientResolver(throwingResolver());

        HttpServletRequest req = baseRequest("/federation/attester-configuration");
        when(req.getParameter("client_id")).thenReturn("nope");
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));

        servlet.doGet(req, resp);

        org.mockito.Mockito.verify(resp).setStatus(404);
        assertEquals("invalid_client", JsonUtil.parseJson(body.toString()).get("error"));
    }

    @Test
    void wellKnownIgnoresClientIdAndStaysStatic() throws Exception {
        AttesterConfigurationServlet servlet = new AttesterConfigurationServlet();
        // resolve(client_id) must NOT be consulted on the well-known path; attestationClients() may be
        // (to advertise the deployment evidence_audience) and is empty here.
        servlet.setClientResolver(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) {
                throw new AssertionError("well-known must not resolve a client");
            }

            @Override
            public java.util.List<com.pingidentity.ps.oidf.issuer.AttesterClient> attestationClients() {
                return java.util.List.of();
            }
        });

        HttpServletRequest req = baseRequest("/.well-known/client-attester");
        when(req.getParameter("client_id")).thenReturn("demo-attest-gke"); // present but must be ignored
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));

        servlet.doGet(req, resp);

        org.mockito.Mockito.verify(resp).setStatus(200);
        Map<String, Object> doc = JsonUtil.parseJson(body.toString());
        assertEquals("http://pingfederate:9080/federation/attester-configuration",
                doc.get("client_configuration_endpoint"));
        assertNull(doc.get("issuer"), "no per-client fields on the well-known document");
        org.mockito.Mockito.verify(resp).setHeader("Cache-Control", "public, max-age=300");
    }

    @Test
    void configurationEndpointRequiresClientId() throws Exception {
        AttesterConfigurationServlet servlet = new AttesterConfigurationServlet();
        HttpServletRequest req = baseRequest("/federation/attester-configuration");
        when(req.getParameter("client_id")).thenReturn(null);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));

        servlet.doGet(req, resp);

        org.mockito.Mockito.verify(resp).setStatus(400);
        assertEquals("invalid_request", JsonUtil.parseJson(body.toString()).get("error"));
    }

    /** A request from {@code remote} carrying {@code headers}, each name to its one value. */
    private static HttpServletRequest from(String remote, Map<String, String> headers) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getRemoteAddr()).thenReturn(remote);
        when(req.getScheme()).thenReturn("http");
        when(req.getServerName()).thenReturn("pingfederate");
        when(req.getServerPort()).thenReturn(9031);
        when(req.getContextPath()).thenReturn("");
        headers.forEach((name, value) -> {
            when(req.getHeader(name)).thenReturn(value);
            when(req.getHeaders(name)).thenAnswer(i -> java.util.Collections.enumeration(List.of(value)));
        });
        return req;
    }

    private static final Map<String, String> FORWARDED = Map.of("X-Forwarded-Proto", "https",
            "X-Forwarded-Host", "attester.proxy.example", "X-Forwarded-Port", "443", "X-Forwarded-For", "192.0.2.1");

    @Test
    void forwardedHeadersFromASenderNotListedAreIgnored() {
        // H-ATT-3, F-0061: before 0.6.0 any caller could make the document name a host of its choosing.
        assertEquals("http://pingfederate:9031", AttesterConfigurationServlet.baseUrl(from("198.51.100.7", FORWARDED)));
    }

    @Test
    void aListedProxysForwardedHeadersNameTheOriginAndDefaultPortsAreOmitted() {
        System.setProperty("oidf.trusted.proxies", "10.0.0.0/8");
        try {
            assertEquals("https://attester.proxy.example", AttesterConfigurationServlet.baseUrl(from("10.1.1.1", FORWARDED)));
            // A per-hop header read at the client's hop: the edge saw https and edge.example:8443.
            HttpServletRequest chained = from("10.1.1.1", Map.of("X-Forwarded-For", "192.0.2.1, 10.2.2.2",
                    "X-Forwarded-Proto", "https, http", "X-Forwarded-Host", "edge.example:8443, inner"));
            when(chained.getContextPath()).thenReturn("/oidf");
            assertEquals("https://edge.example:8443/oidf", AttesterConfigurationServlet.baseUrl(chained));
            // A port the host does not carry is appended; a bracketed IPv6 host with a port is left alone.
            assertEquals("http://attester.example:8080", AttesterConfigurationServlet.baseUrl(from("10.1.1.1",
                    Map.of("X-Forwarded-Host", "attester.example", "X-Forwarded-Port", "8080"))));
            assertEquals("http://[2001:db8::1]:8443", AttesterConfigurationServlet.baseUrl(from("10.1.1.1",
                    Map.of("X-Forwarded-Host", "[2001:db8::1]:8443", "X-Forwarded-Port", "9999"))));
            // A host the proxy did not send: the request's own, with the forwarded scheme.
            assertEquals("https://pingfederate:9031", AttesterConfigurationServlet.baseUrl(from("10.1.1.1",
                    Map.of("X-Forwarded-Proto", "https"))));
        } finally {
            System.clearProperty("oidf.trusted.proxies");
        }
    }

    @Test
    void theRequestsOwnPortIsOmittedWhenDefaultOrUnknownAndTheContextPathKeptUnlessRoot() {
        HttpServletRequest http80 = from("198.51.100.7", Map.of());
        when(http80.getServerPort()).thenReturn(80);
        when(http80.getContextPath()).thenReturn("/");
        assertEquals("http://pingfederate", AttesterConfigurationServlet.baseUrl(http80));
        HttpServletRequest unknown = from("198.51.100.7", Map.of());
        when(unknown.getServerPort()).thenReturn(-1);
        when(unknown.getContextPath()).thenReturn(null);
        assertEquals("http://pingfederate", AttesterConfigurationServlet.baseUrl(unknown));
        HttpServletRequest https = from("198.51.100.7", Map.of());
        when(https.getScheme()).thenReturn("https");
        when(https.getServerPort()).thenReturn(443);
        assertEquals("https://pingfederate", AttesterConfigurationServlet.baseUrl(https));
    }

    @Test
    void hasPortReadsBracketedHosts() {
        assertTrue(AttesterConfigurationServlet.hasPort("h:1"));
        assertFalse(AttesterConfigurationServlet.hasPort("h"));
        assertTrue(AttesterConfigurationServlet.hasPort("[::1]:1"));
        assertFalse(AttesterConfigurationServlet.hasPort("[::1]"));
    }

    // ---- CORS (H-ATT-3) ------------------------------------------------------------------------------------------

    @Test
    void noOriginIsAllowedByDefault() throws Exception {
        AttesterConfigurationServlet servlet = new AttesterConfigurationServlet();
        HttpServletResponse resp = mock(HttpServletResponse.class);
        servlet.doOptions(from("198.51.100.7", Map.of("Origin", "https://evil.example")), resp);
        org.mockito.Mockito.verify(resp).setStatus(204);
        org.mockito.Mockito.verify(resp, org.mockito.Mockito.never()).setHeader(
                org.mockito.ArgumentMatchers.eq("Access-Control-Allow-Origin"), org.mockito.ArgumentMatchers.anyString());
        org.mockito.Mockito.verify(resp, org.mockito.Mockito.never()).addHeader("Vary", "Origin");
    }

    @Test
    void aListedOriginIsAllowedToGetAndOthersAreNot() {
        java.util.Set<String> allowed = AttesterConfigurationServlet.corsOrigins(java.util.Set.of("https://Console.Example"));
        HttpServletResponse listed = mock(HttpServletResponse.class);
        AttesterConfigurationServlet.applyCors(from("198.51.100.7", Map.of("Origin", "https://console.example")), listed, allowed);
        org.mockito.Mockito.verify(listed).setHeader("Access-Control-Allow-Origin", "https://console.example");
        org.mockito.Mockito.verify(listed).setHeader("Access-Control-Allow-Methods", "GET");
        org.mockito.Mockito.verify(listed).addHeader("Vary", "Origin");

        HttpServletResponse other = mock(HttpServletResponse.class);
        AttesterConfigurationServlet.applyCors(from("198.51.100.7", Map.of("Origin", "https://evil.example")), other, allowed);
        org.mockito.Mockito.verify(other).addHeader("Vary", "Origin");
        org.mockito.Mockito.verify(other, org.mockito.Mockito.never()).setHeader(
                org.mockito.ArgumentMatchers.eq("Access-Control-Allow-Origin"), org.mockito.ArgumentMatchers.anyString());

        HttpServletResponse none = mock(HttpServletResponse.class);
        AttesterConfigurationServlet.applyCors(from("198.51.100.7", Map.of()), none, allowed);
        org.mockito.Mockito.verify(none, org.mockito.Mockito.never()).setHeader(
                org.mockito.ArgumentMatchers.eq("Access-Control-Allow-Origin"), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void theDocumentAnswersAListedOriginOnly() throws Exception {
        AttesterConfigurationServlet servlet = new AttesterConfigurationServlet();
        servlet.setClientResolver(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.invalidClient("unknown");
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of();
            }
        });
        servlet.setCorsOrigins(java.util.Set.of("https://console.example"));
        HttpServletRequest req = from("198.51.100.7", Map.of("Origin", "https://console.example"));
        when(req.getRequestURI()).thenReturn("/.well-known/client-attester");
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(new StringWriter()));
        servlet.doGet(req, resp);
        org.mockito.Mockito.verify(resp).setHeader("Access-Control-Allow-Origin", "https://console.example");
        org.mockito.Mockito.verify(resp).setStatus(200);
    }

    @Test
    void anOriginThatIsNotOneIsRefusedNamingTheSetting() {
        assertEquals(java.util.Set.of(), AttesterConfigurationServlet.corsOrigins(null));
        assertEquals(java.util.Set.of("http://[2001:db8::1]:8443", "https://a.example"),
                AttesterConfigurationServlet.corsOrigins(new java.util.LinkedHashSet<>(List.of("http://[2001:db8::1]:8443", "https://a.example"))));
        for (String bad : List.of("*", "https://a.example/", "a.example", "ftp://a.example", "https://a.example/path",
                "https://user@a.example")) {
            com.pingidentity.ps.oidf.platform.settings.SettingRefused e = org.junit.jupiter.api.Assertions.assertThrows(
                    com.pingidentity.ps.oidf.platform.settings.SettingRefused.class,
                    () -> AttesterConfigurationServlet.corsOrigins(java.util.Set.of(bad)), bad);
            assertEquals(AttesterConfigurationServlet.CORS_SETTING, e.setting());
        }
    }

    @Test
    void initReadsTheOriginsAndTheProxiesAndFailsOnAValueItCannotRead() throws Exception {
        jakarta.servlet.ServletConfig config = mock(jakarta.servlet.ServletConfig.class);
        System.setProperty("oidf.attester.cors.origins", "https://console.example");
        try {
            AttesterConfigurationServlet servlet = new AttesterConfigurationServlet();
            servlet.init(config);
            HttpServletResponse resp = mock(HttpServletResponse.class);
            servlet.doOptions(from("198.51.100.7", Map.of("Origin", "https://console.example")), resp);
            org.mockito.Mockito.verify(resp).setHeader("Access-Control-Allow-Origin", "https://console.example");

            System.setProperty("oidf.attester.cors.origins", "*");
            AttesterConfigurationServlet refused = new AttesterConfigurationServlet();
            refused.init(config);
            HttpServletResponse gated = mock(HttpServletResponse.class);
            when(gated.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
                @Override
                public void write(int b) {
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setWriteListener(jakarta.servlet.WriteListener listener) {
                }
            });
            HttpServletRequest get = from("198.51.100.7", Map.of());
            when(get.getMethod()).thenReturn("GET");
            refused.service((jakarta.servlet.ServletRequest) get, (jakarta.servlet.ServletResponse) gated);
            org.mockito.Mockito.verify(gated).setStatus(503);
        } finally {
            System.clearProperty("oidf.attester.cors.origins");
        }
    }
}
