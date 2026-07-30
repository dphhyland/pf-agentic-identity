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

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.AttesterClient;
import com.pingidentity.ps.oidf.common.InstanceAttestationValidators;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.IssuanceException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
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

    @Test
    void globalDocumentAdvertisesEndpointsAndProofRequirements() {
        Map<String, Object> m = AttesterConfigurationServlet.metadata("https://pf.example.com", true);

        assertEquals("https://pf.example.com/federation/attestation", m.get("attestation_endpoint"));
        assertEquals("https://pf.example.com/federation/attestation-challenge", m.get("challenge_endpoint"));
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
            public java.util.List<com.pingidentity.ps.oidf.common.AttesterClient> attestationClients() {
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

    @Test
    void baseUrlPrefersForwardedHeadersAndOmitsDefaultPorts() {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("X-Forwarded-Proto")).thenReturn("https");
        when(req.getHeader("X-Forwarded-Host")).thenReturn("attester.proxy.example");
        when(req.getHeader("X-Forwarded-Port")).thenReturn("443");
        when(req.getContextPath()).thenReturn("");
        assertEquals("https://attester.proxy.example", AttesterConfigurationServlet.baseUrl(req));

        HttpServletRequest proxied = mock(HttpServletRequest.class);
        when(proxied.getHeader("X-Forwarded-Proto")).thenReturn("https, http");
        when(proxied.getHeader("X-Forwarded-Host")).thenReturn("edge.example:8443, inner");
        when(proxied.getContextPath()).thenReturn("/oidf");
        assertEquals("https://edge.example:8443/oidf", AttesterConfigurationServlet.baseUrl(proxied));

        HttpServletRequest plain = mock(HttpServletRequest.class);
        when(plain.getScheme()).thenReturn("http");
        when(plain.getServerName()).thenReturn("pingfederate");
        when(plain.getServerPort()).thenReturn(9080);
        when(plain.getContextPath()).thenReturn("");
        assertEquals("http://pingfederate:9080", AttesterConfigurationServlet.baseUrl(plain));
    }
}
