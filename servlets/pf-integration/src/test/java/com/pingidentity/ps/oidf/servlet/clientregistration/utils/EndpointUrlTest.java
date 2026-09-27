package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.conformance.Requirement;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;

/**
 * The URL a DPoP proof's {@code htu} must name, and the audience a PoP must carry, as {@link ClientAttestationUtils}
 * derives them from configuration for both the token-endpoint filter and the OGNL criterion.
 *
 * <p>What PingFederate 13.1.3 advertises (its {@code ProviderConfigurationInfoHandler}, read with javap on
 * 2026-09-27): {@code token_endpoint} is the token endpoint base URL, or the issuer when that is blank, followed by
 * {@code /as/token.oauth2}; {@code pushed_authorization_request_endpoint} is the issuer followed by
 * {@code /as/par.oauth2}.
 */
class EndpointUrlTest {
    private static final String ISSUER = "https://as.example.com";
    private static final String BASE = "https://mtls.as.example.com:8443";

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void anEndpointIsTheIssuerFollowedByItsPath() {
        assertEquals(ISSUER + "/as/token.oauth2", ClientAttestationUtils.endpointUrl(ISSUER, null, "/as/token.oauth2"));
        assertEquals(ISSUER + "/as/par.oauth2", ClientAttestationUtils.endpointUrl(ISSUER, null, "/as/par.oauth2"));
        assertEquals(ISSUER + "/as/token.oauth2", ClientAttestationUtils.endpointUrl(ISSUER, " ", "/as/token.oauth2"));
    }

    @Test
    @Requirement("RFC9449 §4.3(9)")
    void theTokenEndpointBaseUrlMovesTheTokenEndpointOnly() {
        assertEquals(BASE + "/as/token.oauth2", ClientAttestationUtils.endpointUrl(ISSUER, BASE, "/as/token.oauth2"));
        assertEquals(ISSUER + "/as/par.oauth2", ClientAttestationUtils.endpointUrl(ISSUER, BASE, "/as/par.oauth2"));
    }

    @Test
    void anUnknownIssuerOrPathIsNoUrl() {
        assertNull(ClientAttestationUtils.endpointUrl(null, BASE, "/as/token.oauth2"));
        assertNull(ClientAttestationUtils.endpointUrl(" ", BASE, "/as/token.oauth2"));
        assertNull(ClientAttestationUtils.endpointUrl(ISSUER, BASE, null));
        assertNull(ClientAttestationUtils.endpointUrl(ISSUER, BASE, ""));
    }

    /** The path the container routed on: PingFederate maps *.oauth2 by extension, so the servlet path is all of it. */
    @Test
    void theEndpointPathIsWhatTheContainerRoutedOn() {
        assertEquals("/as/token.oauth2", ClientAttestationUtils.endpointPath(request("", "/as/token.oauth2", null)));
        assertEquals("/as/token.oauth2", ClientAttestationUtils.endpointPath(request(null, "/as/token.oauth2", null)));
        assertEquals("/ctx/as/token.oauth2", ClientAttestationUtils.endpointPath(request("/ctx", "/as", "/token.oauth2")));
        assertNull(ClientAttestationUtils.endpointPath(request(null, null, null)));
        assertNull(ClientAttestationUtils.endpointPath(request("", "", null)));
    }

    private static HttpServletRequest request(String contextPath, String servletPath, String pathInfo) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getContextPath()).thenReturn(contextPath);
        when(request.getServletPath()).thenReturn(servletPath);
        when(request.getPathInfo()).thenReturn(pathInfo);
        // What must not be read: the URL the container rebuilds from the Host header.
        when(request.getRequestURL()).thenReturn(new StringBuffer("https://other-bank.example/as/token.oauth2"));
        return request;
    }

    @Test
    @Requirement({"ABCA-10 §5.1", "RFC9449 §4.3(9)"})
    void theFiltersPolicyIsTheIssuerAloneAndTheEndpointUrl() {
        ClientAttestationConfig config = ClientAttestationUtils.defaultConfig(ISSUER, ISSUER + "/as/token.oauth2");

        assertEquals(ISSUER, config.expectedAudience());
        assertEquals(ISSUER + "/as/token.oauth2", config.expectedHtu());
        assertEquals("POST", config.expectedHtm());
    }

    /**
     * Outside a running PingFederate the setting cannot be read (its registry is not there), and unreadable is
     * unset: the token endpoint stays under the issuer. Asked twice, because the second failure is not logged.
     */
    @Test
    void anUnreadableTokenEndpointBaseUrlIsUnset() {
        assertNull(ClientAttestationUtils.configuredTokenEndpointBaseUrl());
        assertNull(ClientAttestationUtils.configuredTokenEndpointBaseUrl());
    }
}
