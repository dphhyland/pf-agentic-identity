/*
 * S-9's rule for FAPI (S9b, F-0270): while FAPI is failed, a request from a client its list names meets the 503 and every
 * other request goes on; a list that cannot be read makes every request FAPI's.
 */
package com.pingidentity.ps.oidf.servlet.fapi2;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.servlet.GateTesting;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

class SurfaceGateTest {

    @Test
    void aFapiFilterWhoseListCannotBeReadAnswersEveryRequest503() throws Exception {
        Fapi2ProfileFilter filter = new Fapi2ProfileFilter(r -> "https://op.example", name -> {
            throw new IllegalStateException("the environment could not be read");
        });
        assertDoesNotThrow(() -> filter.init(null));
        assertEquals(ComponentState.FAILED_CONFIG, GateTesting.part("Fapi2ProfileFilter").state());

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        ByteArrayOutputStream answer = GateTesting.body(response);
        filter.doFilter(request, response, chain);
        verify(response).setStatus(503);
        assertTrue(GateTesting.text(answer).contains("FAPI is not available"), GateTesting.text(answer));
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    void aFilterNeverInitialisedHasNoClientsAndPassesEverythingOn() throws Exception {
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        new Fapi2ProfileFilter(r -> "https://op.example", name -> null).doFilter(request, response, chain);
        verify(chain).doFilter(request, response);
    }

    @Test
    void aWeakProofAtAnEndpointWithNoUriIsNotTheResources() throws Exception {
        Fapi2ProfileFilter filter = new Fapi2ProfileFilter(r -> "https://op.example",
                name -> Fapi2ProfileFilter.CLIENTS_ENV.equals(name) ? "*" : null);
        filter.init(null);
        HttpServletRequest request = mock(HttpServletRequest.class);
        org.mockito.Mockito.when(request.getMethod()).thenReturn("POST");
        org.mockito.Mockito.when(request.getHeaders("DPoP")).thenReturn(java.util.Collections.enumeration(java.util.List.of(
                b64("{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\"}") + "." + b64("{}") + ".c2ln")));
        HttpServletResponse response = mock(HttpServletResponse.class);
        org.mockito.Mockito.when(response.getWriter()).thenReturn(new java.io.PrintWriter(new java.io.StringWriter()));
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(response).setStatus(400);
        verify(chain, never()).doFilter(any(), any());
    }

    private static HttpServletRequest from(String clientId, String... assertions) {
        HttpServletRequest request = mock(HttpServletRequest.class);
        org.mockito.Mockito.when(request.getParameter("client_id")).thenReturn(clientId);
        org.mockito.Mockito.when(request.getParameterValues("client_assertion")).thenReturn(assertions.length == 0 ? null : assertions);
        return request;
    }

    /** Whether a failed FAPI filter with {@code list} answered {@code request} 503 rather than passing it on. */
    private static boolean refused(String list, HttpServletRequest request) throws Exception {
        Fapi2ProfileFilter filter = new Fapi2ProfileFilter(r -> "https://op.example",
                name -> Fapi2ProfileFilter.CLIENTS_ENV.equals(name) ? list : null);
        filter.init(null);
        // Failed on its switch - unset in production beside its settings, say - with its list readable.
        com.pingidentity.ps.oidf.platform.health.Startup.begin(com.pingidentity.ps.oidf.platform.health.Startup.FAPI, "Fapi2ProfileFilter")
                .failedConfig("OIDF_FAPI_ENABLED is unset");
        HttpServletResponse response = mock(HttpServletResponse.class);
        GateTesting.body(response);
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        boolean passed = org.mockito.Mockito.mockingDetails(chain).getInvocations().size() == 1;
        if (!passed) {
            verify(response).setStatus(503);
        }
        return !passed;
    }

    @Test
    void aFailedFapiFilterAnswersOnlyTheClientsItsListNames503() throws Exception {
        String own = b64("{\"alg\":\"PS256\"}") + "." + b64("{\"sub\":\"fapi-client\"}") + ".c2ln";
        String other = b64("{\"alg\":\"PS256\"}") + "." + b64("{\"sub\":\"conformance-ssf-emitter\"}") + ".c2ln";
        assertTrue(refused("fapi-client, other-fapi", from("fapi-client")));
        assertTrue(refused("fapi-client", from(null, own)));
        assertTrue(!refused("fapi-client", from("conformance-ssf-emitter")), "PingFederate's other clients keep the endpoint");
        assertTrue(!refused("fapi-client", from(null, other)));
        assertTrue(!refused("fapi-client", from(null)), "a request that names nobody is not FAPI's");
        // An assertion whose owner cannot be read, or two of them, is FAPI's: a healthy filter refuses both.
        assertTrue(refused("fapi-client", from(null, "not a jwt")));
        assertTrue(refused("fapi-client", from(null, other, other)));
        // Every client, and no client at all.
        assertTrue(refused("*", from("anyone")));
        assertTrue(!refused("", from("anyone")));
        // The system property wins over the environment, as the start reads it.
        System.setProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY, "anyone");
        try {
            assertTrue(refused("fapi-client", from("anyone")));
        } finally {
            System.clearProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY);
        }
        // A blank system property is unset: the environment's list decides.
        System.setProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY, " ");
        try {
            assertTrue(refused("fapi-client", from("fapi-client")));
        } finally {
            System.clearProperty(Fapi2ProfileFilter.CLIENTS_PROPERTY);
        }
        // No assertion sent (an empty list of them) and a blank client_id: the access token names the client, here none.
        HttpServletRequest empty = mock(HttpServletRequest.class);
        org.mockito.Mockito.when(empty.getParameterValues("client_assertion")).thenReturn(new String[0]);
        org.mockito.Mockito.when(empty.getParameter("client_id")).thenReturn("fapi-client");
        assertTrue(refused("fapi-client", empty));
        assertTrue(!refused("fapi-client", from(" ")), "a blank client_id names nobody");
    }

    private static String b64(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
