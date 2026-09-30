/*
 * S-9's floor on FAPI: a filter whose start failed does not know its client list, so every request meets the 503.
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
    void aFapiFilterThatDidNotStartAnswersEveryRequest503() throws Exception {
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

    private static String b64(String json) {
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
