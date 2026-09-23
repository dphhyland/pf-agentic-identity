/*
 * x-fapi-interaction-id echoed or minted before the chain runs; a token in the query refused.
 */
package com.pingidentity.ps.oidf.servlet.fapi1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class FapiResourceServerFilterTest {

    private final FapiResourceServerFilter filter = new FapiResourceServerFilter();

    private static HttpServletRequest request(String interactionId, String query) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(FapiResourceServerFilter.HEADER)).thenReturn(interactionId);
        when(req.getQueryString()).thenReturn(query);
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn("/idp/userinfo.openid");
        return req;
    }

    private String run(String given) throws Exception {
        HttpServletRequest req = request(given, null);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        ArgumentCaptor<String> value = ArgumentCaptor.forClass(String.class);
        InOrder order = inOrder(resp, chain);
        order.verify(resp).setHeader(eq(FapiResourceServerFilter.HEADER), value.capture());
        order.verify(chain).doFilter(req, resp);
        return value.getValue();
    }

    @Test
    @Requirement("FAPI1-BASE §6.2.1(11)")
    void aUuidFromTheClientIsEchoedBeforeTheChainRuns() throws Exception {
        String id = UUID.randomUUID().toString();
        assertEquals(id, run(id));
        assertEquals(id.toUpperCase(), run(" " + id.toUpperCase() + " "), "trimmed, case kept");
    }

    @Test
    @Requirement("FAPI1-BASE §6.2.1(11)")
    void withoutOneOrWithSomethingThatIsNotAUuidAFreshOneIsMinted() throws Exception {
        String minted = run(null);
        UUID.fromString(minted);
        assertNotEquals(minted, run(null));
        String notEchoed = run("<script>alert(1)</script>");
        UUID.fromString(notEchoed);
        assertFalse(notEchoed.contains("script"));
        UUID.fromString(run("12345678-1234-1234-1234-12345678901"));
    }

    @Test
    @Requirement({"FAPI1-BASE §6.2.1(3)", "RFC6750 §3.1"})
    void anAccessTokenInTheQueryIsRefusedBeforeTheChainAndStillGetsAnInteractionId() throws Exception {
        for (String query : new String[] {"access_token=abc", "foo=1&access_token=abc", "access_token="}) {
            HttpServletRequest req = request(null, query);
            HttpServletResponse resp = mock(HttpServletResponse.class);
            ByteArrayOutputStream sink = new ByteArrayOutputStream();
            when(resp.getWriter()).thenReturn(new PrintWriter(sink, true));
            FilterChain chain = mock(FilterChain.class);

            filter.doFilter(req, resp, chain);

            verify(chain, never()).doFilter(any(), any());
            verify(resp).setStatus(400);
            verify(resp).setHeader(eq(FapiResourceServerFilter.HEADER), any());
            ArgumentCaptor<String> challenge = ArgumentCaptor.forClass(String.class);
            verify(resp).setHeader(eq("WWW-Authenticate"), challenge.capture());
            assertTrue(challenge.getValue().startsWith("Bearer error=\"invalid_request\""));
            assertTrue(sink.toString(StandardCharsets.UTF_8).contains("\"error\":\"invalid_request\""), query);
        }
    }

    @Test
    void onlyTheQueryCountsNotAParameterThatMerelyContainsTheName() throws Exception {
        for (String query : new String[] {"my_access_token=abc", "x=access_token", "scope=openid"}) {
            HttpServletRequest req = request(null, query);
            HttpServletResponse resp = mock(HttpServletResponse.class);
            FilterChain chain = mock(FilterChain.class);
            filter.doFilter(req, resp, chain);
            verify(chain).doFilter(req, resp);
            verify(resp, never()).setStatus(400);
        }
        assertFalse(FapiResourceServerFilter.carriesTokenInQuery(request(null, null)));
    }

    @Test
    void aNonHttpExchangeIsPassedThroughUntouched() throws Exception {
        ServletRequest req = mock(ServletRequest.class);
        ServletResponse resp = mock(ServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        filter.init(null);
        filter.doFilter(req, resp, chain);
        filter.destroy();
        verify(chain).doFilter(req, resp);
        verify(resp, never()).setContentType(any());

        HttpServletRequest httpReq = mock(HttpServletRequest.class);
        FilterChain chain2 = mock(FilterChain.class);
        filter.doFilter(httpReq, resp, chain2);
        verify(chain2).doFilter(httpReq, resp);
    }
}
