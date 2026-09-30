/*
 * For FAPI clients: x-fapi-interaction-id echoed or minted before the chain runs; a token in the query refused.
 */
package com.pingidentity.ps.oidf.servlet.fapi1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.events.Event;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.metrics.MetricSnapshot;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import com.pingidentity.ps.oidf.platform.metrics.SeriesSnapshot;
import com.pingidentity.ps.oidf.servlet.fapi2.FapiEvents;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

class FapiResourceServerFilterTest {
    private static final String FAPI = "fapi-client";
    private static final String OTHER = "ordinary-client";

    private final List<Event> events = new ArrayList<>();

    @BeforeEach
    void capture() {
        Events.reset();
        Events.configure(this.events::add);
    }

    @AfterEach
    void release() {
        Events.reset();
    }

    /** The filter, started with {@code OIDF_FAPI2_CLIENTS} set to {@code clients} (null: unset). */
    private static FapiResourceServerFilter filter(String clients) {
        FapiResourceServerFilter filter = new FapiResourceServerFilter(
                name -> "OIDF_FAPI2_CLIENTS".equals(name) ? clients : null);
        filter.init(mock(FilterConfig.class));
        return filter;
    }

    /** A JWT access token (unsigned: the filter never verifies one, PingFederate does) issued to {@code clientId}. */
    static String token(String clientId) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"PS256\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(("{\"client_id\":\"" + clientId + "\"}").getBytes(StandardCharsets.UTF_8)) + ".c2ln";
    }

    private static HttpServletRequest request(String interactionId, String query, String authorization) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader(FapiResourceServerFilter.HEADER)).thenReturn(interactionId);
        when(req.getHeader("Authorization")).thenReturn(authorization);
        when(req.getQueryString()).thenReturn(query);
        when(req.getMethod()).thenReturn("GET");
        when(req.getRequestURI()).thenReturn("/idp/userinfo.openid");
        when(req.getRemoteAddr()).thenReturn("203.0.113.9");
        return req;
    }

    private static String run(FapiResourceServerFilter filter, String given) throws Exception {
        HttpServletRequest req = request(given, null, "Bearer " + token(FAPI));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        ArgumentCaptor<String> value = ArgumentCaptor.forClass(String.class);
        InOrder order = inOrder(resp, chain);
        order.verify(resp).setHeader(eq(FapiResourceServerFilter.HEADER), value.capture());
        order.verify(chain).doFilter(req, resp);
        return value.getValue();
    }

    /** Runs {@code query} through {@code filter}; the body when it was refused, null when the chain ran. */
    private static String refusal(FapiResourceServerFilter filter, String query, String authorization) throws Exception {
        HttpServletRequest req = request(null, query, authorization);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        when(resp.getWriter()).thenReturn(new PrintWriter(sink, true));
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(req, resp, chain);

        if (sink.size() == 0) {
            verify(chain).doFilter(req, resp);
            verify(resp, never()).setStatus(400);
            return null;
        }
        verify(chain, never()).doFilter(any(), any());
        verify(resp).setStatus(400);
        verify(resp).setHeader(eq(FapiResourceServerFilter.HEADER), anyString());
        verify(resp).setHeader("WWW-Authenticate", "Bearer error=\"invalid_request\"");
        return sink.toString(StandardCharsets.UTF_8);
    }

    private static long counted() {
        for (MetricSnapshot metric : Metrics.snapshot()) {
            if (metric.getName().equals("oidf_events_total")) {
                for (SeriesSnapshot series : metric.getSeries()) {
                    if (series.getLabelValues().contains(FapiEvents.REFUSED)) {
                        return (long) series.getValue();
                    }
                }
            }
        }
        return 0L;
    }

    @Test
    @Requirement("FAPI1-BASE §6.2.1(11)")
    void aUuidFromTheClientIsEchoedBeforeTheChainRuns() throws Exception {
        FapiResourceServerFilter filter = filter(FAPI);
        String id = UUID.randomUUID().toString();
        assertEquals(id, run(filter, id));
        assertEquals(id.toUpperCase(), run(filter, " " + id.toUpperCase() + " "), "trimmed, case kept");
    }

    @Test
    @Requirement("FAPI1-BASE §6.2.1(11)")
    void withoutOneOrWithSomethingThatIsNotAUuidAFreshOneIsMinted() throws Exception {
        FapiResourceServerFilter filter = filter(FAPI);
        String minted = run(filter, null);
        UUID.fromString(minted);
        assertNotEquals(minted, run(filter, null));
        String notEchoed = run(filter, "<script>alert(1)</script>");
        UUID.fromString(notEchoed);
        assertFalse(notEchoed.contains("script"));
        UUID.fromString(run(filter, "12345678-1234-1234-1234-12345678901"));
    }

    @Test
    @Requirement({"FAPI1-BASE §6.2.1(3)", "FAPI2-SP §5.3.4(2)", "RFC6750 §3.1"})
    void aFapiClientsAccessTokenInTheQueryIsRefusedAndRecorded() throws Exception {
        FapiResourceServerFilter filter = filter(FAPI + " another");
        long before = counted();
        String body = refusal(filter, "foo=1&access_token=" + token(FAPI), null);

        assertTrue(body.contains("\"error\":\"invalid_request\""), body);
        assertFalse(body.contains(token(FAPI)), "the token is never echoed");
        assertEquals(1, this.events.size());
        Event event = this.events.get(0);
        assertEquals(FapiEvents.REFUSED, event.code());
        assertEquals(FAPI, event.subject());
        assertEquals("invalid_request", event.reason());
        assertEquals(Map.of("filter", FapiEvents.RESOURCE_SERVER_FILTER, "rule", "access_token_in_query",
                "endpoint", "/idp/userinfo.openid"), event.fields());
        assertEquals(before + 1, counted(), "counted in oidf_events_total");
    }

    @Test
    @Requirement({"FAPI1-BASE §6.2.1(3)", "FAPI2-SP §5.3.4(2)"})
    void everySpellingOfTheNameIsTheSameParameter() throws Exception {
        FapiResourceServerFilter filter = filter(FAPI);
        String fapi = token(FAPI);
        for (String query : new String[] {"access%5Ftoken=" + fapi, "access%5ftoken=" + fapi, "Access_Token=" + fapi,
                "ACCESS_TOKEN=" + fapi, "%61ccess_token=" + fapi, "access_token=" + token(OTHER) + "&access_token=" + fapi,
                "x=1&access_token=" + fapi + "&access_token=" + fapi}) {
            assertTrue(refusal(filter, query, null) != null, query);
        }
    }

    @Test
    void aClientTheListDoesNotNameIsLeftToPingFederate() throws Exception {
        FapiResourceServerFilter filter = filter(FAPI);
        assertNull(refusal(filter, "access_token=" + token(OTHER), null), "an ordinary client's query token is PingFederate's to judge");
        assertNull(refusal(filter, "access_token=opaque-reference-token", null), "a token naming no client is FAPI's only under *");
        assertNull(refusal(filter, null, "Bearer " + token(OTHER)));
        assertTrue(this.events.isEmpty());

        HttpServletRequest req = request(null, null, "Bearer " + token(OTHER));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        filter.doFilter(req, resp, mock(FilterChain.class));
        verify(resp, never()).setHeader(eq(FapiResourceServerFilter.HEADER), anyString());
    }

    @Test
    void aFapiClientsHeaderTokenBesideAQueryTokenMakesTheRequestFapis() throws Exception {
        assertTrue(refusal(filter(FAPI), "access_token=opaque", "DPoP " + token(FAPI)) != null);
    }

    @Test
    void everyClientUnderTheWildcard() throws Exception {
        FapiResourceServerFilter filter = filter("*");
        assertTrue(refusal(filter, "access_token=opaque", null) != null);
        assertNull(this.events.get(0).subject(), "no client could be told");
        assertTrue(refusal(filter, "access_token=" + token(OTHER), null) != null);
        assertEquals(OTHER, this.events.get(1).subject());
    }

    @Test
    void unsetTheFilterDoesNothing() throws Exception {
        FapiResourceServerFilter filter = filter(null);
        assertNull(refusal(filter, "access_token=" + token(FAPI), "Bearer " + token(FAPI)));
        assertTrue(this.events.isEmpty());
    }

    @Test
    void aListThatCannotBeReadHoldsEveryClient() throws Exception {
        FapiResourceServerFilter filter = filter(",");
        assertTrue(refusal(filter, "access_token=opaque", null) != null);
    }

    @Test
    void onlyTheQueryCountsNotAParameterThatMerelyContainsTheName() throws Exception {
        FapiResourceServerFilter filter = filter("*");
        for (String query : new String[] {"my_access_token=abc", "x=access_token", "scope=openid", "access_token_hint=x"}) {
            assertNull(refusal(filter, query, null), query);
        }
        assertEquals(List.of(), FapiResourceServerFilter.tokensInQuery(null));
        assertEquals(List.of(), FapiResourceServerFilter.tokensInQuery(""));
        assertEquals(List.of("", "a b"), FapiResourceServerFilter.tokensInQuery("access_token&access_token=a+b"));
        assertEquals(List.of("%zz"), FapiResourceServerFilter.tokensInQuery("access_token=%zz"), "a malformed escape is read as it is");
        assertEquals("a%", FapiResourceServerFilter.decoded("a%"));
    }

    @Test
    void aNonHttpExchangeIsPassedThroughUntouched() throws Exception {
        FapiResourceServerFilter filter = new FapiResourceServerFilter();
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

    /** H-FED-4: a token in the query - whatever it carries - is never written back, and the refusal is generic. */
    @Test
    void aHostileMarkerNeverReachesTheResponse() throws Exception {
        String marker = "hfede-marker-" + UUID.randomUUID();
        String body = refusal(filter("*"), "access_token=" + marker + "&" + marker + "=1", null);
        assertFalse(body.contains(marker), body);
        com.pingidentity.ps.oidf.servlet.oauth.PublicErrorsAssert.assertGeneric("invalid_request", body);
    }
}
