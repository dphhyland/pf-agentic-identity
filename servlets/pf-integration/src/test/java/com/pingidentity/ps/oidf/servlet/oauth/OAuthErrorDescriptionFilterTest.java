/*
 * error_description leaves within RFC 6749's character set; everything else leaves as written.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class OAuthErrorDescriptionFilterTest {

    private static final String DIRTY = "The Expiration Time (exp -> Sep 23, 2026, 9:37:22 PM GMT) is \"wrong\" \\ here";

    /** What PingFederate writes into the response, and how: status, content type, then the body via one of the two channels. */
    private byte[] through(int status, String contentType, String body, boolean viaWriter) throws Exception {
        HttpServletResponse real = mock(HttpServletResponse.class);
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ServletOutputStream realStream = new ServletOutputStream() {
            @Override
            public void write(int b) {
                sink.write(b);
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(WriteListener l) {
            }
        };
        when(real.getOutputStream()).thenReturn(realStream);
        when(real.getStatus()).thenReturn(status);
        when(real.getContentType()).thenReturn(contentType);
        FilterChain chain = (req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            wrapped.setStatus(status);
            wrapped.setContentType(contentType);
            wrapped.setContentLength(999);
            if (viaWriter) {
                wrapped.getWriter().write(body);
                wrapped.flushBuffer();
            } else {
                wrapped.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));
            }
        };

        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), real, chain);
        verify(real).setContentLength(sink.size());
        return sink.toByteArray();
    }

    @Test
    @Requirement("RFC6749 §5.2")
    void anErrorDescriptionOutsideTheSetIsBroughtInsideIt() throws Exception {
        String json = JsonUtil.toJson(Map.of("error", "invalid_request", "error_description", DIRTY));
        for (boolean viaWriter : new boolean[] {true, false}) {
            Map<String, Object> out = JsonUtil.parseJson(new String(through(400, "application/json;charset=UTF-8", json, viaWriter), StandardCharsets.UTF_8));
            String description = (String) out.get("error_description");
            assertEquals("invalid_request", out.get("error"));
            assertFalse(description.contains(" "));
            assertFalse(description.contains("\""));
            assertFalse(description.contains("\\"));
            assertTrue(description.contains("9:37:22 PM GMT"), description);
            assertEquals(OAuthErrorDescriptionFilter.withinSet(DIRTY), description);
        }
    }

    @Test
    void whatIsNotAnErrorOrNotJsonOrNotParseableGoesOutAsWritten() throws Exception {
        String token = "{\"access_token\":\"x y\"}";
        assertArrayEquals(token.getBytes(StandardCharsets.UTF_8), through(200, "application/json", token, false));
        // a 200 is not an error response, whatever it carries: the rule is RFC 6749 §5.2's, about errors
        String successWithDescription = "{\"access_token\":\"x\",\"error_description\":\"odd but not ours\u202f\"}";
        assertArrayEquals(successWithDescription.getBytes(StandardCharsets.UTF_8), through(200, "application/json", successWithDescription, true));
        assertArrayEquals(successWithDescription.getBytes(StandardCharsets.UTF_8), through(399, "application/json", successWithDescription, false));
        String html = "<html> </html>";
        assertArrayEquals(html.getBytes(StandardCharsets.UTF_8), through(400, "text/html", html, true));
        assertArrayEquals(html.getBytes(StandardCharsets.UTF_8), through(400, null, html, true));
        String broken = "{not json  ";
        assertArrayEquals(broken.getBytes(StandardCharsets.UTF_8), through(400, "application/json", broken, false));
        String noDescription = "{\"error\":\"invalid_request\"}";
        assertArrayEquals(noDescription.getBytes(StandardCharsets.UTF_8), through(400, "application/json", noDescription, false));
        String clean = "{\"error\":\"invalid_request\",\"error_description\":\"already fine\"}";
        assertArrayEquals(clean.getBytes(StandardCharsets.UTF_8), through(400, "application/json", clean, false));
        String notAString = "{\"error_description\":7}";
        assertArrayEquals(notAString.getBytes(StandardCharsets.UTF_8), through(400, "application/json", notAString, false));
    }

    @Test
    void theSetIsExactlyTheOneTheRfcGives() {
        assertEquals(" !#[]~", OAuthErrorDescriptionFilter.withinSet(" !#[]~"));
        assertEquals("a b c d", OAuthErrorDescriptionFilter.withinSet("a\"b\\c\u007fd"));
        assertEquals("   ", OAuthErrorDescriptionFilter.withinSet("\t\n\u0000"));
        byte[] same = "{\"x\":1}".getBytes(StandardCharsets.UTF_8);
        assertSame(same, OAuthErrorDescriptionFilter.sanitise(same));
        assertTrue(OAuthErrorDescriptionFilter.isJson("Application/JSON; charset=utf-8"));
        assertFalse(OAuthErrorDescriptionFilter.isJson("text/plain"));
    }

    @Test
    void aNonHttpResponsePassesThrough() throws Exception {
        ServletRequest req = mock(ServletRequest.class);
        ServletResponse resp = mock(ServletResponse.class);
        FilterChain chain = mock(FilterChain.class);
        OAuthErrorDescriptionFilter filter = new OAuthErrorDescriptionFilter();
        filter.init(null);
        filter.doFilter(req, resp, chain);
        filter.destroy();
        verify(chain).doFilter(req, resp);
        verify(resp, never()).getOutputStream();
    }

    @Test
    void theBufferDropsContentLengthAndHoldsFlushes() throws Exception {
        HttpServletResponse real = mock(HttpServletResponse.class);
        OAuthErrorDescriptionFilter.Buffered b = new OAuthErrorDescriptionFilter.Buffered(real);
        b.setContentLength(5);
        b.setContentLengthLong(5L);
        b.flushBuffer();
        verify(real, never()).setContentLength(any(Integer.class));
        verify(real, never()).flushBuffer();
        b.getOutputStream().write('a');
        assertTrue(b.getOutputStream().isReady());
        b.getOutputStream().setWriteListener(null);
        assertSame(b.getOutputStream(), b.getOutputStream());
        assertSame(b.getWriter(), b.getWriter());
        assertEquals("a", new String(b.bytes(), StandardCharsets.UTF_8));
    }
}
