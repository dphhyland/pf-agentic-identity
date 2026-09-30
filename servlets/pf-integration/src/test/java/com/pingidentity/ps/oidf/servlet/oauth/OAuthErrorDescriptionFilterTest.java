/*
 * error_description leaves within RFC 6749's character set; only an error is held; everything else leaves as written.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.servlet.oauth.OAuthErrorDescriptionFilter.ErrorsOnly;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.Test;

class OAuthErrorDescriptionFilterTest {

    private static final String DIRTY = "The Expiration Time (exp -> Sep 23, 2026, 9:37:22\u202fPM GMT) is \"wrong\" \\ here";

    /**
     * The container's response, as far as the filter can tell: a status, a content type and length, a body, whether it
     * is committed, and a record of what reached it in order - so a test sees whether a byte went out before the chain
     * was done.
     */
    static final class Real {
        final HttpServletResponse response = mock(HttpServletResponse.class);
        final ByteArrayOutputStream body = new ByteArrayOutputStream();
        final List<String> calls = new ArrayList<>();
        int status = 200;
        String contentType;
        Long contentLength;
        String charset;
        boolean committed;

        Real() throws Exception {
            ServletOutputStream stream = new ServletOutputStream() {
                @Override
                public void write(int b) {
                    Real.this.body.write(b);
                    Real.this.committed = true;
                    Real.this.calls.add("byte");
                }

                @Override
                public void flush() {
                    Real.this.calls.add("flush");
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setWriteListener(WriteListener l) {
                }
            };
            when(this.response.getOutputStream()).thenReturn(stream);
            when(this.response.getStatus()).thenAnswer(call -> this.status);
            when(this.response.getContentType()).thenAnswer(call -> this.contentType);
            when(this.response.getCharacterEncoding()).thenAnswer(call -> this.charset);
            when(this.response.isCommitted()).thenAnswer(call -> this.committed);
            doAnswer(call -> this.status = call.getArgument(0)).when(this.response).setStatus(anyInt());
            doAnswer(call -> this.contentType = call.getArgument(0)).when(this.response).setContentType(anyString());
            doAnswer(call -> this.contentLength = (long) (int) call.getArgument(0)).when(this.response).setContentLength(anyInt());
            doAnswer(call -> this.contentLength = call.getArgument(0)).when(this.response).setContentLengthLong(anyLong());
            doAnswer(call -> {
                this.calls.add("sendError " + call.getArgument(0));
                this.status = call.getArgument(0);
                this.committed = true;
                return null;
            }).when(this.response).sendError(anyInt());
            doAnswer(call -> {
                this.calls.add("sendError " + call.getArgument(0) + " " + call.getArgument(1));
                this.status = call.getArgument(0);
                this.committed = true;
                return null;
            }).when(this.response).sendError(anyInt(), anyString());
            doAnswer(call -> {
                this.calls.add("reset");
                this.status = 200;
                this.contentType = null;
                this.contentLength = null;
                return null;
            }).when(this.response).reset();
            doAnswer(call -> this.calls.add("flushBuffer")).when(this.response).flushBuffer();
            doAnswer(call -> this.calls.add("resetBuffer")).when(this.response).resetBuffer();
        }

        String text() {
            return this.body.toString(StandardCharsets.UTF_8);
        }
    }

    private static Real run(FilterChain chain) throws Exception {
        Real real = new Real();
        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), real.response, chain);
        return real;
    }

    /** What PingFederate writes: status, content type, a length, then the body via one of the two channels. */
    private static byte[] through(int status, String contentType, String body, boolean viaWriter) throws Exception {
        Real real = run((req, resp) -> {
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
        });
        if (status >= 400) {
            assertEquals(real.body.size(), real.contentLength, "a held body's length is its final one");
        } else {
            assertEquals(999L, real.contentLength, "a body that passes through keeps the length PingFederate declared");
        }
        return real.body.toByteArray();
    }

    @Test
    @Requirement("RFC6749 §5.2")
    void anErrorDescriptionOutsideTheSetIsBroughtInsideIt() throws Exception {
        String json = JsonUtil.toJson(Map.of("error", "invalid_request", "error_description", DIRTY));
        for (boolean viaWriter : new boolean[] {true, false}) {
            Map<String, Object> out = JsonUtil.parseJson(new String(through(400, "application/json;charset=UTF-8", json, viaWriter), StandardCharsets.UTF_8));
            String description = (String) out.get("error_description");
            assertEquals("invalid_request", out.get("error"));
            assertFalse(description.contains("\u202f"));
            assertFalse(description.contains("\""));
            assertFalse(description.contains("\\"));
            assertTrue(description.contains("9:37:22 PM GMT"), description);
            assertEquals(OAuthErrorDescriptionFilter.withinSet(DIRTY), description);
        }
    }

    @Test
    void whatIsNotAnErrorOrNotJsonOrNotParseableGoesOutAsWritten() throws Exception {
        String token = "{\"access_token\":\"x y\"}";
        assertArrayEquals(token.getBytes(StandardCharsets.UTF_8), through(200, "application/json", token, false));
        // a 200 is not an error response, whatever it carries: the rule is RFC 6749 §5.2's, about errors
        String successWithDescription = "{\"access_token\":\"x\",\"error_description\":\"odd but not ours \"}";
        assertArrayEquals(successWithDescription.getBytes(StandardCharsets.UTF_8), through(200, "application/json", successWithDescription, true));
        assertArrayEquals(successWithDescription.getBytes(StandardCharsets.UTF_8), through(399, "application/json", successWithDescription, false));
        String html = "<html> </html>";
        assertArrayEquals(html.getBytes(StandardCharsets.UTF_8), through(400, "text/html", html, true));
        assertArrayEquals(html.getBytes(StandardCharsets.UTF_8), through(400, null, html, true));
        String broken = "{not json  ";
        assertArrayEquals(broken.getBytes(StandardCharsets.UTF_8), through(400, "application/json", broken, false));
        String noDescription = "{\"error\":\"invalid_request\"}";
        assertArrayEquals(noDescription.getBytes(StandardCharsets.UTF_8), through(400, "application/json", noDescription, false));
        String clean = "{\"error\":\"invalid_request\",\"error_description\":\"already fine\"}";
        assertArrayEquals(clean.getBytes(StandardCharsets.UTF_8), through(400, "application/json", clean, false));
        String notAString = "{\"error_description\":7}";
        assertArrayEquals(notAString.getBytes(StandardCharsets.UTF_8), through(400, "application/json", notAString, false));
    }

    @Test
    void aTwoHundredBodyGoesOutAsItIsWrittenNotAtTheEnd() throws Exception {
        List<String> seenDuringChain = new ArrayList<>();
        Real[] holder = new Real[1];
        Real real = new Real();
        holder[0] = real;
        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), real.response, (req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            wrapped.setStatus(200);
            wrapped.setContentType("application/json");
            wrapped.getOutputStream().write("{\"access_token\":".getBytes(StandardCharsets.UTF_8));
            seenDuringChain.add(holder[0].text());
            wrapped.getWriter().write("\"t\"}");
            wrapped.getWriter().flush();
            seenDuringChain.add(holder[0].text());
            assertEquals(ErrorsOnly.Mode.PASSING, ((ErrorsOnly) resp).mode());
            wrapped.flushBuffer();
        });
        assertEquals(List.of("{\"access_token\":", "{\"access_token\":\"t\"}"), seenDuringChain,
                "each write reached the real response while PingFederate was still writing");
        assertTrue(real.calls.contains("flushBuffer"), "a flush of a body that passes through is a flush");
    }

    @Test
    void anErrorBodyIsHeldUntilTheEnd() throws Exception {
        Real real = new Real();
        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), real.response, (req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            wrapped.setStatus(401);
            wrapped.setContentType("application/json");
            wrapped.getWriter().write("{\"error\":\"invalid_client\"}");
            wrapped.flushBuffer();
            assertEquals(0, real.body.size(), "nothing of an error goes out before it can be checked");
            assertFalse(wrapped.isCommitted());
        });
        assertEquals("{\"error\":\"invalid_client\"}", real.text());
        assertFalse(real.calls.contains("flushBuffer"));
    }

    @Test
    void theDecisionIsTheStatusAtTheFirstByteNotWhenTheStreamWasTaken() throws Exception {
        // PingFederate may take its writer before it knows the answer is an error.
        String json = JsonUtil.toJson(Map.of("error", "invalid_request", "error_description", DIRTY));
        Real real = run((req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            var writer = wrapped.getWriter();
            wrapped.setStatus(400);
            wrapped.setContentType("application/json");
            writer.write(json);
        });
        assertEquals(OAuthErrorDescriptionFilter.withinSet(DIRTY), JsonUtil.parseJson(real.text()).get("error_description"));
    }

    @Test
    void aSendErrorAfterTheBodyWasHeldDropsWhatWasHeldAndReachesTheContainer() throws Exception {
        Real real = run((req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            wrapped.setStatus(400);
            wrapped.setContentType("application/json");
            wrapped.getOutputStream().write("{\"error\":\"half".getBytes(StandardCharsets.UTF_8));
            wrapped.sendError(500, "boom");
            wrapped.getOutputStream().write("after".getBytes(StandardCharsets.UTF_8));
            assertEquals(ErrorsOnly.Mode.SENT, ((ErrorsOnly) resp).mode());
        });
        assertEquals(List.of("sendError 500 boom"), real.calls);
        assertEquals(0, real.body.size(), "neither the held half nor what followed the error went out");

        Real plain = run((req, resp) -> {
            ((HttpServletResponse) resp).getOutputStream().write('x');
            ((HttpServletResponse) resp).sendError(404);
            ((HttpServletResponse) resp).reset();
        });
        assertEquals("sendError 404", plain.calls.get(1), "a sendError after a body that passed through reaches the container too");
    }

    @Test
    void aResetAfterTheBodyWasHeldStartsOverAndTheNextBodyIsDecidedAfresh() throws Exception {
        Real real = run((req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            wrapped.setStatus(400);
            wrapped.setContentType("application/json");
            wrapped.setContentLength(5);
            wrapped.getOutputStream().write("{\"error\":\"stale\"}".getBytes(StandardCharsets.UTF_8));
            wrapped.reset();
            assertEquals(ErrorsOnly.Mode.UNDECIDED, ((ErrorsOnly) resp).mode());
            wrapped.setStatus(200);
            wrapped.setContentType("application/json");
            wrapped.getOutputStream().write("{\"ok\":1}".getBytes(StandardCharsets.UTF_8));
            assertEquals(ErrorsOnly.Mode.PASSING, ((ErrorsOnly) resp).mode());
        });
        assertEquals("{\"ok\":1}", real.text(), "nothing held before the reset went out");
        assertTrue(real.calls.contains("reset"));
        assertNull(real.contentLength, "the length set before the reset went with it");
    }

    @Test
    void aResetBufferDropsWhatWasHeldAndKeepsHolding() throws Exception {
        Real real = run((req, resp) -> {
            HttpServletResponse wrapped = (HttpServletResponse) resp;
            wrapped.setStatus(400);
            wrapped.setContentType("application/json");
            wrapped.getOutputStream().write("junk".getBytes(StandardCharsets.UTF_8));
            wrapped.resetBuffer();
            wrapped.getOutputStream().write("{\"error\":\"invalid_request\"}".getBytes(StandardCharsets.UTF_8));
        });
        assertEquals("{\"error\":\"invalid_request\"}", real.text());
        assertFalse(real.calls.contains("resetBuffer"), "a held body's buffer is ours");

        Real passing = run((req, resp) -> {
            ((HttpServletResponse) resp).resetBuffer();
            ((HttpServletResponse) resp).getOutputStream().write('x');
            ((HttpServletResponse) resp).resetBuffer();
        });
        assertEquals(2, passing.calls.stream().filter("resetBuffer"::equals).count(), "otherwise the container's");
    }

    @Test
    void aResponseWithNoBodyKeepsItsDeclaredLength() throws Exception {
        Real real = run((req, resp) -> {
            ((HttpServletResponse) resp).setStatus(204);
            ((HttpServletResponse) resp).setContentLength(0);
        });
        assertEquals(0L, real.contentLength);
        assertEquals(0, real.body.size());
        Real none = run((req, resp) -> ((HttpServletResponse) resp).setStatus(204));
        assertNull(none.contentLength);
    }

    @Test
    void theWriterEncodesInTheResponsesCharacterSetAndKeepsASurrogatePairWhole() throws Exception {
        String emoji = "😀";
        Real real = new Real();
        real.charset = "UTF-8";
        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), real.response, (req, resp) -> {
            var writer = ((HttpServletResponse) resp).getWriter();
            writer.write(emoji.charAt(0));
            writer.write(emoji.charAt(1));
            writer.close();
        });
        assertEquals(emoji, real.text());

        Real latin = new Real();
        latin.charset = "ISO-8859-1";
        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), latin.response,
                (req, resp) -> ((HttpServletResponse) resp).getWriter().write("é"));
        assertArrayEquals(new byte[] {(byte) 0xe9}, latin.body.toByteArray());

        Real unknown = new Real();
        unknown.charset = "no-such-charset";
        new OAuthErrorDescriptionFilter().doFilter(mock(HttpServletRequest.class), unknown.response,
                (req, resp) -> ((HttpServletResponse) resp).getWriter().write("é"));
        assertEquals("é", unknown.text(), "a character set this JVM does not know is read as UTF-8");
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
        assertTrue(OAuthErrorDescriptionFilter.isError(400));
        assertTrue(OAuthErrorDescriptionFilter.isError(500));
        assertFalse(OAuthErrorDescriptionFilter.isError(399));
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
    void theStreamsAreOneEachAndAlwaysReady() throws Exception {
        Real real = new Real();
        ErrorsOnly wrapped = new ErrorsOnly(real.response);
        assertSame(wrapped.getOutputStream(), wrapped.getOutputStream());
        assertSame(wrapped.getWriter(), wrapped.getWriter());
        assertTrue(wrapped.getOutputStream().isReady());
        wrapped.getOutputStream().setWriteListener(null);
        wrapped.getOutputStream().flush();
        assertEquals(List.of(), real.calls, "a flush before any byte decides nothing");
        wrapped.getOutputStream().write(new byte[] {'a', 'b'}, 0, 2);
        wrapped.getOutputStream().flush();
        assertEquals("ab", real.text());
        assertTrue(real.calls.contains("flush"));
    }
}
