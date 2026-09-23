/*
 * Keeps PingFederate's OAuth error descriptions inside the character set RFC 6749 gives them.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * RFC 6749 §5.2: "Values for the "error_description" parameter MUST NOT include characters outside the
 * set %x20-21 / %x23-5B / %x5D-7E." When PingFederate 13.0.3 refuses a signed request object it puts
 * jose4j's whole explanation in the description, dates included, and a Java-formatted date carries
 * U+202F, the narrow no-break space, before "PM". The FAPI-CIBA conformance plan checks the set on every
 * error it provokes and fails four modules on that one character.
 *
 * <p>Mapped over the backchannel, token and PAR endpoints. An error response - a 4xx with a JSON body -
 * is buffered and its {@code error_description} rewritten with each character outside the set replaced
 * by a space; nothing else about the response changes, and a response that is not an error, not JSON, or
 * not parseable goes out byte for byte as PingFederate wrote it. The buffering is the cost: these
 * endpoints answer in a few hundred bytes, so it is a small one.
 */
public final class OAuthErrorDescriptionFilter implements Filter {

    @Override
    public void init(FilterConfig config) {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }
        HttpServletResponse http = (HttpServletResponse) response;
        Buffered buffered = new Buffered(http);
        chain.doFilter(request, buffered);
        byte[] body = buffered.bytes();
        byte[] out = buffered.getStatus() >= 400 && isJson(buffered.getContentType()) ? sanitise(body) : body;
        http.setContentLength(out.length);
        http.getOutputStream().write(out);
        http.getOutputStream().flush();
    }

    /** The body with its {@code error_description} inside the set; the body untouched when there is nothing to do. */
    static byte[] sanitise(byte[] body) {
        try {
            java.util.Map<String, Object> json = JsonUtil.parseJson(new String(body, StandardCharsets.UTF_8));
            Object description = json.get("error_description");
            if (!(description instanceof String)) {
                return body;
            }
            String clean = withinSet((String) description);
            if (clean.equals(description)) {
                return body;
            }
            java.util.Map<String, Object> rewritten = new java.util.LinkedHashMap<>(json);
            rewritten.put("error_description", clean);
            return JsonUtil.toJson(rewritten).getBytes(StandardCharsets.UTF_8);
        } catch (JoseException | RuntimeException e) {
            return body;
        }
    }

    /** Each character outside %x20-21 / %x23-5B / %x5D-7E becomes a space. */
    static String withinSet(String s) {
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            boolean allowed = (c >= 0x20 && c <= 0x21) || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
            b.append(allowed ? c : ' ');
        }
        return b.toString();
    }

    static boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase(java.util.Locale.ROOT).contains("application/json");
    }

    @Override
    public void destroy() {
    }

    /** Captures the body; status, headers and content type pass straight through to the real response. */
    static final class Buffered extends HttpServletResponseWrapper {
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private ServletOutputStream stream;
        private PrintWriter writer;

        Buffered(HttpServletResponse response) {
            super(response);
        }

        byte[] bytes() {
            if (this.writer != null) {
                this.writer.flush();
            }
            return this.bytes.toByteArray();
        }

        @Override
        public void setContentLength(int len) {
            // recomputed by the filter once the body is final
        }

        @Override
        public void setContentLengthLong(long len) {
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (this.stream == null) {
                this.stream = new ServletOutputStream() {
                    @Override
                    public void write(int b) {
                        Buffered.this.bytes.write(b);
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener listener) {
                    }
                };
            }
            return this.stream;
        }

        @Override
        public PrintWriter getWriter() {
            if (this.writer == null) {
                this.writer = new PrintWriter(new OutputStreamWriter(this.bytes, StandardCharsets.UTF_8), false);
            }
            return this.writer;
        }

        @Override
        public void flushBuffer() {
            // held back: the real response is written once, by the filter
        }
    }
}
