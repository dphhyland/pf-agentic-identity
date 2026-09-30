/*
 * Keeps PingFederate's OAuth error descriptions inside the character set RFC 6749 gives them.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * RFC 6749 §5.2: "Values for the "error_description" parameter MUST NOT include characters outside the
 * set %x20-21 / %x23-5B / %x5D-7E." When PingFederate 13.0.3 refuses a signed request object it puts
 * jose4j's whole explanation in the description, dates included, and a Java-formatted date carries
 * U+202F, the narrow no-break space, before "PM". The FAPI-CIBA conformance plan checks the set on every
 * error it provokes and fails four modules on that one character.
 *
 * <p>Mapped over the backchannel, token and PAR endpoints. An error response - an error status with a JSON body - is
 * held and its {@code error_description} rewritten with each character outside the set replaced by a space; nothing
 * else about the response changes, and an error that is not JSON, or not parseable, goes out byte for byte as
 * PingFederate wrote it.
 *
 * <p><b>Only an error is held</b> (plan item H-FED-6, finding F-0048). The body is decided on at its first byte: if the
 * status set by then is an error (400 or above), the body is held until PingFederate is done; otherwise it goes
 * straight to the real response, unheld - a token response is never buffered. PingFederate's other ways of ending a
 * response are followed, not lost: {@code sendError} after the body was held drops what was held and sends the error
 * as the container would; {@code reset} drops what was held and the decision with it, so the next body is decided on
 * afresh; {@code resetBuffer} drops what was held and keeps the decision; {@code flushBuffer} while holding waits for
 * the end, and while passing through flushes.
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
        ErrorsOnly wrapped = new ErrorsOnly(http);
        chain.doFilter(request, wrapped);
        wrapped.finish();
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

    /** Whether {@code status} is one whose body is held: an error. */
    static boolean isError(int status) {
        return status >= 400;
    }

    @Override
    public void destroy() {
    }

    /**
     * The response PingFederate writes to. Status, headers and content type pass straight through; the body is held
     * only when the status is an error at its first byte ({@link Mode}).
     */
    static final class ErrorsOnly extends HttpServletResponseWrapper {
        /** What happens to the body: not yet decided, held, passed through, or ended by {@code sendError}. */
        enum Mode { UNDECIDED, HOLDING, PASSING, SENT }

        private final HttpServletResponse real;
        private final ByteArrayOutputStream held = new ByteArrayOutputStream();
        private Mode mode = Mode.UNDECIDED;
        private ServletOutputStream stream;
        private PrintWriter writer;
        private Integer contentLength;

        ErrorsOnly(HttpServletResponse response) {
            super(response);
            this.real = response;
        }

        Mode mode() {
            return this.mode;
        }

        /** Decides, at the body's first byte, whether it is held. */
        private Mode decide() {
            if (this.mode == Mode.UNDECIDED) {
                this.mode = isError(this.real.getStatus()) ? Mode.HOLDING : Mode.PASSING;
                if (this.mode == Mode.PASSING && this.contentLength != null) {
                    this.real.setContentLengthLong(this.contentLength);
                }
            }
            return this.mode;
        }

        void write(int b) throws IOException {
            switch (this.decide()) {
                case HOLDING -> this.held.write(b);
                case PASSING -> this.real.getOutputStream().write(b);
                default -> { } // after sendError the response is committed: what follows is dropped, as the container drops it
            }
        }

        void write(byte[] b, int off, int len) throws IOException {
            switch (this.decide()) {
                case HOLDING -> this.held.write(b, off, len);
                case PASSING -> this.real.getOutputStream().write(b, off, len);
                default -> { }
            }
        }

        /** Sends what was held, sanitised; called once the chain is done. */
        void finish() throws IOException {
            if (this.writer != null) {
                this.writer.flush();
            }
            if (this.mode == Mode.HOLDING) {
                byte[] body = this.held.toByteArray();
                byte[] out = isError(this.real.getStatus()) && isJson(this.real.getContentType()) ? sanitise(body) : body;
                this.real.setContentLength(out.length);
                this.real.getOutputStream().write(out);
                this.real.getOutputStream().flush();
            } else if (this.mode == Mode.UNDECIDED && this.contentLength != null && !this.real.isCommitted()) {
                // No body was written: the length PingFederate declared is its to keep.
                this.real.setContentLengthLong(this.contentLength);
            }
        }

        @Override
        public void setContentLength(int len) {
            this.setContentLengthLong(len);
        }

        @Override
        public void setContentLengthLong(long len) {
            if (this.mode == Mode.PASSING) {
                this.real.setContentLengthLong(len);
            } else if (this.mode == Mode.UNDECIDED) {
                // Recomputed for a held body; passed on for one that goes through.
                this.contentLength = (int) Math.min(len, Integer.MAX_VALUE);
            }
        }

        @Override
        public void sendError(int sc) throws IOException {
            this.dropHeld(Mode.SENT);
            this.real.sendError(sc);
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {
            this.dropHeld(Mode.SENT);
            this.real.sendError(sc, msg);
        }

        @Override
        public void reset() {
            this.dropHeld(Mode.UNDECIDED);
            this.contentLength = null;
            this.real.reset();
        }

        @Override
        public void resetBuffer() {
            if (this.mode == Mode.HOLDING) {
                this.held.reset();
            } else {
                this.real.resetBuffer();
            }
        }

        @Override
        public void flushBuffer() throws IOException {
            if (this.mode != Mode.HOLDING) {
                if (this.writer != null && this.mode == Mode.PASSING) {
                    this.writer.flush();
                }
                this.real.flushBuffer();
            }
        }

        @Override
        public boolean isCommitted() {
            return this.mode == Mode.HOLDING ? false : this.real.isCommitted();
        }

        private void dropHeld(Mode next) {
            this.held.reset();
            if (this.mode != Mode.SENT) {
                this.mode = next;
            }
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (this.stream == null) {
                this.stream = new ServletOutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        ErrorsOnly.this.write(b);
                    }

                    @Override
                    public void write(byte[] b, int off, int len) throws IOException {
                        ErrorsOnly.this.write(b, off, len);
                    }

                    @Override
                    public void flush() throws IOException {
                        if (ErrorsOnly.this.mode == Mode.PASSING) {
                            ErrorsOnly.this.real.getOutputStream().flush();
                        }
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
                this.writer = new PrintWriter(new Writer() {
                    /** A high surrogate whose low half has not been written yet: encoded with it, never alone. */
                    private char pending;

                    @Override
                    public void write(char[] chars, int off, int len) throws IOException {
                        StringBuilder text = new StringBuilder(len + 1);
                        if (this.pending != 0) {
                            text.append(this.pending);
                            this.pending = 0;
                        }
                        text.append(chars, off, len);
                        if (text.length() > 0 && Character.isHighSurrogate(text.charAt(text.length() - 1))) {
                            this.pending = text.charAt(text.length() - 1);
                            text.setLength(text.length() - 1);
                        }
                        byte[] bytes = text.toString().getBytes(ErrorsOnly.this.charset());
                        ErrorsOnly.this.write(bytes, 0, bytes.length);
                    }

                    @Override
                    public void flush() throws IOException {
                        if (ErrorsOnly.this.mode == Mode.PASSING) {
                            ErrorsOnly.this.real.getOutputStream().flush();
                        }
                    }

                    @Override
                    public void close() throws IOException {
                        this.flush();
                    }
                }, false);
            }
            return this.writer;
        }

        /** The response's character set, UTF-8 when it names none or one this JVM does not know. */
        java.nio.charset.Charset charset() {
            String name = this.real.getCharacterEncoding();
            try {
                return name == null ? StandardCharsets.UTF_8 : java.nio.charset.Charset.forName(name);
            } catch (RuntimeException e) {
                return StandardCharsets.UTF_8;
            }
        }
    }
}
