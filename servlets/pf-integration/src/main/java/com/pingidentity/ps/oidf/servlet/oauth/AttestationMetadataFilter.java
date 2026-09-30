/*
 * Adds the authorization server's attestation members to PingFederate's own two discovery documents.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import com.pingidentity.ps.oidf.federation.AttestationMetadataConfig;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.platform.metrics.Counter;
import com.pingidentity.ps.oidf.platform.metrics.Label;
import com.pingidentity.ps.oidf.platform.metrics.Metrics;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.WriteListener;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.jose4j.lang.JoseException;

/**
 * Over {@code /.well-known/openid-configuration} and {@code /.well-known/oauth-authorization-server} (plan item S-4,
 * F-0115): PingFederate 13.1.3 serves both itself, from its {@code controller} servlet, and neither names a challenge
 * endpoint or an attestation client authentication method. ABCA-10 §6.1 (read 2026-10-01): "If the Authorization Server
 * supports metadata as defined in [RFC8414] ..., it MUST signal support for the challenge endpoint by including the
 * metadata entry challenge_endpoint"; §8 asks the same documents for {@code attest_jwt_client_auth} and its algorithm
 * members. PingFederate has no setting for either, so this filter adds them: the member set
 * {@link AttestationMetadataConfig#extend} adds to the Entity Configuration's {@code oauth_authorization_server} block,
 * from {@link AttestationMetadataConfig#current}, the federation servlet's own configuration.
 *
 * <ul>
 *   <li>A {@code GET} answered 200 with a JSON object that names its {@code issuer} is held (up to {@value #LIMIT} bytes)
 *       and sent on with the members added: PingFederate's own members first, unchanged and in its order, and
 *       {@code challenge_endpoint} the authorization server's ({@code <issuer><context>/federation/attestation-challenge}),
 *       never the attester's. The JSON is written compact; the content is PingFederate's.</li>
 *   <li>Every other answer goes out as PingFederate wrote it, and is counted: another status, a
 *       {@code Content-Encoding} (PingFederate 13.1.3 compresses neither document, U-0029, the rig, 2026-10-01), a body
 *       that is not JSON, not an object, names no issuer or has a {@code token_endpoint_auth_methods_supported} that is
 *       not an array of strings, or one past the limit.</li>
 *   <li>With {@code ATTESTATION_AUTH} switched off, or no ABCA-10 method configured, the request is passed on untouched:
 *       nothing is held and nothing added (plan item S9b: a disabled component advertises nothing).</li>
 *   <li>A {@code HEAD} is rendered by PingFederate as the {@code GET} it describes, and answered with the extended
 *       document's {@code Content-Length} and no body.</li>
 * </ul>
 *
 * <p>It belongs to no component and has no gate: it never refuses a request, and what it adds is decided by
 * {@code ATTESTATION_AUTH}'s switch. A failure here - a configuration that cannot be read - sends PingFederate's document
 * as it came.
 */
public final class AttestationMetadataFilter implements Filter {
    private static final Log LOGGER = LogFactory.getLog(AttestationMetadataFilter.class);
    /** The most of a discovery document held; PingFederate 13.1.3's are 6218 and 4778 bytes on the rig. */
    static final int LIMIT = 256 * 1024;
    /** The two documents, by the last segment of their path. */
    static final List<String> DOCUMENTS = List.of("openid-configuration", "oauth-authorization-server");
    /** What happened to a document. */
    static final List<String> OUTCOMES = List.of("extended", "not_advertised", "status", "encoded", "not_json", "unparseable",
            "too_large", "committed", "no_configuration");

    private static final Counter ANSWERS = Metrics.counter("oidf_discovery_attestation_members_total",
            "PingFederate discovery documents the attestation metadata filter answered, by document and what it did",
            Label.oneOf("document", DOCUMENTS), Label.oneOf("outcome", OUTCOMES));

    /** At most one warning a minute about unreadable settings: every discovery request would otherwise log one. */
    static final long WARN_EVERY_MILLIS = 60_000;

    private final Supplier<AttestationMetadataConfig> configuration;
    /** When the last unreadable-settings warning was logged, as {@link System#currentTimeMillis}; 0 for never. */
    private final AtomicLong warned = new AtomicLong();

    /** The federation servlet's member set, as {@link AttestationMetadataConfig#current} gives it. */
    public AttestationMetadataFilter() {
        this(AttestationMetadataConfig::current);
    }

    /** The member set from {@code configuration}: a test's, or a consumer's that builds its own. */
    public AttestationMetadataFilter(Supplier<AttestationMetadataConfig> configuration) {
        this.configuration = configuration;
    }

    @Override
    public void init(FilterConfig config) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse out)) {
            chain.doFilter(request, response);
            return;
        }
        String document = document(http);
        AttestationMetadataConfig members;
        try {
            members = this.configuration.get();
        } catch (RuntimeException e) {
            long now = System.currentTimeMillis();
            // two requests racing past the minute may both log; that is the most it costs
            if (now - this.warned.get() >= WARN_EVERY_MILLIS) {
                this.warned.set(now);
                LOGGER.warn((Object) ("AttestationMetadataFilter: the attestation metadata settings could not be read, so "
                        + http.getRequestURI() + " goes out without its attestation members (counted in"
                        + " oidf_discovery_attestation_members_total{outcome=\"no_configuration\"}; logged at most once a minute): "
                        + e.getMessage()));
            }
            count(document, "no_configuration");
            chain.doFilter(request, response);
            return;
        }
        if (!members.advertised()) {
            count(document, "not_advertised");
            chain.doFilter(request, response);
            return;
        }
        String method = http.getMethod();
        boolean head = "HEAD".equalsIgnoreCase(method);
        if (!head && !"GET".equalsIgnoreCase(method)) {
            chain.doFilter(request, response);
            return;
        }
        Held held = new Held(out);
        // A HEAD is rendered as the GET it describes, so that its Content-Length is the extended document's; no body is sent.
        chain.doFilter(head ? new AsGet(http) : http, held);
        this.finish(http, out, held, members, document, head);
    }

    /** Sends PingFederate's document with the members added, or as it came. */
    void finish(HttpServletRequest request, HttpServletResponse out, Held held, AttestationMetadataConfig members, String document,
            boolean head) throws IOException {
        byte[] body = held.close();
        if (body == null) {
            count(document, "too_large");
            return;
        }
        if (out.isCommitted()) {
            // PingFederate answered past the wrapper (sendError, say): what it wrote has gone, and nothing held can follow.
            LOGGER.warn((Object) ("AttestationMetadataFilter: the response was committed past the filter; " + body.length
                    + " held bytes are dropped"));
            count(document, "committed");
            return;
        }
        String outcome;
        byte[] sent = body;
        if (held.getStatus() != 200) {
            outcome = "status";
        } else if (held.encoded()) {
            LOGGER.warn((Object) ("AttestationMetadataFilter: " + request.getRequestURI() + " came with Content-Encoding "
                    + held.encoding() + " and goes out without its attestation members; PingFederate 13.1.3 compresses neither"
                    + " discovery document"));
            outcome = "encoded";
        } else if (!isJson(held.getContentType())) {
            outcome = "not_json";
        } else {
            byte[] extended = extended(body, members, request.getContextPath());
            if (extended == null) {
                LOGGER.warn((Object) ("AttestationMetadataFilter: " + request.getRequestURI() + " is not a discovery document"
                        + " this filter can extend, and goes out as PingFederate wrote it"));
                outcome = "unparseable";
            } else {
                outcome = "extended";
                sent = extended;
            }
        }
        count(document, outcome);
        out.setContentLength(sent.length);
        if (head) {
            return;
        }
        ServletOutputStream stream = out.getOutputStream();
        stream.write(sent);
        stream.flush();
    }

    /**
     * {@code body} with the members added, as UTF-8 JSON; null when it is not a JSON object naming its {@code issuer}, or
     * {@link AttestationMetadataConfig#extend} cannot extend it.
     */
    static byte[] extended(byte[] body, AttestationMetadataConfig members, String contextPath) {
        Map<String, Object> json;
        Object named;
        try {
            json = JsonUtil.parseJson(new String(body, StandardCharsets.UTF_8));
            named = json.get("issuer");
        } catch (JoseException | RuntimeException e) {
            return null;
        }
        if (!(named instanceof String issuer) || issuer.isBlank()) {
            return null;
        }
        String context = contextPath == null || "/".equals(contextPath) ? "" : contextPath;
        Map<String, Object> out = members.extend(json, EntityId.comparable(issuer) + context + AttestationMetadataConfig.CHALLENGE_PATH);
        return out == null ? null : JsonUtil.toJson(out).getBytes(StandardCharsets.UTF_8);
    }

    static boolean isJson(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).trim().startsWith("application/json");
    }

    /** Which of the two documents {@code request} asked for, by the last segment of its path. */
    static String document(HttpServletRequest request) {
        String uri = request.getRequestURI();
        for (String document : DOCUMENTS) {
            if (uri != null && uri.contains("/" + document)) {
                return document;
            }
        }
        return Label.OTHER;
    }

    private static void count(String document, String outcome) {
        ANSWERS.inc(document, outcome);
    }

    /** The count for {@code document} and {@code outcome}, for tests. */
    static long counted(String document, String outcome) {
        return ANSWERS.get(document, outcome);
    }

    /** A {@code HEAD} request as the {@code GET} whose headers it asks for. */
    static final class AsGet extends HttpServletRequestWrapper {
        AsGet(HttpServletRequest request) {
            super(request);
        }

        @Override
        public String getMethod() {
            return "GET";
        }
    }

    /**
     * The wrapped response: the body is held, up to {@link #LIMIT} bytes, and past that what is held goes out and the rest
     * streams after it. Status and headers go to the real response, but for a content length and a flush, which are held
     * back while the body is.
     */
    static final class Held extends HttpServletResponseWrapper {
        private final HttpServletResponse real;
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private long count;
        private boolean streamedOut;
        private Long contentLength;
        private String encoding;
        private ServletOutputStream stream;
        private PrintWriter writer;

        Held(HttpServletResponse real) {
            super(real);
            this.real = real;
        }

        boolean encoded() {
            return this.encoding != null && !this.encoding.isBlank() && !"identity".equalsIgnoreCase(this.encoding.trim());
        }

        String encoding() {
            return this.encoding;
        }

        /** The held body, once PingFederate is done; null when it was past the limit and has been streamed out. */
        byte[] close() throws IOException {
            if (this.writer != null) {
                this.writer.flush();
            }
            if (this.streamedOut) {
                this.real.getOutputStream().flush();
                return null;
            }
            return this.bytes.toByteArray();
        }

        private void write(int b) throws IOException {
            if (this.streamedOut) {
                this.real.getOutputStream().write(b);
                return;
            }
            this.count++;
            if (this.count <= LIMIT) {
                this.bytes.write(b);
                return;
            }
            // Too large to be a discovery document: what is held goes out, and the rest streams after it.
            this.streamedOut = true;
            if (this.contentLength != null) {
                this.real.setContentLengthLong(this.contentLength);
            }
            ServletOutputStream out = this.real.getOutputStream();
            this.bytes.writeTo(out);
            this.bytes.reset();
            out.write(b);
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (this.stream == null) {
                this.stream = new ServletOutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        Held.this.write(b);
                    }

                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener listener) {
                        throw new IllegalStateException("the discovery document is held; it is not written asynchronously");
                    }
                };
            }
            return this.stream;
        }

        @Override
        public PrintWriter getWriter() {
            if (this.writer == null) {
                this.writer = new PrintWriter(new OutputStreamWriter(this.getOutputStream(), StandardCharsets.UTF_8), false);
            }
            return this.writer;
        }

        @Override
        public void flushBuffer() throws IOException {
            if (this.streamedOut) {
                this.real.flushBuffer();
            }
        }

        @Override
        public void setContentLength(int len) {
            this.setContentLengthLong(len);
        }

        @Override
        public void setContentLengthLong(long len) {
            if (this.streamedOut) {
                this.real.setContentLengthLong(len);
            } else {
                this.contentLength = len;
            }
        }

        @Override
        public void setHeader(String name, String value) {
            if (this.passes(name, value)) {
                super.setHeader(name, value);
            }
        }

        @Override
        public void addHeader(String name, String value) {
            if (this.passes(name, value)) {
                super.addHeader(name, value);
            }
        }

        @Override
        public void setIntHeader(String name, int value) {
            if (this.passes(name, Integer.toString(value))) {
                super.setIntHeader(name, value);
            }
        }

        @Override
        public void addIntHeader(String name, int value) {
            if (this.passes(name, Integer.toString(value))) {
                super.addIntHeader(name, value);
            }
        }

        /** Notes a Content-Encoding and holds back a Content-Length; answers whether the header goes to the real response. */
        private boolean passes(String name, String value) {
            if ("Content-Encoding".equalsIgnoreCase(name)) {
                this.encoding = value;
            }
            if ("Content-Length".equalsIgnoreCase(name) && !this.streamedOut) {
                try {
                    this.contentLength = Long.parseLong(value.trim());
                } catch (NumberFormatException | NullPointerException e) {
                    this.contentLength = null;
                }
                return false;
            }
            return true;
        }
    }
}
