/*
 * One outbound HTTP request: method, URL, headers, body and its own limits.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * An outbound request. Headers are allowed on every method; a body on every method but GET. The headers that
 * frame the message - {@code Host}, {@code Content-Length}, {@code Transfer-Encoding}, {@code Connection} and the
 * like - are {@link OutboundHttp}'s to write and are refused here, as is any name that is not an HTTP token and any
 * value with a control character or a byte outside printable ASCII, so a header cannot split the request.
 *
 * <p>The connect and header timeouts and the body cap default to the client's; a request may set its own.
 */
public final class OutboundRequest {

    /** The methods {@link OutboundHttp} sends. */
    public enum Method { GET, POST, PUT, PATCH, DELETE }

    /**
     * The largest request body. Writes are not bounded by the deadline (U-0195), so this limits how much a write can
     * be left waiting on when the peer stops reading; whether a body this size fits the socket buffers, so that the
     * write returns without the peer reading, is U-0195's open question (on macOS and JDK 17, on 2026-09-28, a 1 MiB
     * write to a peer that never read returned about 4 s after a 1 s deadline).
     */
    public static final int MAX_REQUEST_BODY_BYTES = 1 << 20;

    /** Header names the client writes itself, lower case. */
    static final Set<String> RESERVED_HEADERS = Set.of("host", "content-length", "transfer-encoding", "connection",
            "keep-alive", "proxy-connection", "upgrade", "te", "trailer", "expect");

    private final Method method;
    private final URI uri;
    private final List<String[]> headers;
    private final byte[] body;
    private final Duration connectTimeout;
    private final Duration headerTimeout;
    private final long maxBodyBytes;

    private OutboundRequest(Builder builder) {
        this.method = builder.method;
        this.uri = builder.uri;
        this.headers = List.copyOf(builder.headers);
        this.body = builder.body;
        this.connectTimeout = builder.connectTimeout;
        this.headerTimeout = builder.headerTimeout;
        this.maxBodyBytes = builder.maxBodyBytes;
    }

    public static Builder builder(Method method, URI uri) {
        return new Builder(method, uri);
    }

    public static Builder get(String url) {
        return builder(Method.GET, URI.create(url));
    }

    public static Builder post(String url) {
        return builder(Method.POST, URI.create(url));
    }

    /** Builds an {@link OutboundRequest}. */
    public static final class Builder {
        private final Method method;
        private final URI uri;
        private final List<String[]> headers = new ArrayList<>();
        private byte[] body;
        private Duration connectTimeout;
        private Duration headerTimeout;
        private long maxBodyBytes = -1L;

        private Builder(Method method, URI uri) {
            this.method = Objects.requireNonNull(method, "method");
            this.uri = Objects.requireNonNull(uri, "uri");
        }

        /** Adds a header; a name may repeat. */
        public Builder header(String name, String value) {
            checkHeader(name, value);
            this.headers.add(new String[] {name, value});
            return this;
        }

        /** The body, sent with {@code Content-Type: contentType} and its length. */
        public Builder body(String contentType, byte[] content) {
            Objects.requireNonNull(content, "content");
            if (this.method == Method.GET) {
                throw new IllegalArgumentException("a GET carries no body");
            }
            if (content.length > MAX_REQUEST_BODY_BYTES) {
                throw new IllegalArgumentException("a request body is at most " + MAX_REQUEST_BODY_BYTES + " bytes");
            }
            header("Content-Type", contentType);
            this.body = content.clone();
            return this;
        }

        /** The body as UTF-8 text. */
        public Builder body(String contentType, String content) {
            return body(contentType, Objects.requireNonNull(content, "content").getBytes(StandardCharsets.UTF_8));
        }

        /** How long connecting, TLS included, may take; the client's default otherwise. */
        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = positive(timeout, "connectTimeout");
            return this;
        }

        /** How long, from connecting, the status line and headers may take; the client's default otherwise. */
        public Builder headerTimeout(Duration timeout) {
            this.headerTimeout = positive(timeout, "headerTimeout");
            return this;
        }

        /** The largest response body accepted; the client's default otherwise. */
        public Builder maxBodyBytes(long max) {
            this.maxBodyBytes = notNegative(max);
            return this;
        }

        public OutboundRequest build() {
            return new OutboundRequest(this);
        }
    }

    public Method method() {
        return this.method;
    }

    public URI uri() {
        return this.uri;
    }

    /** The headers as name-value pairs, in the order added. */
    public List<String[]> headers() {
        List<String[]> copy = new ArrayList<>(this.headers.size());
        for (String[] header : this.headers) {
            copy.add(header.clone());
        }
        return copy;
    }

    /** The body, or null when there is none. */
    public byte[] body() {
        return this.body == null ? null : this.body.clone();
    }

    /** The request's own connect timeout, or null for the client's. */
    public Duration connectTimeout() {
        return this.connectTimeout;
    }

    /** The request's own header timeout, or null for the client's. */
    public Duration headerTimeout() {
        return this.headerTimeout;
    }

    /** The request's own body cap, or -1 for the client's. */
    public long maxBodyBytes() {
        return this.maxBodyBytes;
    }

    /** Refuses a header the client writes itself, a name that is not a token, or a value that could split the message. */
    static void checkHeader(String name, String value) {
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(value, "value");
        if (name.isEmpty() || !name.chars().allMatch(OutboundRequest::isTokenChar)) {
            throw new IllegalArgumentException("not an HTTP header name: " + name);
        }
        if (RESERVED_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException("the client writes " + name + " itself");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c < 0x20 && c != '\t') || c > 0x7E) {
                throw new IllegalArgumentException("header " + name + " has a control or non-ASCII character at " + i);
            }
        }
    }

    /** An RFC 9110 tchar. */
    static boolean isTokenChar(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }

    static long notNegative(long max) {
        if (max < 0) {
            throw new IllegalArgumentException("maxBodyBytes must not be negative");
        }
        return max;
    }

    static Duration positive(Duration timeout, String what) {
        Objects.requireNonNull(timeout, what);
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException(what + " must be positive");
        }
        return timeout;
    }
}
