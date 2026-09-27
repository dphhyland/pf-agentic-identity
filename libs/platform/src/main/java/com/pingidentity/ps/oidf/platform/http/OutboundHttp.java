/*
 * Platform's outbound HTTP client: pinned to checked addresses, bounded in time and size.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.impl.io.DefaultBHttpClientConnection;
import org.apache.hc.core5.http.impl.io.DefaultHttpResponseParserFactory;
import org.apache.hc.core5.http.io.entity.ByteArrayEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;

/**
 * GET, POST, PUT, PATCH and DELETE over HTTP/1.1, one request per connection, with the connection pinned to an
 * address the {@link AddressPolicy} checked (plan item S5a, part 1).
 *
 * <p>An exchange:
 * <ol>
 *   <li>The policy checks the URL and resolves the host once, checking every address.</li>
 *   <li>The {@link Bulkhead} lets the request in (by default it always does).</li>
 *   <li>A socket connects to the first checked address that accepts within the connect deadline - the sooner of the
 *       connect timeout and the total - trying the next on failure. Nothing resolves the name again.</li>
 *   <li>For {@code https}, TLS is layered on that socket with the URL's host as the server name (SNI, unless the host
 *       is an IP literal) and HTTPS endpoint identification on, so the certificate is checked against the name, not
 *       the address. TLS 1.3 and 1.2 only. The handshake is part of the connect deadline.</li>
 *   <li>The request goes out with {@code Host}, {@code Connection: close} and, for a body, {@code Content-Length};
 *       the status line and headers must arrive within the header deadline (the sooner of the header timeout, counted
 *       from here, and the total).</li>
 *   <li>The body is read within the total deadline and the cap: a declared length over the cap is refused before a
 *       byte is read, and a chunked or close-delimited body is refused as soon as it passes the cap.</li>
 * </ol>
 * Every read on the socket - the handshake's included - waits no longer than what is left of the deadline for its
 * phase ({@link DeadlineSocket}), so the total holds without a watchdog thread. Writes are not bounded (U-0195):
 * a request body is at most {@link OutboundRequest#MAX_REQUEST_BODY_BYTES}.
 *
 * <p>Redirects are not followed: a 3xx is returned like any status, and following it is a new request through the
 * policy. A response of any status is returned; only a missing response throws, as {@link OutboundHttpException}
 * with its {@link OutboundHttpException.Reason}.
 *
 * <p>The HTTP/1.1 message layer - the request writer, the status-line and header parser, and the chunked,
 * length-delimited and close-delimited body decoders - is Apache HttpComponents Core 5's classic I/O, shaded into
 * platform and relocated; this class adds the limits and checks around it: at most {@value #MAX_HEADER_COUNT}
 * headers of at most {@value #MAX_LINE_LENGTH} bytes a line, HTTP/1.0 or 1.1 only, a status of 100-599, no 101,
 * at most {@value #MAX_INTERIM_RESPONSES} interim responses, and a response carrying both {@code Transfer-Encoding} and
 * {@code Content-Length}, more than one {@code Content-Length}, or one that is not plain digits refused as malformed.
 */
public final class OutboundHttp {
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);
    public static final Duration DEFAULT_HEADER_TIMEOUT = Duration.ofSeconds(10);
    /** Entity statements and JWKS documents are small; 256 KiB is generous (oidf-jose's cap). */
    public static final long DEFAULT_MAX_BODY_BYTES = 256L * 1024L;
    public static final int MAX_HEADER_COUNT = 100;
    public static final int MAX_LINE_LENGTH = 8192;
    public static final int MAX_INTERIM_RESPONSES = 8;
    static final String[] TLS_PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

    private static final Http1Config HTTP1 = Http1Config.custom()
            .setVersion(HttpVersion.HTTP_1_1)
            // HttpCore refuses once the count it has read reaches its limit (AbstractMessageParser.parseHeaders,
            // 5.4.4), so it is given one more than the most this accepts.
            .setMaxHeaderCount(MAX_HEADER_COUNT + 1)
            .setMaxLineLength(MAX_LINE_LENGTH)
            .setMaxEmptyLineCount(2)
            .setBufferSize(8192)
            .build();

    private final AddressPolicy policy;
    private final TlsTrust tls;
    private final Bulkhead bulkhead;
    private final Duration connectTimeout;
    private final Duration headerTimeout;
    private final long maxBodyBytes;
    private final String userAgent;

    private OutboundHttp(Builder builder) {
        this.policy = builder.policy;
        this.tls = builder.tls;
        this.bulkhead = builder.bulkhead;
        this.connectTimeout = builder.connectTimeout;
        this.headerTimeout = builder.headerTimeout;
        this.maxBodyBytes = builder.maxBodyBytes;
        this.userAgent = builder.userAgent;
    }

    public static Builder builder(AddressPolicy policy) {
        return new Builder(policy);
    }

    /** Builds an {@link OutboundHttp}. */
    public static final class Builder {
        private final AddressPolicy policy;
        private TlsTrust tls;
        private Bulkhead bulkhead = Bulkhead.NONE;
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration headerTimeout = DEFAULT_HEADER_TIMEOUT;
        private long maxBodyBytes = DEFAULT_MAX_BODY_BYTES;
        private String userAgent = "pf-agentic-identity";

        private Builder(AddressPolicy policy) {
            this.policy = Objects.requireNonNull(policy, "policy");
        }

        /** The TLS trust; the JVM's by default. */
        public Builder tls(TlsTrust trust) {
            this.tls = Objects.requireNonNull(trust, "trust");
            return this;
        }

        public Builder bulkhead(Bulkhead value) {
            this.bulkhead = Objects.requireNonNull(value, "bulkhead");
            return this;
        }

        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = OutboundRequest.positive(timeout, "connectTimeout");
            return this;
        }

        public Builder headerTimeout(Duration timeout) {
            this.headerTimeout = OutboundRequest.positive(timeout, "headerTimeout");
            return this;
        }

        public Builder maxBodyBytes(long max) {
            this.maxBodyBytes = OutboundRequest.notNegative(max);
            return this;
        }

        /** The {@code User-Agent} sent when a request sets none. */
        public Builder userAgent(String value) {
            OutboundRequest.checkHeader("User-Agent", value);
            this.userAgent = value;
            return this;
        }

        public OutboundHttp build() {
            if (this.tls == null) {
                this.tls = TlsTrust.jvmDefault();
            }
            return new OutboundHttp(this);
        }
    }

    public AddressPolicy policy() {
        return this.policy;
    }

    /** GETs {@code url} with {@code Accept: accept}. */
    public OutboundResponse get(String url, String accept, Deadline total) throws OutboundHttpException {
        return send(OutboundRequest.builder(OutboundRequest.Method.GET, uri(url)).header("Accept", accept).build(), total);
    }

    /** Sends {@code request}, spending one of the budget's requests and bounded by its deadline. */
    public OutboundResponse send(OutboundRequest request, Budget budget) throws OutboundHttpException {
        Objects.requireNonNull(request, "request");
        Deadline total = Objects.requireNonNull(budget, "budget").spend(request.uri().toString());
        return send(request, total);
    }

    /**
     * Sends {@code request} and reads the whole response by {@code total}.
     *
     * @return the response, whatever its status
     * @throws OutboundHttpException when there is no response, with the reason
     */
    public OutboundResponse send(OutboundRequest request, Deadline total) throws OutboundHttpException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(total, "total");
        if (total.expired()) {
            throw new OutboundHttpException(OutboundHttpException.Reason.DEADLINE,
                    "not fetching " + request.uri() + ": the deadline has already passed");
        }
        AddressPolicy.Target target = this.policy.check(request.uri());
        if (total.expired()) {
            throw new OutboundHttpException(OutboundHttpException.Reason.DEADLINE,
                    "the deadline passed while resolving " + target.host());
        }
        try (Bulkhead.Permit permit = this.bulkhead.enter(target.origin(), total)) {
            return exchange(request, target, total);
        }
    }

    private OutboundResponse exchange(OutboundRequest request, AddressPolicy.Target target, Deadline total)
            throws OutboundHttpException {
        Deadline connectBy = total.sooner(orDefault(request.connectTimeout(), this.connectTimeout));
        DeadlineSocket socket = connect(target, connectBy, total);
        try {
            SSLSocket ssl = target.tls() ? handshake(socket, target) : null;
            socket.readBy(total.sooner(orDefault(request.headerTimeout(), this.headerTimeout)), DeadlineSocket.Phase.HEADERS);
            // The parser takes its limits from its own factory, not from the connection's config (HttpCore 5.4.4's
            // DefaultHttpResponseParserFactory.INSTANCE parses with Http1Config.DEFAULT), so it is given them too.
            DefaultBHttpClientConnection connection = new DefaultBHttpClientConnection(HTTP1, null, null, null, null,
                    null, new DefaultHttpResponseParserFactory(HTTP1));
            if (ssl != null) {
                connection.bind(ssl, socket);
            } else {
                connection.bind(socket);
            }
            BasicClassicHttpRequest message = message(request, target);
            connection.sendRequestHeader(message);
            connection.sendRequestEntity(message);
            connection.flush();
            ClassicHttpResponse head = head(connection);
            long cap = request.maxBodyBytes() >= 0 ? request.maxBodyBytes() : this.maxBodyBytes;
            boolean hasBody = framing(head, cap, target);
            byte[] body = new byte[0];
            if (hasBody) {
                socket.readBy(total, DeadlineSocket.Phase.BODY);
                connection.receiveResponseEntity(head);
                body = readCapped(head.getEntity(), cap, target);
            }
            List<OutboundResponse.Header> headers = new ArrayList<>();
            for (Header header : head.getHeaders()) {
                headers.add(new OutboundResponse.Header(header.getName(), header.getValue()));
            }
            return new OutboundResponse(head.getCode(), Objects.toString(head.getReasonPhrase(), ""), headers, body,
                    (InetSocketAddress) socket.getRemoteSocketAddress());
        } catch (OutboundHttpException e) {
            throw e;
        } catch (IOException | HttpException | RuntimeException e) {
            throw failure(e, socket, total, target);
        } finally {
            closeQuietly(socket);
        }
    }

    /** Connects to the first checked address that accepts before {@code connectBy}. */
    DeadlineSocket connect(AddressPolicy.Target target, Deadline connectBy, Deadline total) throws OutboundHttpException {
        IOException last = null;
        boolean timedOut = false;
        for (InetAddress address : target.addresses()) {
            int millis = connectBy.timeoutMillis();
            if (millis == 0) {
                timedOut = true;
                break;
            }
            DeadlineSocket socket = new DeadlineSocket(connectBy);
            try {
                socket.connect(new InetSocketAddress(address, target.port()), millis);
                return socket;
            } catch (IOException e) {
                timedOut |= e instanceof SocketTimeoutException;
                last = e;
            }
            closeQuietly(socket);
        }
        if (timedOut) {
            throw timeout(total, OutboundHttpException.Reason.CONNECT_TIMEOUT, "connecting to " + target.origin(), last);
        }
        throw new OutboundHttpException(OutboundHttpException.Reason.CONNECT_FAILED,
                "no address of " + target.host() + " accepted a connection on port " + target.port(), last);
    }

    /** Layers TLS on {@code socket}: the host as SNI, the certificate checked against the host. */
    SSLSocket handshake(DeadlineSocket socket, AddressPolicy.Target target) throws IOException {
        SSLSocket ssl = (SSLSocket) this.tls.socketFactory().createSocket(socket, target.host(), target.port(), true);
        SSLParameters parameters = ssl.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setProtocols(TLS_PROTOCOLS.clone());
        if (!AddressPolicy.isLiteral(target.host())) {
            parameters.setServerNames(List.of(new SNIHostName(target.host())));
        }
        ssl.setSSLParameters(parameters);
        ssl.startHandshake();
        return ssl;
    }

    /** The request as HttpCore writes it: origin-form target, Host, the caller's headers, framing, Connection: close. */
    BasicClassicHttpRequest message(OutboundRequest request, AddressPolicy.Target target) {
        URI uri = target.uri();
        // The policy passed only URIs with a host, which are hierarchical and so have a raw path, if an empty one.
        String path = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        String requestTarget = uri.getRawQuery() == null ? path : path + "?" + uri.getRawQuery();
        BasicClassicHttpRequest message = new BasicClassicHttpRequest(request.method().name(), requestTarget);
        message.setVersion(HttpVersion.HTTP_1_1);
        message.addHeader("Host", uri.getRawAuthority());
        boolean userAgent = false;
        for (String[] header : request.headers()) {
            message.addHeader(header[0], header[1]);
            userAgent |= header[0].equalsIgnoreCase("User-Agent");
        }
        if (!userAgent) {
            message.addHeader("User-Agent", this.userAgent);
        }
        byte[] body = request.body();
        if (body != null) {
            message.addHeader("Content-Length", Integer.toString(body.length));
            message.setEntity(new ByteArrayEntity(body, null));
        } else if (request.method() != OutboundRequest.Method.GET && request.method() != OutboundRequest.Method.DELETE) {
            message.addHeader("Content-Length", "0");
        }
        message.addHeader("Connection", "close");
        return message;
    }

    /** The final response head, after at most {@value #MAX_INTERIM_RESPONSES} interim ones. */
    static ClassicHttpResponse head(DefaultBHttpClientConnection connection) throws IOException, HttpException {
        for (int interim = 0; ; interim++) {
            ClassicHttpResponse head = connection.receiveResponseHeader();
            int code = head.getCode();
            if (code >= 200) {
                return head;
            }
            if (code == 101) {
                throw new OutboundHttpException(OutboundHttpException.Reason.MALFORMED_RESPONSE,
                        "the server switched protocols, which was never asked for");
            }
            if (interim >= MAX_INTERIM_RESPONSES) {
                throw new OutboundHttpException(OutboundHttpException.Reason.MALFORMED_RESPONSE,
                        "more than " + MAX_INTERIM_RESPONSES + " interim responses");
            }
        }
    }

    /**
     * Checks the head's version, status and framing; refuses a declared length over {@code cap}. Returns whether a
     * body follows.
     */
    static boolean framing(ClassicHttpResponse head, long cap, AddressPolicy.Target target) throws OutboundHttpException {
        if (head.getVersion().getMajor() != 1 || head.getVersion().getMinor() > 1) {
            throw malformed("an HTTP version other than 1.0 or 1.1: " + head.getVersion());
        }
        int code = head.getCode();
        if (code > 599) {
            throw malformed("status " + code + " is out of range");
        }
        Header[] lengths = head.getHeaders("Content-Length");
        boolean chunked = head.containsHeader("Transfer-Encoding");
        if (chunked && lengths.length > 0) {
            throw malformed("both Transfer-Encoding and Content-Length");
        }
        if (lengths.length > 1) {
            throw malformed("more than one Content-Length");
        }
        if (code == 204 || code == 304) {
            return false;
        }
        if (lengths.length == 1) {
            String value = lengths[0].getValue();
            if (value.isEmpty() || value.length() > 18 || !value.chars().allMatch(c -> c >= '0' && c <= '9')) {
                throw malformed("Content-Length is not a length: " + LogText.clip(value));
            }
            long declared = Long.parseLong(value);
            if (declared > cap) {
                throw new OutboundHttpException(OutboundHttpException.Reason.BODY_TOO_LARGE, target.origin()
                        + " declares a " + declared + "-byte body, over the " + cap + "-byte cap");
            }
            return declared > 0;
        }
        return true;
    }

    /** Reads the body, refusing it once it passes {@code cap}. */
    static byte[] readCapped(HttpEntity entity, long cap, AddressPolicy.Target target) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        try (InputStream in = entity.getContent()) {
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > cap) {
                    throw new OutboundHttpException(OutboundHttpException.Reason.BODY_TOO_LARGE,
                            target.origin() + " sent a body over the " + cap + "-byte cap");
                }
                buffer.write(chunk, 0, read);
            }
        }
        return buffer.toByteArray();
    }

    /** Names a failure by what went wrong and when. */
    static OutboundHttpException failure(Exception e, DeadlineSocket socket, Deadline total, AddressPolicy.Target target) {
        if (socket.timedOut()) {
            switch (socket.phase()) {
                case CONNECT:
                    return timeout(total, OutboundHttpException.Reason.CONNECT_TIMEOUT, "the TLS handshake with " + target.origin(), e);
                case HEADERS:
                    return timeout(total, OutboundHttpException.Reason.HEADER_TIMEOUT, "the response head from " + target.origin(), e);
                default:
                    return timeout(total, OutboundHttpException.Reason.DEADLINE, "the response body from " + target.origin(), e);
            }
        }
        if (socket.phase() == DeadlineSocket.Phase.CONNECT && causedBy(e, SSLException.class)) {
            return new OutboundHttpException(OutboundHttpException.Reason.TLS,
                    "the TLS handshake with " + target.origin() + " failed: " + e.getMessage(), e);
        }
        if (e instanceof HttpException || e instanceof RuntimeException || isHttpCoreIo(e)) {
            return new OutboundHttpException(OutboundHttpException.Reason.MALFORMED_RESPONSE,
                    target.origin() + " sent a malformed or truncated response: " + LogText.clip(String.valueOf(e.getMessage())), e);
        }
        return new OutboundHttpException(OutboundHttpException.Reason.IO,
                "the exchange with " + target.origin() + " failed: " + e.getMessage(), e);
    }

    /** HttpCore's own I/O failures, which all mean the response broke its framing or limits or ended early. */
    static boolean isHttpCoreIo(Exception e) {
        String name = e.getClass().getName();
        return name.startsWith(HttpException.class.getPackageName() + ".");
    }

    private static OutboundHttpException timeout(Deadline total, OutboundHttpException.Reason phaseReason, String what,
            Throwable cause) {
        OutboundHttpException.Reason reason = total.expired() ? OutboundHttpException.Reason.DEADLINE : phaseReason;
        return new OutboundHttpException(reason, "ran out of time waiting for " + what, cause);
    }

    static boolean causedBy(Throwable e, Class<? extends Throwable> type) {
        for (Throwable t = e; t != null; t = t.getCause()) {
            if (type.isInstance(t)) {
                return true;
            }
        }
        return false;
    }

    private static OutboundHttpException malformed(String message) {
        return new OutboundHttpException(OutboundHttpException.Reason.MALFORMED_RESPONSE, message);
    }

    private static Duration orDefault(Duration value, Duration fallback) {
        return value != null ? value : fallback;
    }

    private static URI uri(String url) throws OutboundHttpException {
        try {
            return new URI(Objects.requireNonNull(url, "url"));
        } catch (java.net.URISyntaxException e) {
            throw new OutboundHttpException(OutboundHttpException.Reason.REFUSED_URL,
                    "refusing to fetch a malformed URL: " + e.getMessage(), e);
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // Nothing is left to do with a socket that will not close.
        }
    }

    /** Text from a peer, clipped before it goes into a message. */
    static final class LogText {
        private LogText() {
        }

        static String clip(String value) {
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < value.length() && out.length() < 80; i++) {
                char c = value.charAt(i);
                out.append(c >= 0x20 && c < 0x7F ? c : '?');
            }
            return value.length() > 80 ? out + "..." : out.toString();
        }
    }
}
