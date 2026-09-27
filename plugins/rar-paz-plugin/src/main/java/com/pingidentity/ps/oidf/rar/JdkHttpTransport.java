/*
 * JDK java.net.http implementation of HttpTransport (no third-party HTTP dependency).
 */
package com.pingidentity.ps.oidf.rar;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.EOFException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.ProtocolException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.UnknownHostException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;

/**
 * Posts to the governance engine using the JDK HTTP client. When {@code insecureTls} is set it trusts any
 * server certificate — a scoped dev flag for self-signed test instances, replacing the reference plugin's
 * always-on trust-all manager.
 *
 * <p>The JDK {@code HttpClient} performs TLS hostname verification (endpoint identification) during the
 * handshake even with a trust-all {@link SSLContext}, and it cannot be disabled per client. Give the PDP a
 * certificate whose subject alternative name is the host PingFederate dials; the README says why the
 * JVM-wide property that turns the check off must not be set.
 *
 * <p>What the client throws is sorted into two classes before it leaves here, because the processor grants
 * through exactly one of them when fail-open is on: {@link #classify}.
 */
public final class JdkHttpTransport implements HttpTransport {

    private final HttpClient client;
    private final Duration timeout;
    private final boolean trustsAnyCertificate;

    public JdkHttpTransport(boolean insecureTls, int timeoutMillis) {
        this.timeout = Duration.ofMillis(timeoutMillis > 0 ? timeoutMillis : 10_000);
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(timeout);
        if (insecureTls) {
            builder.sslContext(trustAllContext());
        }
        this.trustsAnyCertificate = insecureTls;
        this.client = builder.build();
    }

    /** Whether this transport was built with the trust-all context: what a test of configure asserts on. */
    boolean trustsAnyCertificate() {
        return trustsAnyCertificate;
    }

    @Override
    public Response post(String url, String body, Map<String, String> headers) throws IOException {
        HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        if (headers != null) {
            headers.forEach(rb::header);
        }
        try {
            HttpResponse<String> response = client.send(rb.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            return new Response(response.statusCode(), response.body(),
                    response.headers().firstValue("Content-Type").orElse(null));
        } catch (IOException e) {
            throw classify(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("governance engine request interrupted", e);
        }
    }

    /**
     * The transport failures that mean the PDP was not reached, as {@link PdpUnavailableException}: the
     * connection was refused or timed out ({@link ConnectException}, {@link HttpTimeoutException} and its
     * connect-timeout subclass, {@link SocketTimeoutException}), the name did not resolve
     * ({@link UnknownHostException}), or the connection was reset or closed under the request
     * ({@link SocketException}, {@link EOFException}, {@link ClosedChannelException}, or an {@link IOException}
     * whose message starts with the JDK's own "Connection reset" text, which older JDKs throw from the socket
     * layer).
     *
     * <p>Two failures refuse whatever else the chain holds, because each means something answered: an
     * {@link SSLException} (it could not prove it was the PDP) and a {@link ProtocolException} (it sent a status
     * line or header the client could not parse). The client copies the offending wire text into a protocol
     * error's message - {@code Invalid status line: "..."}, {@code Invalid header name "..."} - and JDK 17
     * rethrows it as a plain {@link IOException} with the same message, so a message is only matched from its
     * start and never searched: a PDP whose malformed answer names "connection reset" is still an answer.
     * Anything else the client throws stays what it was, so it fails closed. The chain is walked because the
     * JDK client wraps what its exchange threw.
     */
    static IOException classify(IOException e) {
        if (e instanceof PdpUnavailableException) {
            return e;
        }
        boolean unreachable = false;
        // Bounded: initCause forbids a direct self-cause and nothing else, so a longer cycle is constructible.
        Throwable t = e;
        for (int depth = 0; t != null && depth < 16; t = t.getCause(), depth++) {
            if (t instanceof SSLException || t instanceof ProtocolException) {
                return e;
            }
            if (t instanceof ConnectException || t instanceof HttpTimeoutException || t instanceof SocketTimeoutException
                    || t instanceof UnknownHostException || t instanceof SocketException || t instanceof EOFException
                    || t instanceof ClosedChannelException
                    || (t instanceof IOException && t.getMessage() != null
                        && t.getMessage().toLowerCase(Locale.ROOT).startsWith("connection reset"))) {
                unreachable = true;
            }
        }
        return unreachable ? new PdpUnavailableException("PDP unreachable: " + e, e) : e;
    }

    private static SSLContext trustAllContext() {
        try {
            TrustManager[] trustAll = { new X509TrustManager() {
                @Override public void checkClientTrusted(X509Certificate[] chain, String authType) { }
                @Override public void checkServerTrusted(X509Certificate[] chain, String authType) { }
                @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            } };
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, trustAll, new java.security.SecureRandom());
            return ctx;
        } catch (Exception e) {
            throw new IllegalStateException("failed to build insecure TLS context", e);
        }
    }
}
