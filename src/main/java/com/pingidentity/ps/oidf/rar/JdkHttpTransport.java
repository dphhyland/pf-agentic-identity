/*
 * JDK java.net.http implementation of HttpTransport (no third-party HTTP dependency).
 */
package com.pingidentity.ps.oidf.rar;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;

/**
 * Posts to the governance engine using the JDK HTTP client. When {@code insecureTls} is set it trusts any
 * server certificate — a scoped dev flag for self-signed test instances, replacing the reference plugin's
 * always-on trust-all manager.
 */
public final class JdkHttpTransport implements HttpTransport {

    private final HttpClient client;
    private final Duration timeout;

    public JdkHttpTransport(boolean insecureTls, int timeoutMillis) {
        this.timeout = Duration.ofMillis(timeoutMillis > 0 ? timeoutMillis : 10_000);
        HttpClient.Builder builder = HttpClient.newBuilder().connectTimeout(timeout);
        if (insecureTls) {
            builder.sslContext(trustAllContext());
        }
        this.client = builder.build();
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
            return new Response(response.statusCode(), response.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("governance engine request interrupted", e);
        }
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
