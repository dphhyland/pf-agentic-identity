package com.pingidentity.ps.oidf.jose;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * GET and POST over the JDK {@link HttpClient}, every request screened by an {@link OutboundUrlPolicy}
 * first and every response body read through the policy's size cap.
 *
 * <p>This is {@link JdkHttpGetClient}'s transport generalised: the same fail-fast timeouts (a remote
 * that stalls costs the caller's thread a few seconds, not an unbounded wait), HTTP/1.1 so concurrent
 * requests to one host do not serialise over one HTTP/2 connection, no redirects (so one policy check
 * per request is sufficient), and a capped body read rather than {@code BodyHandlers.ofString}. POST
 * reports the status to the caller instead of throwing on it (see {@link HttpPostClient}).
 *
 * <p>When constructed with {@code ignoreSslErrors} it trusts all TLS certificates and disables hostname
 * verification - for a development peer over self-signed TLS, never for production.
 */
public final class JdkHttpClient implements HttpGetClient, HttpPostClient {

    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(8);
    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient httpClient;
    private final OutboundUrlPolicy policy;
    private final Duration requestTimeout;

    public JdkHttpClient(boolean ignoreSslErrors, OutboundUrlPolicy policy) {
        this(ignoreSslErrors, policy, DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT);
    }

    public JdkHttpClient(boolean ignoreSslErrors, OutboundUrlPolicy policy, Duration connectTimeout, Duration requestTimeout) {
        Objects.requireNonNull(connectTimeout, "connectTimeout");
        this.httpClient = ignoreSslErrors ? buildTrustAllClient(connectTimeout) : baseBuilder(connectTimeout).build();
        this.policy = Objects.requireNonNull(policy, "policy");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
    }

    /** Test seam: a supplied {@link HttpClient}. */
    JdkHttpClient(HttpClient httpClient, OutboundUrlPolicy policy, Duration requestTimeout) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.policy = Objects.requireNonNull(policy, "policy");
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
    }

    public OutboundUrlPolicy policy() {
        return this.policy;
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        URI uri = this.policy.check(url);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Accept", acceptHeader)
                .timeout(this.requestTimeout)
                .GET()
                .build();
        HttpResponse<InputStream> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalArgumentException("GET failed: " + url + " status=" + response.statusCode());
            }
            return readBody(response, body, url, "GET");
        }
    }

    @Override
    public Response post(String url, String contentType, String body, Map<String, String> headers, String accept) throws Exception {
        URI uri = this.policy.check(url);
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(uri)
                .timeout(this.requestTimeout)
                .header("Content-Type", Objects.requireNonNull(contentType, "contentType"))
                .POST(HttpRequest.BodyPublishers.ofString(body == null ? "" : body, StandardCharsets.UTF_8));
        if (accept != null) {
            builder.header("Accept", accept);
        }
        if (headers != null) {
            for (Map.Entry<String, String> header : headers.entrySet()) {
                if (header.getKey() != null && header.getValue() != null) {
                    builder.header(header.getKey(), header.getValue());
                }
            }
        }
        HttpResponse<InputStream> response = this.httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream in = response.body()) {
            String responseBody = readBody(response, in, url, "POST");
            return new Response(response.statusCode(), responseBody, response.headers().map());
        }
    }

    private String readBody(HttpResponse<InputStream> response, InputStream body, String url, String method) throws IOException {
        // A declared over-cap length is refused without reading; an undeclared or lying one is
        // caught by the read itself, so a chunked response cannot stream past the cap either.
        long declared = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
        if (declared > this.policy.maxBodyBytes()) {
            throw new IllegalArgumentException(method + " refused: " + url + " declares " + declared
                    + " bytes, over the " + this.policy.maxBodyBytes() + "-byte cap");
        }
        return readCapped(body, this.policy.maxBodyBytes(), url, method);
    }

    private static String readCapped(InputStream in, long cap, String url, String method) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = in.read(chunk)) != -1) {
            total += read;
            if (total > cap) {
                throw new IllegalArgumentException(method + " refused: " + url + " body exceeds the " + cap + "-byte cap");
            }
            buffer.write(chunk, 0, read);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private static HttpClient.Builder baseBuilder(Duration connectTimeout) {
        return HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .version(HttpClient.Version.HTTP_1_1);
    }

    private static HttpClient buildTrustAllClient(Duration connectTimeout) {
        try {
            TrustManager[] trustAll = {new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }};
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new SecureRandom());
            SSLParameters sslParameters = new SSLParameters();
            sslParameters.setEndpointIdentificationAlgorithm(null);
            return baseBuilder(connectTimeout).sslContext(sslContext).sslParameters(sslParameters).build();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to build trust-all HttpClient", e);
        }
    }
}
