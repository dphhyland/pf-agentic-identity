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
import java.util.Objects;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * {@link HttpGetClient} backed by the JDK {@link HttpClient}. When constructed
 * with {@code ignoreSslErrors} it trusts all TLS certificates and disables
 * hostname verification — intended only for talking to a development trust
 * controller over self-signed TLS, never for production.
 *
 * <p>Trust-chain validation runs synchronously on the caller's request thread
 * (see {@code TrustChainValidator}), so every fetch here MUST fail fast rather
 * than hang: a stalled remote entity should cost this thread a few seconds,
 * not tie it up until the CALLER's own timeout gives up (which just produces
 * an orphaned in-flight fetch PF keeps working on after the client is gone —
 * observed in production as a client 499 at ~45s followed by PF completing
 * the same exchange ~30-60s later against a connection nobody's still on).
 * HTTP/1.1 is forced so concurrent fetches to the same host get independent
 * TCP connections instead of potentially serializing over one HTTP/2 stream.
 *
 * <p>Every fetch is screened by an {@link OutboundUrlPolicy} first, because federation resolution
 * follows caller-supplied identifiers (see that class). Redirects are never followed - the JDK
 * default - so one check per request is sufficient; if that ever changes, each hop needs checking.
 * Response bodies are read through a cap rather than with {@code BodyHandlers.ofString}, which would
 * buffer whatever a remote chose to send.
 */
public final class JdkHttpGetClient implements HttpGetClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(8);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient httpClient;
    private final OutboundUrlPolicy policy;

    public JdkHttpGetClient(boolean ignoreSslErrors) {
        this(ignoreSslErrors, OutboundUrlPolicy.fromEnvironment());
    }

    public JdkHttpGetClient(boolean ignoreSslErrors, OutboundUrlPolicy policy) {
        this.httpClient = ignoreSslErrors ? buildTrustAllClient() : baseBuilder().build();
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    JdkHttpGetClient(HttpClient httpClient) {
        this(httpClient, OutboundUrlPolicy.fromEnvironment());
    }

    JdkHttpGetClient(HttpClient httpClient, OutboundUrlPolicy policy) {
        this.httpClient = httpClient;
        this.policy = Objects.requireNonNull(policy, "policy");
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        URI uri = this.policy.check(url);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("Accept", acceptHeader)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
        HttpResponse<InputStream> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
        try (InputStream body = response.body()) {
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IllegalArgumentException("GET failed: " + url + " status=" + response.statusCode());
            }
            // A declared over-cap length is refused without reading; an undeclared or lying one is
            // caught by the read itself, so a chunked response cannot stream past the cap either.
            long declared = response.headers().firstValueAsLong("Content-Length").orElse(-1L);
            if (declared > this.policy.maxBodyBytes()) {
                throw new IllegalArgumentException("GET refused: " + url + " declares " + declared
                        + " bytes, over the " + this.policy.maxBodyBytes() + "-byte cap");
            }
            return readCapped(body, this.policy.maxBodyBytes(), url);
        }
    }

    private static String readCapped(InputStream in, long cap, String url) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = in.read(chunk)) != -1) {
            total += read;
            if (total > cap) {
                throw new IllegalArgumentException("GET refused: " + url + " body exceeds the " + cap + "-byte cap");
            }
            buffer.write(chunk, 0, read);
        }
        return buffer.toString(StandardCharsets.UTF_8);
    }

    private static HttpClient.Builder baseBuilder() {
        return HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .version(HttpClient.Version.HTTP_1_1);
    }

    private static HttpClient buildTrustAllClient() {
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
            return baseBuilder().sslContext(sslContext).sslParameters(sslParameters).build();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to build trust-all HttpClient", e);
        }
    }
}
