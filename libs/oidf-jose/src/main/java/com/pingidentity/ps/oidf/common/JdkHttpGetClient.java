package com.pingidentity.ps.oidf.common;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
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
 */
public final class JdkHttpGetClient implements HttpGetClient {

    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(8);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);

    private final HttpClient httpClient;

    public JdkHttpGetClient(boolean ignoreSslErrors) {
        this.httpClient = ignoreSslErrors ? buildTrustAllClient() : baseBuilder().build();
    }

    JdkHttpGetClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", acceptHeader)
                .timeout(REQUEST_TIMEOUT)
                .GET()
                .build();
        HttpResponse<String> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalArgumentException("GET failed: " + url + " status=" + response.statusCode());
        }
        return response.body();
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
