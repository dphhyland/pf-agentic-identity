package com.pingidentity.ps.oidf.common;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * {@link HttpGetClient} backed by the JDK {@link HttpClient}. When constructed
 * with {@code ignoreSslErrors} it trusts all TLS certificates and disables
 * hostname verification — intended only for talking to a development trust
 * controller over self-signed TLS, never for production.
 */
public final class JdkHttpGetClient implements HttpGetClient {

    private final HttpClient httpClient;

    public JdkHttpGetClient(boolean ignoreSslErrors) {
        this.httpClient = ignoreSslErrors ? buildTrustAllClient() : HttpClient.newBuilder().build();
    }

    JdkHttpGetClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public String get(String url, String acceptHeader) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", acceptHeader)
                .GET()
                .build();
        HttpResponse<String> response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalArgumentException("GET failed: " + url + " status=" + response.statusCode());
        }
        return response.body();
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
            return HttpClient.newBuilder().sslContext(sslContext).sslParameters(sslParameters).build();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to build trust-all HttpClient", e);
        }
    }
}
