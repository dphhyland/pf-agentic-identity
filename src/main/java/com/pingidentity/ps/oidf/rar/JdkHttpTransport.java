/*
 * HttpURLConnection implementation of HttpTransport (no third-party HTTP dependency).
 */
package com.pingidentity.ps.oidf.rar;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Map;

/**
 * Posts to the governance engine using {@code java.net.HttpURLConnection}. When {@code insecureTls} is set it
 * trusts any server certificate AND skips hostname verification — a scoped dev flag for self-signed test
 * instances whose cert SAN does not match the internal hostname (e.g. Railway's *.railway.internal). The JDK's
 * newer {@code java.net.http.HttpClient} cannot disable hostname verification per-client (only via a global JVM
 * property), so HttpURLConnection is used here for its per-connection {@link HostnameVerifier}.
 */
public final class JdkHttpTransport implements HttpTransport {

    private final boolean insecureTls;
    private final int timeoutMillis;
    private final SSLContext insecureContext;

    public JdkHttpTransport(boolean insecureTls, int timeoutMillis) {
        this.insecureTls = insecureTls;
        this.timeoutMillis = timeoutMillis > 0 ? timeoutMillis : 10_000;
        this.insecureContext = insecureTls ? trustAllContext() : null;
    }

    @Override
    public Response post(String url, String body, Map<String, String> headers) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        if (insecureTls && conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            https.setSSLSocketFactory(insecureContext.getSocketFactory());
            https.setHostnameVerifier(ALLOW_ALL_HOSTNAMES);
        }
        conn.setRequestMethod("POST");
        conn.setConnectTimeout(timeoutMillis);
        conn.setReadTimeout(timeoutMillis);
        conn.setDoOutput(true);
        if (headers != null) {
            headers.forEach(conn::setRequestProperty);
        }
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        int status = conn.getResponseCode();
        InputStream is = (status >= 200 && status < 300) ? conn.getInputStream() : conn.getErrorStream();
        String responseBody = is == null ? "" : new String(is.readAllBytes(), StandardCharsets.UTF_8);
        return new Response(status, responseBody);
    }

    private static final HostnameVerifier ALLOW_ALL_HOSTNAMES = (hostname, session) -> true;

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
