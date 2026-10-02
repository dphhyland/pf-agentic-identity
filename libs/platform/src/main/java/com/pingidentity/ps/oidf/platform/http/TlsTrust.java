/*
 * Which server certificates an outbound TLS connection accepts.
 */
package com.pingidentity.ps.oidf.platform.http;

import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import java.io.IOException;
import java.io.InputStream;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executor;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

/**
 * The trust an {@link OutboundHttp} connection uses: the JVM's by default, a caller's {@link SSLContext} or CA
 * bundle, or - only when a caller's setting asks - platform's {@link InsecureTls} trust-all.
 *
 * <p>Whatever the trust, {@link OutboundHttp} sets the HTTPS endpoint identification algorithm on every connection,
 * so the certificate must name the host the URL names. There is no mode here that turns that off: InsecureTls's
 * JVM-wide {@code jdk.internal.httpclient.disableHostnameVerification} governs {@link HttpClient} alone, and carrying it
 * into this transport would widen finding F-0035 rather than keep a behaviour. The trust-all is a plain
 * {@code X509TrustManager}, which JSSE wraps and follows with that identity check, so under it the chain goes
 * unchecked and the name is still checked - what InsecureTls documents for the JDK client.
 */
public final class TlsTrust {
    private final SSLSocketFactory socketFactory;
    private final String description;

    private TlsTrust(SSLSocketFactory socketFactory, String description) {
        this.socketFactory = socketFactory;
        this.description = description;
    }

    /** The JVM's default trust (its cacerts, or {@code javax.net.ssl.trustStore}). */
    public static TlsTrust jvmDefault() {
        return new TlsTrust((SSLSocketFactory) SSLSocketFactory.getDefault(), "the JVM's default trust");
    }

    /** The trust {@code context} was initialised with. */
    public static TlsTrust of(SSLContext context) {
        Objects.requireNonNull(context, "context");
        return new TlsTrust(context.getSocketFactory(), "a supplied SSLContext");
    }

    /**
     * Trusts exactly these CA certificates, and nothing from the JVM's own store. The {@link IOException} is
     * {@link KeyStore#load}'s signature: creating an empty store reads nothing.
     */
    public static TlsTrust caCertificates(Collection<X509Certificate> certificates)
            throws IOException, GeneralSecurityException {
        Objects.requireNonNull(certificates, "certificates");
        if (certificates.isEmpty()) {
            throw new GeneralSecurityException("a CA bundle must hold at least one certificate");
        }
        KeyStore store = KeyStore.getInstance(KeyStore.getDefaultType());
        store.load(null, null);
        int index = 0;
        for (X509Certificate certificate : certificates) {
            store.setCertificateEntry("ca-" + index++, Objects.requireNonNull(certificate, "certificate"));
        }
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        return new TlsTrust(context.getSocketFactory(), certificates.size() + " CA certificate(s)");
    }

    /** Trusts exactly the CA certificates in a PEM (or DER) file. */
    public static TlsTrust caBundle(Path file) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(file, "file");
        List<X509Certificate> certificates = new ArrayList<>();
        try (InputStream in = Files.newInputStream(file)) {
            for (Certificate certificate : CertificateFactory.getInstance("X.509").generateCertificates(in)) {
                certificates.add((X509Certificate) certificate);
            }
        }
        return caCertificates(certificates);
    }

    /**
     * The JVM's trust, or InsecureTls's trust-all when {@code insecure} is true: InsecureTls names {@code setting} in
     * its one WARN and records the use for the start-up audit, as it does for every trust-all in the repository.
     */
    public static TlsTrust insecureIf(String setting, boolean insecure) {
        if (!insecure) {
            return jvmDefault();
        }
        ContextCapture capture = new ContextCapture();
        InsecureTls.trustAnyCertificate(capture, setting, true);
        return new TlsTrust(capture.context.getSocketFactory(), "ANY certificate chain (" + setting + ")");
    }

    SSLSocketFactory socketFactory() {
        return this.socketFactory;
    }

    @Override
    public String toString() {
        return "TlsTrust[" + this.description + "]";
    }

    /**
     * Receives the context {@link InsecureTls#trustAnyCertificate} builds, so the one trust-all in the repository is
     * still the only one: InsecureTls hands its context to an {@link HttpClient.Builder}, and building a real client to
     * read it back would start the JDK client's selector thread for nothing. Only {@link #sslContext} is called.
     */
    static final class ContextCapture implements HttpClient.Builder {
        SSLContext context;

        @Override
        public HttpClient.Builder sslContext(SSLContext sslContext) {
            this.context = sslContext;
            return this;
        }

        @Override
        public HttpClient.Builder cookieHandler(CookieHandler cookieHandler) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder connectTimeout(Duration duration) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder sslParameters(SSLParameters sslParameters) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder executor(Executor executor) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder followRedirects(HttpClient.Redirect policy) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder version(HttpClient.Version version) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder priority(int priority) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder proxy(ProxySelector proxySelector) {
            throw unsupported();
        }

        @Override
        public HttpClient.Builder authenticator(Authenticator authenticator) {
            throw unsupported();
        }

        @Override
        public HttpClient build() {
            throw unsupported();
        }

        private static UnsupportedOperationException unsupported() {
            return new UnsupportedOperationException("only receives the SSLContext InsecureTls builds");
        }
    }
}
