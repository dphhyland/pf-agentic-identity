/*
 * How rediss:// verifies the server: the chain, the name, and SNI, before anything is written.
 */
package com.pingidentity.ps.oidf.platform.redis;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

/**
 * TLS for {@code rediss://}, the way a browser verifies a server (S3a, kept from 0.4.0's client): the certificate
 * chains to a trusted CA - the JVM's, or the PEM file {@code OIDF_REDIS_CA_FILE} names - and names the host dialled
 * (the HTTPS endpoint identification algorithm, RFC 2818 section 3.1), with the host sent as SNI. The same rules
 * apply to the sentinels and to a master a sentinel names.
 */
final class RedisTls {
    static final String ENDPOINT_IDENTIFICATION = "HTTPS";
    static final String CA_FILE_SETTING = "OIDF_REDIS_CA_FILE";

    private static final Pattern IPV4 = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private RedisTls() {
    }

    /**
     * The TLS parameters every connection uses: the HTTPS endpoint identification algorithm, so the server's
     * certificate must name {@code host}, and {@code host} as the SNI name when it is a name (RFC 6066 section 3
     * permits no IP literal there; the JDK sends none for one and the certificate is then checked against the
     * address).
     */
    static SSLParameters sslParametersFor(SSLParameters base, String host) {
        base.setEndpointIdentificationAlgorithm(ENDPOINT_IDENTIFICATION);
        if (!isIpLiteral(host)) {
            base.setServerNames(List.of(new SNIHostName(host)));
        }
        return base;
    }

    /** An IPv6 literal, in brackets as a URL writes it or bare as a sentinel reports it, or four dotted groups of digits. */
    static boolean isIpLiteral(String host) {
        return host.startsWith("[") || host.indexOf(':') >= 0 || IPV4.matcher(host).matches();
    }

    /**
     * The JVM's default context, or one that trusts only the certificates in {@code caFile} - a PEM file with one or
     * more CA certificates, the shape managed Redis providers publish.
     *
     * @throws IllegalArgumentException when the file cannot be read or holds no certificate, naming the setting
     */
    static SSLContext sslContextFor(Path caFile) {
        if (caFile == null) {
            return jvmDefaultContext();
        }
        try (InputStream in = Files.newInputStream(caFile)) {
            Collection<? extends Certificate> certificates = CertificateFactory.getInstance("X.509").generateCertificates(in);
            if (certificates.isEmpty()) {
                throw new IllegalArgumentException(CA_FILE_SETTING + " names " + caFile + ", which holds no certificate");
            }
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null, null);
            int i = 0;
            for (Certificate certificate : certificates) {
                trust.setCertificateEntry("redis-ca-" + i++, certificate);
            }
            TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            factory.init(trust);
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, factory.getTrustManagers(), null);
            return context;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException(CA_FILE_SETTING + " names " + caFile + ", which cannot be used as a CA file: "
                    + e.getMessage(), e);
        }
    }

    static SSLContext jvmDefaultContext() {
        try {
            return SSLContext.getDefault();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("no default SSLContext", e);
        }
    }
}
