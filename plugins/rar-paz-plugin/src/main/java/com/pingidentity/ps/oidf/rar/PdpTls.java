/*
 * How the plugin trusts the PDP's certificate: the JVM's CAs, PingFederate's trusted CAs, or CAs pinned in the instance.
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.http.TlsTrust;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * The "PDP TLS trust" field's three answers, each as platform's {@link TlsTrust}. Whatever the answer,
 * platform's transport checks the PDP's certificate against the host the PDP URL names (HTTPS endpoint
 * identification, set on every connection), so a certificate that does not name the host PingFederate dials is
 * refused in every mode, the development-only "Skip TLS verification" included.
 *
 * <ul>
 *   <li>{@value #JVM_DEFAULT} (the default): the CAs of the JVM PingFederate runs on.</li>
 *   <li>{@value #PINGFEDERATE_TRUSTED_CAS}: what PingFederate's SDK hands a plugin as its trust anchors,
 *       {@code com.pingidentity.access.TrustedCAAccessor.getAllTrustAnchors()}. In PingFederate 13.1.3 that is the
 *       CAs under Security, Trusted CAs <em>and</em> the JVM's own ({@code TrustedCAsManagerImpl.loadConfig} adds
 *       {@code getTrustedCaX509s()} and then {@code getJmvTrustedCAs()}; javap of pf-protocolengine 13.1.3.0,
 *       2026-09-29). It is read on every call and the client rebuilt only when PingFederate's set changes (its
 *       anchors are the same objects until the trusted CAs are reloaded), so a CA added in the console is used
 *       without saving the instance again.</li>
 *   <li>{@value #PINNED_CA}: exactly the CA certificates in the instance's PEM field, and nothing from the
 *       JVM.</li>
 * </ul>
 */
final class PdpTls {

    static final String JVM_DEFAULT = "jvm-default";
    static final String PINGFEDERATE_TRUSTED_CAS = "pingfederate-trusted-cas";
    static final String PINNED_CA = "pinned-ca";
    static final List<String> MODES = List.of(JVM_DEFAULT, PINGFEDERATE_TRUSTED_CAS, PINNED_CA);

    private final String mode;
    private final TlsTrust fixed;
    private final Supplier<Set<TrustAnchor>> anchors;
    private Set<TrustAnchor> lastAnchors;
    private TlsTrust lastTrust;

    private PdpTls(String mode, TlsTrust fixed, Supplier<Set<TrustAnchor>> anchors) {
        this.mode = mode;
        this.fixed = fixed;
        this.anchors = anchors;
    }

    /** The JVM's CAs. */
    static PdpTls jvmDefault() {
        return new PdpTls(JVM_DEFAULT, TlsTrust.jvmDefault(), null);
    }

    /** Any chain, the host name still checked: platform's one trust-all, which names the setting and records its use. */
    static PdpTls insecure(String setting) {
        return new PdpTls("insecure", TlsTrust.insecureIf(setting, true), null);
    }

    /** Exactly the CAs in {@code pem}; refused unless it holds at least one certificate. */
    static PdpTls pinned(String pem) throws GeneralSecurityException, IOException {
        return new PdpTls(PINNED_CA, TlsTrust.caCertificates(certificatesOf(pem)), null);
    }

    /** PingFederate's trust anchors, read from {@code anchors} on each call. */
    static PdpTls pingFederate(Supplier<Set<TrustAnchor>> anchors) {
        return new PdpTls(PINGFEDERATE_TRUSTED_CAS, null, Objects.requireNonNull(anchors, "anchors"));
    }

    /** The field's value, trimmed and lower case; blank is the default. Anything else is not a mode. */
    static String modeOf(String field) {
        if (field == null || field.isBlank()) {
            return JVM_DEFAULT;
        }
        String mode = field.trim().toLowerCase(Locale.ROOT);
        if (!MODES.contains(mode)) {
            throw new IllegalStateException("PDP TLS trust must be one of " + MODES + ", not '" + field.trim() + "'");
        }
        return mode;
    }

    String mode() {
        return mode;
    }

    /**
     * The trust to use now. For PingFederate's CAs, the anchors are read again and the trust rebuilt when the set is
     * not the one it was built from.
     *
     * @throws IOException when there is nothing to trust (PingFederate handed no anchor with a certificate), which
     *     refuses the call rather than reading as the PDP being unreachable
     */
    synchronized TlsTrust current() throws IOException {
        if (fixed != null) {
            return fixed;
        }
        Set<TrustAnchor> now;
        try {
            now = anchors.get();
        } catch (RuntimeException | LinkageError e) {
            throw new IOException("PingFederate's trusted CAs could not be read: " + e, e);
        }
        if (lastTrust != null && now != null && now.equals(lastAnchors)) {
            return lastTrust;
        }
        List<X509Certificate> certificates = new ArrayList<>();
        if (now != null) {
            for (TrustAnchor anchor : now) {
                if (anchor != null && anchor.getTrustedCert() != null) {
                    certificates.add(anchor.getTrustedCert());
                }
            }
        }
        try {
            lastTrust = TlsTrust.caCertificates(certificates);
        } catch (GeneralSecurityException e) {
            throw new IOException("PingFederate's trusted CAs hold no certificate to trust the PDP with: " + e.getMessage(), e);
        }
        lastAnchors = now;
        return lastTrust;
    }

    /**
     * Every certificate in a PEM (or DER) text. Blank, or text that is not certificates, is refused; so is text that
     * holds none, by {@link TlsTrust#caCertificates} when the trust is built.
     */
    static List<X509Certificate> certificatesOf(String pem) throws CertificateException {
        if (pem == null || pem.isBlank()) {
            throw new CertificateException("the pinned CA field holds no certificate");
        }
        Collection<? extends Certificate> read;
        try {
            read = CertificateFactory.getInstance("X.509")
                    .generateCertificates(new ByteArrayInputStream(pem.trim().getBytes(StandardCharsets.US_ASCII)));
        } catch (RuntimeException e) {
            // The JDK's parser throws a NullPointerException for some malformed PKCS#7 (JDK 17, 2026-09-29).
            throw new CertificateException("the pinned CA field is not a certificate: " + e, e);
        }
        List<X509Certificate> certificates = new ArrayList<>();
        for (Certificate certificate : read) {
            certificates.add((X509Certificate) certificate);
        }
        return certificates;
    }

    @Override
    public String toString() {
        return "PdpTls[" + mode + "]";
    }
}
