/*
 * The one place a trust-all TLS context is built, and the one place the JDK's hostname check is turned off.
 */
package com.pingidentity.ps.oidf.platform.tls;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Every trust-all TLS the repository builds, built here and nowhere else (plan item PR-1, finding F-0042), and a
 * source scan ({@code tools/trust-scan.py}) holds every other main source to it. Each use names the setting that
 * asked for it, logs one WARN per setting name in this loader, and is recorded for the start-up audit (F-2):
 * {@link #uses()}.
 *
 * <p>What "trust-all" means here, verified against the JDK's source and by {@code InsecureTlsTest}:
 * <ul>
 *   <li>It is handed out only to {@link java.net.http.HttpClient}, whose connection sets the HTTPS endpoint
 *       identification algorithm on every TLS connection unless the JVM-wide
 *       {@value #JDK_HOSTNAME_VERIFICATION_PROPERTY} property is set ({@code AbstractAsyncSSLConnection}, JDK 17
 *       and 21). The trust manager is a plain {@link X509TrustManager}, which JSSE wraps and follows with that
 *       identity check; an {@code X509ExtendedTrustManager} would not be wrapped and would skip it. So the chain
 *       is not checked, but the certificate must still name the host dialled.</li>
 *   <li>With {@value #JDK_HOSTNAME_VERIFICATION_PROPERTY} set, the host name goes unchecked too, for this and for
 *       every other {@code HttpClient} in the JVM, trust-all or not (finding F-0035).</li>
 * </ul>
 *
 * <p>It does not refuse anything under the production profile. That is PR-2 (Phase 3), which forbids ignore-TLS
 * in every form in production; until then the start-up audit reports each use.
 */
public final class InsecureTls {
    /** The JVM-wide system property that turns off the JDK HTTP client's hostname check, read once per JVM. */
    public static final String JDK_HOSTNAME_VERIFICATION_PROPERTY = "jdk.internal.httpclient.disableHostnameVerification";

    private static final PlatformLog LOG = PlatformLog.get(InsecureTls.class);
    private static final ConcurrentMap<String, Use> USES = new ConcurrentHashMap<>();
    /** Oldest first; then by setting and kind, so two uses recorded in the same instant list the same way each time. */
    static final Comparator<Use> ORDER = Comparator.comparing(Use::first).thenComparing(Use::setting).thenComparing(Use::kind);

    /** What was turned off. */
    public enum Kind {
        /** A trust-all context on an {@link HttpClient}: the chain is not checked, the host name still is. */
        TRUST_ALL_CERTIFICATES,
        /** {@value InsecureTls#JDK_HOSTNAME_VERIFICATION_PROPERTY}: no host name checked by any HttpClient in the JVM. */
        JDK_HOSTNAME_VERIFICATION_OFF
    }

    /** A setting that asked for insecure TLS in this loader: which, what for, and when it first did. */
    public record Use(String setting, Kind kind, Instant first) {
    }

    private InsecureTls() {
    }

    /**
     * {@code builder} with a context that trusts any certificate when {@code insecureTls} is true, and unchanged
     * when it is false. The first use for a setting name logs a WARN naming it.
     *
     * @param setting     the setting that asked, as an operator writes it (an environment variable, an
     *                    init-param, a plugin field's label)
     * @param insecureTls that setting's value
     */
    public static HttpClient.Builder trustAnyCertificate(HttpClient.Builder builder, String setting, boolean insecureTls) {
        return trustAnyCertificate(builder, setting, insecureTls, "TLS");
    }

    /** The same, with the context's protocol named: a test seam for a JVM that has no such protocol. */
    static HttpClient.Builder trustAnyCertificate(HttpClient.Builder builder, String setting, boolean insecureTls, String protocol) {
        Objects.requireNonNull(builder, "builder");
        requireSetting(setting);
        if (insecureTls) {
            SSLContext context;
            try {
                context = SSLContext.getInstance(protocol);
                context.init(null, new TrustManager[] {new TrustEveryCertificate()}, null);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("could not build the trust-all TLS context " + setting + " asked for", e);
            }
            record(setting, Kind.TRUST_ALL_CERTIFICATES, setting + " is on: TLS certificate chains are NOT checked on the"
                    + " connections it governs (the host name still is). Development only; production will refuse it (PR-2)");
            return builder.sslContext(context);
        }
        return builder;
    }

    /**
     * Sets {@value #JDK_HOSTNAME_VERIFICATION_PROPERTY} for the whole JVM when {@code disableHostnameVerification}
     * is true. The JDK reads the property once, when its HTTP client first opens a TLS connection, so it must be
     * set before then; a JVM that already read it keeps what it read.
     */
    public static void disableJdkHostnameVerification(String setting, boolean disableHostnameVerification) {
        requireSetting(setting);
        if (disableHostnameVerification) {
            System.setProperty(JDK_HOSTNAME_VERIFICATION_PROPERTY, "true");
            record(setting, Kind.JDK_HOSTNAME_VERIFICATION_OFF, setting + " set " + JDK_HOSTNAME_VERIFICATION_PROPERTY
                    + "=true: no java.net.http client in this JVM checks a server's host name. Development only");
        }
    }

    /**
     * Whether this JVM's HTTP client skips the host name check, read as the JDK reads it: set and empty, or set
     * to {@code true} in any case. For the start-up audit, which reports it wherever it came from (F-0035).
     */
    public static boolean jdkHostnameVerificationDisabled() {
        return disabledByValue(System.getProperty(JDK_HOSTNAME_VERIFICATION_PROPERTY));
    }

    /** The JDK's reading of the property's value (jdk.internal.net.http.common.Utils, JDK 17 and 21). */
    static boolean disabledByValue(String value) {
        if (value == null) {
            return false;
        }
        return value.isEmpty() || Boolean.parseBoolean(value);
    }

    /** Every setting that asked for insecure TLS in this loader, oldest first. */
    public static List<Use> uses() {
        List<Use> uses = new ArrayList<>(USES.values());
        uses.sort(ORDER);
        return List.copyOf(uses);
    }

    /** Records the first use of a setting for a kind, and logs it once. */
    static boolean record(String setting, Kind kind, String warning) {
        Use use = new Use(setting, kind, Instant.now());
        if (USES.putIfAbsent(kind + " " + setting, use) == null) {
            LOG.warn(warning);
            return true;
        }
        return false;
    }

    /** Test seam: forget what this loader recorded. */
    static void reset() {
        USES.clear();
    }

    private static void requireSetting(String setting) {
        if (setting == null || setting.isBlank()) {
            throw new IllegalArgumentException("an insecure TLS use must name the setting that asked for it");
        }
    }

    /**
     * Accepts any chain. Deliberately a plain {@link X509TrustManager}: JSSE wraps one of these and then checks the
     * endpoint identity itself, which is what keeps the host name checked on an {@link HttpClient}.
     */
    static final class TrustEveryCertificate implements X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // Trusts any client: this context never asks for one.
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // Trusts any server chain; see the class comment for the host name.
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
