package com.pingidentity.ps.oidf.pf;

import java.util.Objects;
import java.util.function.Function;

/**
 * The deployment-wide federation settings, resolved once from the process environment.
 *
 * <p>These values are a property of the <em>deployment</em>, not of any one servlet: the OGNL
 * issuance criterion, the token-endpoint filters and the registration servlet all need the same
 * trust controller. They used to live in three {@code public static} fields on
 * {@code RegistrationConfiguration}, written as a side effect of its constructor — so whichever
 * component happened to initialise last won, and until something had initialised at all the values
 * were {@code ""}, which makes {@code knownTrustAnchor} empty and fails every attestation. Two
 * components wrote them with different meanings (one passed the bare host as the base URL), and each
 * reader had grown its own env-var fallback to paper over the ordering. This class is that fallback,
 * promoted to the only source: computed once, immutable, identical for every reader, and unaffected
 * by initialisation order.
 *
 * <p>Resolution is system property first, then environment variable — the same precedence the rest of
 * the codebase uses, so a JVM flag can override a container variable without a redeploy.
 */
public final class FederationRuntimeConfig {

    /** The trust controller's bare federation identity, for {@code knownTrustAnchor} matching. */
    public static final String HOST_ENV = "OIDF_FEDERATION_TRUST_CONTROLLER_HOST";
    /** The HTTP base actually used to reach the trust controller (may carry a context path). */
    public static final String BASE_URL_ENV = "OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL";
    public static final String IGNORE_SSL_ENV = "OIDF_FEDERATION_IGNORE_SSL_ERRORS";

    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String BASE_URL_PROP = "oidf.federation.trust.controller.base.url";
    private static final String IGNORE_SSL_PROP = "oidf.federation.ignore.ssl.errors";

    private static volatile FederationRuntimeConfig instance;

    private final String trustControllerHost;
    private final String trustControllerBaseUrl;
    private final boolean ignoreSslErrors;

    private FederationRuntimeConfig(String trustControllerHost, String trustControllerBaseUrl, boolean ignoreSslErrors) {
        this.trustControllerHost = trustControllerHost == null ? "" : trustControllerHost.trim();
        String base = trustControllerBaseUrl == null ? "" : trustControllerBaseUrl.trim();
        // The identity and its reachable location are the same thing in most deployments; only a PF
        // serving federation under a context path (e.g. /oidf) needs them to differ.
        this.trustControllerBaseUrl = base.isBlank() ? this.trustControllerHost : base;
        this.ignoreSslErrors = ignoreSslErrors;
    }

    /** The process-wide configuration, resolved on first use and cached. */
    public static FederationRuntimeConfig get() {
        FederationRuntimeConfig local = instance;
        if (local == null) {
            synchronized (FederationRuntimeConfig.class) {
                local = instance;
                if (local == null) {
                    local = from(System::getenv, System::getProperty);
                    instance = local;
                }
            }
        }
        return local;
    }

    /** Test seam: resolve from supplied lookups instead of the real process environment. */
    public static FederationRuntimeConfig from(Function<String, String> env, Function<String, String> props) {
        Objects.requireNonNull(env, "env");
        Objects.requireNonNull(props, "props");
        return new FederationRuntimeConfig(
                setting(env, props, HOST_PROP, HOST_ENV),
                setting(env, props, BASE_URL_PROP, BASE_URL_ENV),
                Boolean.parseBoolean(setting(env, props, IGNORE_SSL_PROP, IGNORE_SSL_ENV)));
    }

    private static String setting(Function<String, String> env, Function<String, String> props, String prop, String var) {
        String value = props.apply(prop);
        if (value == null || value.isBlank()) {
            value = env.apply(var);
        }
        return value;
    }

    public String trustControllerHost() {
        return this.trustControllerHost;
    }

    public String trustControllerBaseUrl() {
        return this.trustControllerBaseUrl;
    }

    public boolean ignoreSslErrors() {
        return this.ignoreSslErrors;
    }

    /**
     * True when no trust controller is configured. Attestation and trust-chain validation cannot
     * succeed in that state — they fail closed on an empty {@code knownTrustAnchor} — so callers log
     * it once rather than failing every request with an unexplained rejection.
     */
    public boolean isTrustControllerConfigured() {
        return !this.trustControllerHost.isBlank();
    }

    @Override
    public String toString() {
        return "FederationRuntimeConfig[host=" + this.trustControllerHost
                + ", baseUrl=" + this.trustControllerBaseUrl
                + ", ignoreSslErrors=" + this.ignoreSslErrors + "]";
    }
}
