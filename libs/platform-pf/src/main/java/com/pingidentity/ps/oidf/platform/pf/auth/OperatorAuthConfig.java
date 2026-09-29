/*
 * The operator authenticator's configuration, from the operator-auth catalogue.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import com.pingidentity.ps.oidf.platform.profile.AcceptedRisk;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Secret;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import java.net.URI;
import java.util.Locale;
import java.util.function.Supplier;

/**
 * What {@code META-INF/oidf-settings/operator-auth.json} says, checked. A configuration that cannot authenticate
 * anyone - no audience, no base URL, no key source for its mode, an insecure switch or in-memory replay state that the
 * production profile does not allow - is held with its {@link #problem()}, and the authenticator answers every request
 * 503 with that reason in the log rather than failing PingFederate's start (the per-request effect the catalogue
 * declares). Plan item PR-5 routes these refusals through its start-up audit; until then this is where they are made.
 *
 * @param problem why nothing can be authenticated, or null when the configuration is usable
 */
public record OperatorAuthConfig(Mode mode, String audience, String baseUrl, URI jwksUrl, URI introspectionEndpoint,
                                 String introspectionClientId, Supplier<String> introspectionClientSecret,
                                 boolean insecureTls, int authFailuresPerMinute, int mutationsPerMinute,
                                 DeploymentProfile profile, boolean redisConfigured, String problem) {

    /** The catalogue's component. */
    public static final String COMPONENT = "operator-auth";
    public static final String MODE = "OIDF_OPERATOR_AUTH_MODE";
    public static final String AUDIENCE = "OIDF_OPERATOR_AUDIENCE";
    public static final String BASE_URL = "OIDF_OPERATOR_BASE_URL";
    public static final String JWKS_URL = "OIDF_OPERATOR_JWKS_URL";
    public static final String INTROSPECTION_ENDPOINT = "OIDF_OPERATOR_INTROSPECTION_ENDPOINT";
    public static final String INTROSPECTION_CLIENT_ID = "OIDF_OPERATOR_INTROSPECTION_CLIENT_ID";
    public static final String INTROSPECTION_CLIENT_SECRET = "OIDF_OPERATOR_INTROSPECTION_CLIENT_SECRET";
    public static final String INSECURE_TLS = "OIDF_OPERATOR_INSECURE_TLS";
    public static final String AUTH_FAILURES_PER_MINUTE = "OIDF_OPERATOR_AUTH_FAILURES_PER_MINUTE";
    public static final String MUTATIONS_PER_MINUTE = "OIDF_OPERATOR_MUTATIONS_PER_MINUTE";

    /** How a token is verified. */
    public enum Mode {
        /** A JWT access token, against PingFederate's JWKS (rs-validation's DelegatedTokenValidator). */
        JWT,
        /** Any access token, by asking PingFederate's introspection endpoint (RFC 7662, platform.auth). */
        INTROSPECTION
    }

    /** Whether requests can be authenticated at all. */
    public boolean usable() {
        return this.problem == null;
    }

    /**
     * Reads and checks {@code settings}.
     *
     * @param redisConfigured whether this process names a Redis ({@code RedisConfig.isConfigured()}): without one the
     *                        DPoP replay store is this JVM's, which production allows only under the
     *                        {@code in-memory-state} accepted risk (Phase 3 decision 9)
     */
    public static OperatorAuthConfig from(Settings settings, DeploymentProfile profile, AcceptedRisks risks,
                                          boolean redisConfigured) {
        Mode mode = Mode.JWT;
        String audience = null;
        String baseUrl = null;
        URI jwks = null;
        URI endpoint = null;
        String clientId = null;
        Supplier<String> secret = null;
        boolean insecure = false;
        int failures = 10;
        int mutations = 60;
        String problem;
        try {
            mode = Mode.valueOf(settings.choice(MODE).toUpperCase(Locale.ROOT));
            audience = settings.string(AUDIENCE);
            URI base = settings.url(BASE_URL);
            baseUrl = base == null ? null : base.toString();
            jwks = settings.url(JWKS_URL);
            endpoint = settings.url(INTROSPECTION_ENDPOINT);
            clientId = settings.string(INTROSPECTION_CLIENT_ID);
            Secret s = settings.secret(INTROSPECTION_CLIENT_SECRET);
            secret = s == null ? null : s::reveal;
            insecure = settings.bool(INSECURE_TLS);
            failures = settings.integer(AUTH_FAILURES_PER_MINUTE);
            mutations = settings.integer(MUTATIONS_PER_MINUTE);
            problem = problem(mode, audience, base, jwks, endpoint, clientId, secret != null, insecure, profile, risks,
                    redisConfigured);
        } catch (RuntimeException e) {
            // SettingRefused, or a value its entry refuses: the message names the setting, never a secret's value.
            problem = e.getMessage();
        }
        return new OperatorAuthConfig(mode, audience, baseUrl == null ? null : stripSlash(baseUrl), jwks, endpoint,
                clientId, secret, insecure, failures, mutations, profile, redisConfigured, problem);
    }

    /** Why this configuration cannot authenticate anyone, or null. */
    static String problem(Mode mode, String audience, URI base, URI jwks, URI endpoint, String clientId,
                          boolean hasSecret, boolean insecure, DeploymentProfile profile, AcceptedRisks risks,
                          boolean redisConfigured) {
        if (audience == null || audience.isEmpty()) {
            return AUDIENCE + " is not set, so no token can be checked for its audience";
        }
        String baseProblem = baseUrlProblem(base, profile);
        if (baseProblem != null) {
            return baseProblem;
        }
        if (mode == Mode.JWT && jwks == null) {
            return JWKS_URL + " is not set, and " + MODE + " is jwt";
        }
        if (mode == Mode.INTROSPECTION && (endpoint == null || clientId == null || !hasSecret)) {
            return INTROSPECTION_ENDPOINT + ", " + INTROSPECTION_CLIENT_ID + " and " + INTROSPECTION_CLIENT_SECRET
                    + " are all required when " + MODE + " is introspection";
        }
        if (insecure && profile.isProduction()) {
            return INSECURE_TLS + " is forbidden in production";
        }
        if (!redisConfigured && profile.isProduction() && !risks.accepts(AcceptedRisk.IN_MEMORY_STATE)) {
            return "no Redis is configured (OIDF_REDIS_URL), so DPoP proofs would be remembered in this JVM only;"
                    + " production allows that only with the accepted risk " + AcceptedRisk.IN_MEMORY_STATE.id()
                    + " in " + AcceptedRisks.SETTING;
        }
        return null;
    }

    /** An http or https origin, no path but "/", no query, fragment or user information; https in production. */
    static String baseUrlProblem(URI base, DeploymentProfile profile) {
        if (base == null) {
            return BASE_URL + " is not set, so no DPoP proof's htu can be checked";
        }
        String scheme = base.getScheme() == null ? "" : base.getScheme().toLowerCase(Locale.ROOT);
        String path = base.getRawPath() == null ? "" : base.getRawPath();
        if (!scheme.matches("https?") || base.getHost() == null || !(path.isEmpty() || "/".equals(path))
                || base.getRawQuery() != null || base.getRawFragment() != null || base.getRawUserInfo() != null) {
            return BASE_URL + " is an http or https origin with no path, query, fragment or user information, not "
                    + base;
        }
        if (!"https".equals(scheme) && profile.isProduction()) {
            return BASE_URL + " must be https in production, not " + base;
        }
        return null;
    }

    private static String stripSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
