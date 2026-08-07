package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.util.ArrayList;
import java.util.Set;
import javax.servlet.ServletConfig;

/**
 * Immutable configuration for the client-registration servlet, sourced from servlet init
 * parameters: trust-controller host, SSL error tolerance, subordinate-statement cache size,
 * trust-chain entry max age, and the signing algorithm plus accepted signing algorithms.
 * The legacy static fields mirror the trust-controller host / SSL flag for OGNL access.
 */
public final class RegistrationConfiguration {
    public static boolean _IGNORE_SSL_ERRORS = false;
    public static String _TRUST_CONTROLLER_HOST = "";
    public static String _TRUST_CONTROLLER_BASE_URL = "";
    static final String SUBORDINATE_CACHE_MAX_ENTRIES_PARAM = "subordinateStatementCacheMaxEntries";
    static final String TRUST_CHAIN_ENTRY_MAX_AGE_PARAM = "trustChainEntryMaxAgeSeconds";
    private static final String DEFAULT_SIGNING_ALGORITHM = "RS256";
    private static final Set<String> SUPPORTED_SIGNING_ALGORITHMS = Set.of("RS256", "PS256");
    private final boolean ignoreSslErrors;
    private final String trustControllerHost;
    private final String trustControllerBaseUrl;
    private final int subordinateStatementCacheMaxEntries;
    private final long trustChainEntryMaxAgeSeconds;
    private final String signingAlgorithm;
    private final Set<String> acceptedSigningAlgorithms;

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors) {
        this(trustControllerHost, trustControllerHost, ignoreSslErrors, 256, 60L, DEFAULT_SIGNING_ALGORITHM, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries) {
        this(trustControllerHost, trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, 60L, DEFAULT_SIGNING_ALGORITHM, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds) {
        this(trustControllerHost, trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, trustChainEntryMaxAgeSeconds, DEFAULT_SIGNING_ALGORITHM, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds, String signingAlgorithm) {
        this(trustControllerHost, trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, trustChainEntryMaxAgeSeconds, signingAlgorithm, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds, String signingAlgorithm, Set<String> acceptedSigningAlgorithms) {
        this(trustControllerHost, trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, trustChainEntryMaxAgeSeconds, signingAlgorithm, acceptedSigningAlgorithms);
    }

    /**
     * @param trustControllerHost the trust controller's bare federation identity — used for
     *     {@code knownTrustAnchor} matching during trust-chain walks, NOT necessarily a URL PF can
     *     reach directly (e.g. when PF is its own anchor, this is its path-less self-computed OAuth
     *     issuer).
     * @param trustControllerBaseUrl the HTTP base actually used to reach the trust controller's
     *     federation endpoints (may carry a context path, e.g. {@code /oidf}) — distinct from
     *     {@code trustControllerHost} because that identity string and its reachable location are
     *     not always the same (see {@code HttpTrustControllerGateway}'s {@code selfIssuer} javadoc).
     */
    RegistrationConfiguration(String trustControllerHost, String trustControllerBaseUrl, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds, String signingAlgorithm, Set<String> acceptedSigningAlgorithms) {
        if (subordinateStatementCacheMaxEntries != -1 && subordinateStatementCacheMaxEntries <= 0) {
            throw new IllegalArgumentException("subordinateStatementCacheMaxEntries must be > 0, or -1 for unbounded, got " + subordinateStatementCacheMaxEntries);
        }
        this.ignoreSslErrors = ignoreSslErrors;
        this.trustControllerHost = trustControllerHost;
        this.trustControllerBaseUrl = trustControllerBaseUrl == null || trustControllerBaseUrl.isBlank() ? trustControllerHost : trustControllerBaseUrl;
        this.subordinateStatementCacheMaxEntries = subordinateStatementCacheMaxEntries;
        this.trustChainEntryMaxAgeSeconds = trustChainEntryMaxAgeSeconds;
        this.signingAlgorithm = signingAlgorithm;
        this.acceptedSigningAlgorithms = acceptedSigningAlgorithms != null ? Set.copyOf(acceptedSigningAlgorithms) : Set.of();
        _IGNORE_SSL_ERRORS = ignoreSslErrors;
        _TRUST_CONTROLLER_HOST = trustControllerHost;
        _TRUST_CONTROLLER_BASE_URL = this.trustControllerBaseUrl;
    }

    /**
     * Reads a setting from the servlet {@code init-param}, falling back to an environment variable —
     * same pattern as {@code FederationConfiguration.setting}. Without this, {@code _TRUST_CONTROLLER_HOST}
     * stays {@code ""} (and {@link ClientAttestationUtils#validateClientAttestation(Object)} fails
     * every attestation with an empty {@code knownTrustAnchor}) until {@code /federation/register} has
     * been hit at least once in this JVM's lifetime to trigger {@link OpenIdRegistrationServlet#init}
     * — a fragile, request-order-dependent way to configure a value that's really deployment-wide.
     */
    private static String setting(ServletConfig config, String initParam, String envVar) {
        String value = config.getInitParameter(initParam);
        if (value == null || value.isBlank()) {
            value = System.getenv(envVar);
        }
        return value;
    }

    static RegistrationConfiguration fromServletConfig(ServletConfig config) {
        try {
            String trustControllerHost = setting(config, "trustControllerHost", "OIDF_FEDERATION_TRUST_CONTROLLER_HOST");
            String trustControllerBaseUrl = setting(config, "trustControllerBaseUrl", "OIDF_FEDERATION_TRUST_CONTROLLER_BASE_URL");
            boolean ignoreSslErrors = Boolean.parseBoolean(setting(config, "ignoreSslErrors", "OIDF_FEDERATION_IGNORE_SSL_ERRORS"));
            int cacheMaxEntries = parseCacheMaxEntries(config.getInitParameter(SUBORDINATE_CACHE_MAX_ENTRIES_PARAM));
            long trustChainEntryMaxAge = parseTrustChainEntryMaxAge(config.getInitParameter(TRUST_CHAIN_ENTRY_MAX_AGE_PARAM));
            String signingAlgorithm = parseSigningAlgorithm(config.getInitParameter("signingAlgorithm"));
            Set<String> acceptedSigningAlgorithms = parseAcceptedSigningAlgorithms(config.getInitParameter("acceptedSigningAlgorithms"));
            return new RegistrationConfiguration(trustControllerHost, trustControllerBaseUrl, ignoreSslErrors, cacheMaxEntries, trustChainEntryMaxAge, signingAlgorithm, acceptedSigningAlgorithms);
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid registration servlet configuration", e);
        }
    }

    private static Set<String> parseAcceptedSigningAlgorithms(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        ArrayList<String> result = new ArrayList<String>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result.isEmpty() ? Set.of() : Set.copyOf(result);
    }

    private static String parseSigningAlgorithm(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_SIGNING_ALGORITHM;
        }
        String trimmed = value.trim();
        if (!SUPPORTED_SIGNING_ALGORITHMS.contains(trimmed)) {
            throw new IllegalArgumentException("signingAlgorithm must be RS256 or PS256, got: " + trimmed);
        }
        return trimmed;
    }

    private static int parseCacheMaxEntries(String raw) {
        int parsed;
        if (raw == null || raw.isBlank()) {
            return 256;
        }
        try {
            parsed = Integer.parseInt(raw.trim());
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("subordinateStatementCacheMaxEntries must be an integer, got \"" + raw + "\"", e);
        }
        if (parsed != -1 && parsed <= 0) {
            throw new IllegalArgumentException("subordinateStatementCacheMaxEntries must be > 0, or -1 for unbounded, got " + parsed);
        }
        return parsed;
    }

    String signingAlgorithm() {
        return this.signingAlgorithm;
    }

    Set<String> acceptedSigningAlgorithms() {
        return this.acceptedSigningAlgorithms;
    }

    String trustControllerHost() {
        return this.trustControllerHost;
    }

    String trustControllerBaseUrl() {
        return this.trustControllerBaseUrl;
    }

    boolean ignoreSslErrors() {
        return this.ignoreSslErrors;
    }

    int subordinateStatementCacheMaxEntries() {
        return this.subordinateStatementCacheMaxEntries;
    }

    long trustChainEntryMaxAgeSeconds() {
        return this.trustChainEntryMaxAgeSeconds;
    }

    private static long parseTrustChainEntryMaxAge(String raw) {
        long parsed;
        if (raw == null || raw.isBlank()) {
            return 60L;
        }
        try {
            parsed = Long.parseLong(raw.trim());
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("trustChainEntryMaxAgeSeconds must be an integer (seconds), got \"" + raw + "\"", e);
        }
        if (parsed <= 0L) {
            return 60L;
        }
        return parsed;
    }
}

