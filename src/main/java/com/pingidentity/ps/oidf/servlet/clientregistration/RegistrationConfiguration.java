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
    static final String SUBORDINATE_CACHE_MAX_ENTRIES_PARAM = "subordinateStatementCacheMaxEntries";
    static final String TRUST_CHAIN_ENTRY_MAX_AGE_PARAM = "trustChainEntryMaxAgeSeconds";
    private static final String DEFAULT_SIGNING_ALGORITHM = "RS256";
    private static final Set<String> SUPPORTED_SIGNING_ALGORITHMS = Set.of("RS256", "PS256");
    private final boolean ignoreSslErrors;
    private final String trustControllerHost;
    private final int subordinateStatementCacheMaxEntries;
    private final long trustChainEntryMaxAgeSeconds;
    private final String signingAlgorithm;
    private final Set<String> acceptedSigningAlgorithms;

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors) {
        this(trustControllerHost, ignoreSslErrors, 256, 60L, DEFAULT_SIGNING_ALGORITHM, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries) {
        this(trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, 60L, DEFAULT_SIGNING_ALGORITHM, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds) {
        this(trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, trustChainEntryMaxAgeSeconds, DEFAULT_SIGNING_ALGORITHM, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds, String signingAlgorithm) {
        this(trustControllerHost, ignoreSslErrors, subordinateStatementCacheMaxEntries, trustChainEntryMaxAgeSeconds, signingAlgorithm, Set.of());
    }

    RegistrationConfiguration(String trustControllerHost, boolean ignoreSslErrors, int subordinateStatementCacheMaxEntries, long trustChainEntryMaxAgeSeconds, String signingAlgorithm, Set<String> acceptedSigningAlgorithms) {
        if (subordinateStatementCacheMaxEntries != -1 && subordinateStatementCacheMaxEntries <= 0) {
            throw new IllegalArgumentException("subordinateStatementCacheMaxEntries must be > 0, or -1 for unbounded, got " + subordinateStatementCacheMaxEntries);
        }
        this.ignoreSslErrors = ignoreSslErrors;
        this.trustControllerHost = trustControllerHost;
        this.subordinateStatementCacheMaxEntries = subordinateStatementCacheMaxEntries;
        this.trustChainEntryMaxAgeSeconds = trustChainEntryMaxAgeSeconds;
        this.signingAlgorithm = signingAlgorithm;
        this.acceptedSigningAlgorithms = acceptedSigningAlgorithms != null ? Set.copyOf(acceptedSigningAlgorithms) : Set.of();
        _IGNORE_SSL_ERRORS = ignoreSslErrors;
        _TRUST_CONTROLLER_HOST = trustControllerHost;
    }

    static RegistrationConfiguration fromServletConfig(ServletConfig config) {
        try {
            String trustControllerHost = config.getInitParameter("trustControllerHost");
            boolean ignoreSslErrors = Boolean.parseBoolean(config.getInitParameter("ignoreSslErrors"));
            int cacheMaxEntries = parseCacheMaxEntries(config.getInitParameter(SUBORDINATE_CACHE_MAX_ENTRIES_PARAM));
            long trustChainEntryMaxAge = parseTrustChainEntryMaxAge(config.getInitParameter(TRUST_CHAIN_ENTRY_MAX_AGE_PARAM));
            String signingAlgorithm = parseSigningAlgorithm(config.getInitParameter("signingAlgorithm"));
            Set<String> acceptedSigningAlgorithms = parseAcceptedSigningAlgorithms(config.getInitParameter("acceptedSigningAlgorithms"));
            return new RegistrationConfiguration(trustControllerHost, ignoreSslErrors, cacheMaxEntries, trustChainEntryMaxAge, signingAlgorithm, acceptedSigningAlgorithms);
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

