package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.util.ArrayList;
import java.util.Set;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import javax.servlet.ServletConfig;

/**
 * Immutable per-component configuration for the client-registration servlet and filters: the
 * trust-controller coordinates plus cache sizing, chain freshness and signing algorithms.
 *
 * <p>The deployment-wide half (trust-controller host / base URL / SSL tolerance) comes from
 * {@link FederationRuntimeConfig}, not from this object's constructor. It used to be mirrored into
 * three {@code public static} fields here, written as a constructor side effect — so the last
 * component to initialise silently redefined the trust anchor for every other one, and nothing at
 * all had initialised until the first request arrived. That is now a single immutable process-wide
 * value; this class only carries the settings that legitimately vary per component.
 */
public final class RegistrationConfiguration {
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
    }

    /**
     * The deployment-wide trust-controller settings come from {@link FederationRuntimeConfig}. An
     * {@code init-param} may still name them, but only to agree: a value that differs from the
     * process-wide one is a configuration error, because two components would then be validating
     * chains against two different anchors. Fail at init rather than at some later request.
     */
    private static void requireAgreement(ServletConfig config, String initParam, String actual) {
        String declared = config.getInitParameter(initParam);
        if (declared != null && !declared.isBlank() && !declared.trim().equals(actual)) {
            throw new IllegalArgumentException("init-param " + initParam + "=\"" + declared.trim()
                    + "\" conflicts with the deployment-wide value \"" + actual
                    + "\"; configure it once, in the environment");
        }
    }

    static RegistrationConfiguration fromServletConfig(ServletConfig config) {
        try {
            FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
            requireAgreement(config, "trustControllerHost", runtime.trustControllerHost());
            requireAgreement(config, "trustControllerBaseUrl", runtime.trustControllerBaseUrl());
            String trustControllerHost = runtime.trustControllerHost();
            String trustControllerBaseUrl = runtime.trustControllerBaseUrl();
            boolean ignoreSslErrors = runtime.ignoreSslErrors();
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

