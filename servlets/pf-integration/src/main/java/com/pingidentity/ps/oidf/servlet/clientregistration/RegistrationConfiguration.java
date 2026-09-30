package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.util.Set;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.pf.settings.InitParams;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import jakarta.servlet.ServletConfig;

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
    static final String SIGNING_ALGORITHM_PARAM = "signingAlgorithm";
    static final String ACCEPTED_SIGNING_ALGORITHMS_PARAM = "acceptedSigningAlgorithms";
    static final String TRUST_CONTROLLER_HOST_PARAM = "trustControllerHost";
    static final String TRUST_CONTROLLER_BASE_URL_PARAM = "trustControllerBaseUrl";
    /** The settings catalogue these init-params are in ({@code META-INF/oidf-settings/registration.json}, S5C's). */
    static final String CATALOGUE = "registration";
    private static final String DEFAULT_SIGNING_ALGORITHM = "RS256";
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
    static void requireAgreement(Settings settings, String initParam, String actual) {
        String declared = settings.string(initParam);
        if (declared != null && !declared.equals(actual)) {
            throw new IllegalArgumentException("init-param " + initParam + "=\"" + declared
                    + "\" conflicts with the deployment-wide value \"" + actual
                    + "\"; configure it once, in the environment");
        }
    }

    /**
     * This component's settings from its init-params, through the {@value #CATALOGUE} catalogue (plan item ST-5): each
     * parsed strictly, so a value its entry refuses stops the servlet or filter starting, naming it.
     */
    static Settings settings(java.util.function.Function<String, String> initParams) {
        return Settings.load(RegistrationConfiguration.class.getClassLoader(), CATALOGUE)
                .with(Sources.process().withInitParams(initParams));
    }

    static RegistrationConfiguration fromServletConfig(ServletConfig config) {
        try {
            FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
            Settings settings = settings(InitParams.of(config));
            requireAgreement(settings, TRUST_CONTROLLER_HOST_PARAM, runtime.trustControllerHost());
            requireAgreement(settings, TRUST_CONTROLLER_BASE_URL_PARAM, runtime.trustControllerBaseUrl());
            return new RegistrationConfiguration(runtime.trustControllerHost(), runtime.trustControllerBaseUrl(), runtime.ignoreSslErrors(),
                    cacheMaxEntries(settings), settings.duration(TRUST_CHAIN_ENTRY_MAX_AGE_PARAM).toSeconds(),
                    settings.choice(SIGNING_ALGORITHM_PARAM), acceptedSigningAlgorithms(settings));
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid registration servlet configuration", e);
        }
    }

    /**
     * For a filter in front of PingFederate's OAuth endpoints: the deployment-wide trust controller, and this filter's
     * own sizing from its init-params - parsed as strictly as the registration servlet's, so a typo stops the filter
     * starting rather than quietly meaning the default.
     */
    static RegistrationConfiguration forFilter(FederationRuntimeConfig runtime, jakarta.servlet.FilterConfig config) {
        Settings settings = settings(InitParams.of(config));
        return new RegistrationConfiguration(runtime.trustControllerHost(), runtime.trustControllerBaseUrl(), runtime.ignoreSslErrors(),
                cacheMaxEntries(settings), settings.duration(TRUST_CHAIN_ENTRY_MAX_AGE_PARAM).toSeconds(),
                DEFAULT_SIGNING_ALGORITHM, acceptedSigningAlgorithms(settings));
    }

    static Set<String> acceptedSigningAlgorithms(Settings settings) {
        Set<String> words = settings.words(ACCEPTED_SIGNING_ALGORITHMS_PARAM);
        return words == null ? Set.of() : Set.copyOf(words);
    }

    /** {@value #SUBORDINATE_CACHE_MAX_ENTRIES_PARAM}: at least 1, or -1 for no bound; its entry's range admits 0, which is refused here. */
    static int cacheMaxEntries(Settings settings) {
        int parsed = settings.integer(SUBORDINATE_CACHE_MAX_ENTRIES_PARAM);
        if (parsed == 0) {
            throw new SettingRefused(SUBORDINATE_CACHE_MAX_ENTRIES_PARAM, SUBORDINATE_CACHE_MAX_ENTRIES_PARAM
                    + " must be > 0, or -1 for unbounded, got 0");
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
}
