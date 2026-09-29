/*
 * The processor's 0.6.0 fields for the PDP call: TLS trust, the batch URL, the decision cache and the circuit breaker.
 */
package com.pingidentity.ps.oidf.rar;

import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.validation.ConfigurationValidator;
import org.sourceid.saml20.adapter.gui.validation.ValidationException;

import java.security.cert.CertificateException;
import java.util.Set;

/**
 * The settings plan item S2c added to the processor, read from an instance's configuration and checked. Each is
 * checked twice, like the PDP URL: {@link Validator} runs when the admin console or the admin API saves the instance,
 * where the message reaches the person saving it, and {@link #of} runs at configure time, which is the only check an
 * archive import gets - a configuration it refuses leaves the instance unconfigured, and an unconfigured instance
 * refuses every request that reaches it.
 */
record PdpResilience(String tlsMode, String pinnedPem, String batchUrl, Set<String> cacheTypes, int cacheTtlSeconds,
                     int breakerFailures, int breakerOpenSeconds) {

    static final String TLS_TRUST = "PDP TLS trust";
    static final String PINNED_CAS = "PDP CA certificates (PEM)";
    static final String BATCH_URL = "AuthZEN batch URL";
    static final String CACHE_TYPES = "Decision cache types";
    static final String CACHE_TTL = "Decision cache TTL (s)";
    static final String BREAKER_FAILURES = "Circuit breaker failures";
    static final String BREAKER_OPEN = "Circuit breaker open (s)";

    /**
     * The fields of {@code configuration}, checked.
     *
     * @param dialect        the PDP dialect the instance speaks: a batch URL is an AuthZEN endpoint
     * @param principalTypes the types requiring an authenticated principal, which the cache may never hold
     * @throws IllegalStateException naming the field and what is wrong with it
     */
    static PdpResilience of(Configuration configuration, String profile, boolean authzen, Set<String> principalTypes) {
        String problem = problem(configuration, profile, authzen, principalTypes);
        if (problem != null) {
            throw new IllegalStateException(problem);
        }
        return new PdpResilience(PdpTls.modeOf(configuration.getFieldValue(TLS_TRUST)),
                configuration.getFieldValue(PINNED_CAS), blankToNull(configuration.getFieldValue(BATCH_URL)),
                PdpDecisions.typesOf(configuration.getFieldValue(CACHE_TYPES)),
                DecisionCache.ttlSecondsOf(intOf(configuration.getFieldValue(CACHE_TTL), DecisionCache.DEFAULT_TTL_SECONDS)),
                intOf(configuration.getFieldValue(BREAKER_FAILURES), CircuitBreaker.DEFAULT_THRESHOLD),
                intOf(configuration.getFieldValue(BREAKER_OPEN), CircuitBreaker.DEFAULT_OPEN_SECONDS));
    }

    /** What is wrong with these fields, or {@code null}. */
    static String problem(Configuration configuration, String profile, boolean authzen, Set<String> principalTypes) {
        String mode;
        try {
            mode = PdpTls.modeOf(configuration.getFieldValue(TLS_TRUST));
        } catch (IllegalStateException e) {
            return e.getMessage();
        }
        if (PdpTls.PINNED_CA.equals(mode)) {
            try {
                PdpTls.certificatesOf(configuration.getFieldValue(PINNED_CAS));
            } catch (CertificateException | RuntimeException e) {
                return PINNED_CAS + " must hold the PEM of at least one CA certificate when " + TLS_TRUST + " is "
                        + PdpTls.PINNED_CA + ": " + e.getMessage();
            }
        }
        String batchUrl = blankToNull(configuration.getFieldValue(BATCH_URL));
        if (batchUrl != null) {
            if (!authzen) {
                return BATCH_URL + " is an AuthZEN Access Evaluations endpoint, and this instance's PDP dialect is not authzen";
            }
            String urlProblem = PdpUrlPolicy.problem(batchUrl, profile);
            if (urlProblem != null) {
                return BATCH_URL + ": " + urlProblem;
            }
        }
        String refusal = DecisionCache.refusal(PdpDecisions.typesOf(configuration.getFieldValue(CACHE_TYPES)), principalTypes);
        if (refusal != null) {
            return refusal;
        }
        String ttl = configuration.getFieldValue(CACHE_TTL);
        if (notBlank(ttl) && !inRange(ttl, 1, DecisionCache.MAX_TTL_SECONDS)) {
            return CACHE_TTL + " must be a whole number of seconds from 1 to " + DecisionCache.MAX_TTL_SECONDS + ", not '" + ttl.trim() + "'";
        }
        String failures = configuration.getFieldValue(BREAKER_FAILURES);
        if (notBlank(failures) && !inRange(failures, 1, 1000)) {
            return BREAKER_FAILURES + " must be a whole number from 1 to 1000, not '" + failures.trim() + "'";
        }
        String open = configuration.getFieldValue(BREAKER_OPEN);
        if (notBlank(open) && !inRange(open, 1, 3600)) {
            return BREAKER_OPEN + " must be a whole number of seconds from 1 to 3600, not '" + open.trim() + "'";
        }
        return null;
    }

    static boolean inRange(String value, int min, int max) {
        try {
            int n = Integer.parseInt(value.trim());
            return n >= min && n <= max;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    static int intOf(String value, int fallback) {
        if (!notBlank(value)) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static String blankToNull(String value) {
        return notBlank(value) ? value.trim() : null;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.isBlank();
    }

    /** The admin-console half: every rule above, on save, with the dialect and principal types the form holds. */
    static final class Validator implements ConfigurationValidator {
        private final String profile;
        private final String dialectField;
        private final String authzenDialect;
        private final String principalTypesField;

        Validator(String profile, String dialectField, String authzenDialect, String principalTypesField) {
            this.profile = profile;
            this.dialectField = dialectField;
            this.authzenDialect = authzenDialect;
            this.principalTypesField = principalTypesField;
        }

        @Override
        public void validate(Configuration configuration) throws ValidationException {
            String dialect = configuration.getFieldValue(dialectField);
            boolean authzen = authzenDialect.equalsIgnoreCase(dialect == null ? "" : dialect.trim());
            Set<String> principalTypes = GovernanceEngineConfig.authenticatedPrincipalTypesOf(
                    configuration.getFieldValue(principalTypesField));
            String problem = problem(configuration, profile, authzen, principalTypes);
            if (problem != null) {
                throw new ValidationException(problem);
            }
        }
    }
}
