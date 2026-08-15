package com.pingidentity.ps.oidf.federation;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import javax.servlet.ServletConfig;

/**
 * Immutable configuration for the trust-anchor federation servlet: trust anchor issuers,
 * subordinates, trust controller host, signing algorithm, CORS settings and attestation
 * metadata. {@link #fromServletConfig} parses and validates these from servlet init parameters.
 */
public final class FederationConfiguration {
    private static final String DEFAULT_CORS_ALLOW_ORIGIN = "*";
    private static final String DEFAULT_CORS_ALLOW_METHODS = "GET, OPTIONS";
    private static final String DEFAULT_CORS_ALLOW_HEADERS = "Accept, Content-Type";
    private static final int DEFAULT_CORS_MAX_AGE = 3600;
    private static final String DEFAULT_SIGNING_ALGORITHM = "RS256";
    private static final Set<String> SUPPORTED_SIGNING_ALGORITHMS = Set.of("RS256", "PS256");
    private final List<String> trustAnchorIssuers;
    private final List<String> subordinates;
    private final boolean ignoreSslErrors;
    private final String trustControllerHost;
    private final boolean corsEnabled;
    private final String corsAllowOrigin;
    private final String corsAllowMethods;
    private final String corsAllowHeaders;
    private final int corsMaxAge;
    private final String signingAlgorithm;
    private final AttestationMetadataConfig attestationMetadata;
    private final String attesterJwks;

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, String trustControllerHost, boolean ignoreSslErrors) {
        this(trustAnchorIssuers, subordinates, trustControllerHost, ignoreSslErrors, true, DEFAULT_CORS_ALLOW_ORIGIN, DEFAULT_CORS_ALLOW_METHODS, DEFAULT_CORS_ALLOW_HEADERS, 3600, DEFAULT_SIGNING_ALGORITHM);
    }

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, String trustControllerHost, boolean ignoreSslErrors, boolean corsEnabled, String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge) {
        this(trustAnchorIssuers, subordinates, trustControllerHost, ignoreSslErrors, corsEnabled, corsAllowOrigin, corsAllowMethods, corsAllowHeaders, corsMaxAge, DEFAULT_SIGNING_ALGORITHM);
    }

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, String trustControllerHost, boolean ignoreSslErrors, boolean corsEnabled, String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge, String signingAlgorithm) {
        this(trustAnchorIssuers, subordinates, trustControllerHost, ignoreSslErrors, corsEnabled, corsAllowOrigin, corsAllowMethods, corsAllowHeaders, corsMaxAge, signingAlgorithm, AttestationMetadataConfig.defaults());
    }

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, String trustControllerHost, boolean ignoreSslErrors, boolean corsEnabled, String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge, String signingAlgorithm, AttestationMetadataConfig attestationMetadata) {
        this(trustAnchorIssuers, subordinates, trustControllerHost, ignoreSslErrors, corsEnabled, corsAllowOrigin, corsAllowMethods, corsAllowHeaders, corsMaxAge, signingAlgorithm, attestationMetadata, null);
    }

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, String trustControllerHost, boolean ignoreSslErrors, boolean corsEnabled, String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge, String signingAlgorithm, AttestationMetadataConfig attestationMetadata, String attesterJwks) {
        this.trustAnchorIssuers = List.copyOf(trustAnchorIssuers);
        this.subordinates = List.copyOf(subordinates);
        this.ignoreSslErrors = ignoreSslErrors;
        this.trustControllerHost = trustControllerHost;
        this.corsEnabled = corsEnabled;
        this.corsAllowOrigin = corsAllowOrigin;
        this.corsAllowMethods = corsAllowMethods;
        this.corsAllowHeaders = corsAllowHeaders;
        this.corsMaxAge = corsMaxAge;
        this.signingAlgorithm = signingAlgorithm;
        this.attestationMetadata = attestationMetadata != null ? attestationMetadata : AttestationMetadataConfig.defaults();
        this.attesterJwks = attesterJwks == null || attesterJwks.isBlank() ? null : attesterJwks;
    }

    /**
     * Reads a setting from the servlet {@code init-param}, falling back to an environment variable. The env
     * fallback lets an ephemeral, image-baked PingFederate be configured as a federation entity through
     * deployment env (like the other {@code OIDF_*} settings) rather than a web.xml rebuild per deployment.
     */
    private static String setting(ServletConfig config, String initParam, String envVar) {
        String value = config.getInitParameter(initParam);
        if (value == null || value.isBlank()) {
            value = System.getenv(envVar);
        }
        return value;
    }

    public static FederationConfiguration fromServletConfig(ServletConfig config) {
        try {
            String trustControllerHost = setting(config, "trustControllerHost", "OIDF_FEDERATION_TRUST_CONTROLLER_HOST");
            boolean ignoreSslErrors = Boolean.parseBoolean(setting(config, "ignoreSslErrors", "OIDF_FEDERATION_IGNORE_SSL_ERRORS"));
            List<String> trustAnchorIssuers = parseCommaSeparated(setting(config, "trustAnchorIssuers", "OIDF_FEDERATION_TRUST_ANCHORS"));
            List<String> subordinates = parseCommaSeparated(setting(config, "subordinates", "OIDF_FEDERATION_SUBORDINATES"));
            if (trustAnchorIssuers.isEmpty()) {
                throw new IllegalArgumentException("Configuration must contain at least one trust anchor issuer");
            }
            String signingAlgorithm = parseSigningAlgorithm(setting(config, "signingAlgorithm", "OIDF_FEDERATION_SIGNING_ALG"));
            boolean corsEnabled = parseBoolean(config.getInitParameter("corsEnabled"), true);
            String corsAllowOrigin = orDefault(config.getInitParameter("corsAllowOrigin"), DEFAULT_CORS_ALLOW_ORIGIN);
            String corsAllowMethods = orDefault(config.getInitParameter("corsAllowMethods"), DEFAULT_CORS_ALLOW_METHODS);
            String corsAllowHeaders = orDefault(config.getInitParameter("corsAllowHeaders"), DEFAULT_CORS_ALLOW_HEADERS);
            int corsMaxAge = parseInt(config.getInitParameter("corsMaxAge"), 3600);
            AttestationMetadataConfig attestationMetadata = AttestationMetadataConfig.fromServletConfig(config);
            String attesterJwks = setting(config, "attesterJwks", "OIDF_FEDERATION_ATTESTER_JWKS");
            return new FederationConfiguration(trustAnchorIssuers, subordinates, trustControllerHost, ignoreSslErrors, corsEnabled, corsAllowOrigin, corsAllowMethods, corsAllowHeaders, corsMaxAge, signingAlgorithm, attestationMetadata, attesterJwks);
        }
        catch (Exception e) {
            throw new IllegalArgumentException("Invalid federation servlet configuration", e);
        }
    }

    String trustControllerHost() {
        return this.trustControllerHost;
    }

    List<String> trustAnchorIssuers() {
        return this.trustAnchorIssuers;
    }

    List<String> subordinates() {
        return this.subordinates;
    }

    List<String> authorityHints() {
        return this.trustAnchorIssuers;
    }

    String defaultTrustAnchorIssuer() {
        return this.trustAnchorIssuers.get(0);
    }

    String findTrustAnchor(String issuer) {
        for (String configured : this.trustAnchorIssuers) {
            if (!configured.equals(issuer)) continue;
            return configured;
        }
        throw new IllegalArgumentException("Unknown trust anchor: " + issuer);
    }

    boolean isTrustAnchor(String issuer) {
        return this.trustAnchorIssuers.contains(issuer);
    }

    private static List<String> parseCommaSeparated(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        ArrayList<String> result = new ArrayList<String>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }
        return result;
    }

    private static String orDefault(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value.trim();
    }

    private static boolean parseBoolean(String value, boolean fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return Boolean.parseBoolean(value.trim());
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

    private static int parseInt(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        }
        catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid integer value: " + value, e);
        }
    }

    public String signingAlgorithm() {
        return this.signingAlgorithm;
    }

    /**
     * Public JWKS (raw JSON) of the Client Attester co-hosted with this entity, published in the
     * entity configuration as {@code metadata.oauth_client_attester.jwks} so that remote ASes can
     * resolve the attestation-signing keys through the federation trust chain instead of a locally
     * pinned attester file. Null when this entity hosts no attester.
     */
    String attesterJwks() {
        return this.attesterJwks;
    }

    AttestationMetadataConfig attestationMetadata() {
        return this.attestationMetadata;
    }

    public boolean ignoreSslErrors() {
        return this.ignoreSslErrors;
    }

    public boolean corsEnabled() {
        return this.corsEnabled;
    }

    public String corsAllowOrigin() {
        return this.corsAllowOrigin;
    }

    public String corsAllowMethods() {
        return this.corsAllowMethods;
    }

    public String corsAllowHeaders() {
        return this.corsAllowHeaders;
    }

    public int corsMaxAge() {
        return this.corsMaxAge;
    }
}

