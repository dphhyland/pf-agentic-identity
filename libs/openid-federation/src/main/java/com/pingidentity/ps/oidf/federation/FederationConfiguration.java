package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.jose.Jwks;
import java.util.List;
import java.util.Map;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import jakarta.servlet.ServletConfig;

/**
 * Immutable configuration for the trust-anchor federation servlet: trust anchor issuers,
 * subordinates, signing algorithm, CORS settings, attestation metadata, and what the entity advertises
 * and resolves. {@link #fromServletConfig} reads them through {@code platform.settings} and this module's
 * {@value #CATALOGUE} catalogue: each setting from its init-param, then the system property or
 * environment variable its entry names, parsed strictly (plan item ST-5).
 */
public final class FederationConfiguration {

    /**
     * Which subjects the resolve endpoint will resolve for an unauthenticated caller. OpenID Federation 1.0
     * §18.1: without client authentication "the resolve endpoint should only respond ... with cached
     * information about Entities that have already been evaluated", because each request would otherwise
     * send this deployment fetching wherever the subject's hints point.
     */
    public enum ResolveDiscovery {
        /** This entity, its configured subordinates and the entities it hosts. The default. */
        KNOWN,
        /** Any subject: discovery on demand, bounded only by the validator's fetch budget. */
        ANY
    }

    static final List<String> DEFAULT_CLIENT_REGISTRATION_TYPES = List.of("automatic", "explicit");

    /** The settings catalogue this class reads ({@code META-INF/oidf-settings/federation-entity.json}). */
    public static final String CATALOGUE = "federation-entity";
    static final String TRUST_ANCHORS = "OIDF_FEDERATION_TRUST_ANCHORS";
    static final String SUBORDINATES = "OIDF_FEDERATION_SUBORDINATES";
    static final String SIGNING_ALG = "OIDF_FEDERATION_SIGNING_ALG";
    static final String ORGANIZATION_NAME = "OIDF_FEDERATION_ORGANIZATION_NAME";
    static final String CLIENT_REGISTRATION_TYPES = "OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES";
    static final String RESOLVE_DISCOVERY = "OIDF_FEDERATION_RESOLVE_DISCOVERY";
    static final String ATTESTER_JWKS = "OIDF_FEDERATION_ATTESTER_JWKS";
    /**
     * Whether federation fetches skip certificate checks: one Setting for every reader - this servlet (which also reads
     * its init-param {@code ignoreSslErrors}, first), and {@code FederationRuntimeConfig} in pf-integration for
     * registration, the OGNL criteria and attestation - so the two can no longer disagree (F-0197).
     */
    public static final String IGNORE_SSL_ERRORS = "OIDF_FEDERATION_IGNORE_SSL_ERRORS";
    /** What {@link #CLIENT_REGISTRATION_TYPES} says to advertise neither type. */
    static final String NO_REGISTRATION_TYPES = "none";

    private final List<String> trustAnchorIssuers;
    private final List<String> subordinates;
    private final boolean ignoreSslErrors;
    private final boolean corsEnabled;
    private final String corsAllowOrigin;
    private final String corsAllowMethods;
    private final String corsAllowHeaders;
    private final int corsMaxAge;
    private final String signingAlgorithm;
    private final AttestationMetadataConfig attestationMetadata;
    private final String attesterJwks;
    private final String organizationName;
    private final List<String> clientRegistrationTypes;
    private final ResolveDiscovery resolveDiscovery;

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, boolean ignoreSslErrors, boolean corsEnabled,
                            String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge, String signingAlgorithm,
                            AttestationMetadataConfig attestationMetadata) {
        this(trustAnchorIssuers, subordinates, ignoreSslErrors, corsEnabled, corsAllowOrigin, corsAllowMethods, corsAllowHeaders, corsMaxAge,
                signingAlgorithm, attestationMetadata, null);
    }

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, boolean ignoreSslErrors, boolean corsEnabled,
                            String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge, String signingAlgorithm,
                            AttestationMetadataConfig attestationMetadata, String attesterJwks) {
        this(trustAnchorIssuers, subordinates, ignoreSslErrors, corsEnabled, corsAllowOrigin, corsAllowMethods, corsAllowHeaders, corsMaxAge,
                signingAlgorithm, attestationMetadata, attesterJwks, null, DEFAULT_CLIENT_REGISTRATION_TYPES, ResolveDiscovery.KNOWN);
    }

    FederationConfiguration(List<String> trustAnchorIssuers, List<String> subordinates, boolean ignoreSslErrors,
                            boolean corsEnabled, String corsAllowOrigin, String corsAllowMethods, String corsAllowHeaders, int corsMaxAge,
                            String signingAlgorithm, AttestationMetadataConfig attestationMetadata, String attesterJwks,
                            String organizationName, List<String> clientRegistrationTypes, ResolveDiscovery resolveDiscovery) {
        this.trustAnchorIssuers = List.copyOf(trustAnchorIssuers);
        this.subordinates = List.copyOf(subordinates);
        this.ignoreSslErrors = ignoreSslErrors;
        this.corsEnabled = corsEnabled;
        this.corsAllowOrigin = corsAllowOrigin;
        this.corsAllowMethods = corsAllowMethods;
        this.corsAllowHeaders = corsAllowHeaders;
        this.corsMaxAge = corsMaxAge;
        this.signingAlgorithm = signingAlgorithm;
        this.attestationMetadata = attestationMetadata != null ? attestationMetadata : AttestationMetadataConfig.defaults();
        this.attesterJwks = attesterJwks == null || attesterJwks.isBlank() ? null : publicKeySet(attesterJwks);
        this.organizationName = organizationName == null || organizationName.isBlank() ? null : organizationName.trim();
        this.clientRegistrationTypes = List.copyOf(clientRegistrationTypes);
        this.resolveDiscovery = resolveDiscovery;
    }

    /**
     * The federation entity's settings read from {@code sources}, through this module's catalogue ({@value #CATALOGUE}):
     * each entry's own sources in its own order - for this servlet the init-param first, then the system property or
     * the environment the entry names - its superseded names, and its strict parser (plan item ST-5).
     */
    public static Settings settings(Sources sources) {
        return Settings.load(FederationConfiguration.class.getClassLoader(), CATALOGUE).with(sources);
    }

    /**
     * {@link #IGNORE_SSL_ERRORS} as every reader reads it, from {@code sources} (F-0197): a reader without init-params
     * passes sources without them and gets the system property, the environment and the superseded name, in that order.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused when it is not {@code true} or {@code false}
     */
    public static boolean ignoreSslErrors(Sources sources) {
        Settings settings = settings(sources);
        return settings.bool(IGNORE_SSL_ERRORS);
    }

    /** This servlet's configuration, from its init-params, this process's system properties and its environment. */
    public static FederationConfiguration fromServletConfig(ServletConfig config) {
        java.util.function.Function<String, String> initParams = config == null ? name -> null : config::getInitParameter;
        return from(Sources.process().withInitParams(initParams));
    }

    /**
     * The configuration {@code sources} give, every value parsed strictly: a value its entry refuses stops the servlet
     * starting (FAILED_CONFIG on FEDERATION), naming the setting.
     *
     * @throws IllegalArgumentException wrapping the refusal, "Invalid federation servlet configuration"
     */
    static FederationConfiguration from(Sources sources) {
        try {
            Settings settings = settings(sources);
            List<String> trustAnchorIssuers = trustAnchors(settings);
            List<String> subordinates = list(settings.words(SUBORDINATES));
            String signingAlgorithm = settings.choice(SIGNING_ALG);
            boolean ignoreSslErrors = settings.bool(IGNORE_SSL_ERRORS);
            boolean corsEnabled = settings.bool("corsEnabled");
            String corsAllowOrigin = settings.string("corsAllowOrigin");
            String corsAllowMethods = settings.string("corsAllowMethods");
            String corsAllowHeaders = settings.string("corsAllowHeaders");
            int corsMaxAge = settings.integer("corsMaxAge");
            AttestationMetadataConfig attestationMetadata = AttestationMetadataConfig.from(settings);
            Map<String, Object> attester = settings.jsonObject(ATTESTER_JWKS);
            String attesterJwks = attester == null ? null : org.jose4j.json.JsonUtil.toJson(attester);
            String organizationName = settings.string(ORGANIZATION_NAME);
            List<String> clientRegistrationTypes = registrationTypes(settings.words(CLIENT_REGISTRATION_TYPES));
            ResolveDiscovery resolveDiscovery = ResolveDiscovery.valueOf(settings.choice(RESOLVE_DISCOVERY).toUpperCase(java.util.Locale.ROOT));
            return new FederationConfiguration(trustAnchorIssuers, subordinates, ignoreSslErrors, corsEnabled, corsAllowOrigin,
                    corsAllowMethods, corsAllowHeaders, corsMaxAge, signingAlgorithm, attestationMetadata, attesterJwks, organizationName,
                    clientRegistrationTypes, resolveDiscovery);
        }
        catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid federation servlet configuration", e);
        }
    }

    /**
     * {@link #TRUST_ANCHORS}, each one an Entity Identifier (OpenID Federation 1.0 §1.2): an https URL with a host and no
     * query, fragment or user info. One that is not stops the servlet starting, naming it (H-FED-8, F-0050), since an
     * anchor that is not an identifier is never matched and the entity would publish an {@code authority_hints} no
     * peer can follow.
     */
    private static List<String> trustAnchors(Settings settings) {
        List<String> anchors = list(settings.words(TRUST_ANCHORS));
        if (anchors.isEmpty()) {
            throw new SettingRefused(TRUST_ANCHORS, TRUST_ANCHORS + " is unset: the federation servlet needs at least one trust anchor"
                    + " issuer (it is published as this entity's authority_hints)");
        }
        for (String anchor : anchors) {
            try {
                EntityId.normalize(anchor);
            } catch (IllegalArgumentException e) {
                throw new SettingRefused(TRUST_ANCHORS, TRUST_ANCHORS + " names " + anchor + ", which is not an Entity Identifier"
                        + " (OpenID Federation 1.0 §1.2): " + e.getMessage());
            }
        }
        return anchors;
    }

    /** {@link #CLIENT_REGISTRATION_TYPES}: the words as given, or none for {@value #NO_REGISTRATION_TYPES} alone. */
    private static List<String> registrationTypes(java.util.Set<String> words) {
        if (!words.contains(NO_REGISTRATION_TYPES)) {
            return List.copyOf(words);
        }
        if (words.size() > 1) {
            throw new SettingRefused(CLIENT_REGISTRATION_TYPES, CLIENT_REGISTRATION_TYPES + " lists " + NO_REGISTRATION_TYPES
                    + " beside another type; " + NO_REGISTRATION_TYPES + " stands alone");
        }
        return List.of();
    }

    private static List<String> list(java.util.Set<String> words) {
        return words == null ? List.of() : List.copyOf(words);
    }

    List<String> authorityHints() {
        return this.trustAnchorIssuers;
    }

    /**
     * Whether {@code issuer} is one of the configured anchors: the same Entity Identifier as one of them
     * ({@link EntityId#same}, a trailing slash aside), with the scheme and host compared in any case (RFC 3986 §3.2.2:
     * "The host subcomponent is case-insensitive"; §3.1 for the scheme). An anchor is validated when it is read, so only
     * {@code issuer} can fail to parse, and then it is compared as it stands.
     */
    boolean isTrustAnchor(String issuer) {
        if (issuer == null) {
            return false;
        }
        String candidate = hostInLowerCase(issuer);
        for (String configured : this.trustAnchorIssuers) {
            if (EntityId.same(hostInLowerCase(configured), candidate)) {
                return true;
            }
        }
        return false;
    }

    /** {@code id} with its scheme and host in lower case, the rest as it is; {@code id} unchanged when it does not parse. */
    static String hostInLowerCase(String id) {
        String trimmed = id.trim();
        try {
            java.net.URI uri = new java.net.URI(trimmed);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme == null || host == null) {
                return trimmed;
            }
            int hostAt = trimmed.indexOf(host, scheme.length());
            return scheme.toLowerCase(java.util.Locale.ROOT) + trimmed.substring(scheme.length(), hostAt)
                    + host.toLowerCase(java.util.Locale.ROOT) + trimmed.substring(hostAt + host.length());
        } catch (java.net.URISyntaxException e) {
            return trimmed;
        }
    }

    List<String> subordinates() {
        return this.subordinates;
    }

    public String signingAlgorithm() {
        return this.signingAlgorithm;
    }

    /**
     * The co-hosted attester's key set, which this entity's configuration publishes as it stands: a JSON object whose
     * {@code keys} are public, asymmetric keys. A private or symmetric key here would be handed to anyone who asks.
     *
     * @throws IllegalArgumentException for anything else, naming what is wrong but never the key material
     */
    static String publicKeySet(String jwks) {
        Object parsed;
        try {
            parsed = org.jose4j.json.JsonUtil.parseJson(jwks);
        } catch (Exception e) {
            throw new IllegalArgumentException("attesterJwks is not a JSON object");
        }
        if (!(parsed instanceof Map<?, ?> set) || !(set.get("keys") instanceof List<?> keys)) {
            throw new IllegalArgumentException("attesterJwks is not a JWK Set: expected {\"keys\": [...]}");
        }
        for (Object key : keys) {
            if (!(key instanceof Map<?, ?> jwk)) {
                throw new IllegalArgumentException("attesterJwks holds something other than a JWK");
            }
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> typed = (Map<String, Object>) jwk;
                Jwks.assertPublicOnly(typed);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("attesterJwks would publish a key that is not public: " + e.getMessage());
            }
        }
        return jwks;
    }

    String attesterJwks() {
        return this.attesterJwks;
    }

    AttestationMetadataConfig attestationMetadata() {
        return this.attestationMetadata;
    }

    /** {@code organization_name} for the entity's {@code federation_entity} metadata (§5.1.1 RECOMMENDED), or null. */
    public String organizationName() {
        return this.organizationName;
    }

    /**
     * {@code client_registration_types_supported} (§5.1.3): what this OP accepts - {@code automatic},
     * {@code explicit}, both, or none. An empty list advertises neither and omits the registration endpoint.
     */
    public List<String> clientRegistrationTypes() {
        return this.clientRegistrationTypes;
    }

    public ResolveDiscovery resolveDiscovery() {
        return this.resolveDiscovery;
    }

    /** True when {@code entityId} is one of the configured subordinates, trailing slash aside. */
    boolean isSubordinate(String entityId) {
        for (String subordinate : this.subordinates) {
            if (EntityId.same(subordinate, entityId)) {
                return true;
            }
        }
        return false;
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

