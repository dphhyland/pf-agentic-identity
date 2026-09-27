/*
 * Configuration for calling the PingAuthorize governance-engine decision API.
 */
package com.pingidentity.ps.oidf.rar;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Immutable settings for the {@link GovernanceEngineClient} / {@link GovernanceEngineRequestBuilder}.
 *
 * <p>Mirrors the field set of the reference {@code RARAuthDetailsProcessor} (PDP URL, domain/service/action,
 * attribute prefix, shared-secret header) and adds the enforcement knobs the reference lacked:
 * {@code failOpenOnError} (fail open when the PDP is unreachable, and only then), the types that need an
 * authenticated principal, and {@code insecureTls} (a scoped dev flag instead of an always-on trust-all
 * manager). The decision is always deny-unless-PERMIT; the switch that once turned that off is gone.
 */
public final class GovernanceEngineConfig {

    /** The deployment profile that relaxes the development-only rules. Anything else is production. */
    public static final String PROFILE_DEVELOPMENT = "development";
    public static final String PROFILE_PRODUCTION = "production";

    /**
     * The detail types that need an authenticated principal before the PDP is asked: a payment or an
     * account query decided about a client, or about nobody, is a decision about the wrong party.
     */
    public static final Set<String> DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES =
            Collections.unmodifiableSet(new LinkedHashSet<>(Arrays.asList("payment_initiation", "account_information")));

    private final String pdpUrl;
    private final String domainPrefix;
    private final String service;
    private final String action;
    private final String attributePrefix;
    private final boolean prefixAttributesWithType;
    private final String secretHeader;
    private final String secret;
    private final boolean failOpenOnError;
    private final boolean allowClientAssertedPrincipal;
    private final boolean trustAgentMarker;
    private final boolean insecureTls;
    private final int timeoutMillis;
    private final Set<String> authenticatedPrincipalTypes;
    private final String deploymentProfile;

    private GovernanceEngineConfig(Builder b) {
        this.pdpUrl = b.pdpUrl;
        this.domainPrefix = b.domainPrefix;
        this.service = b.service;
        this.action = b.action;
        this.attributePrefix = b.attributePrefix;
        this.prefixAttributesWithType = b.prefixAttributesWithType;
        this.secretHeader = b.secretHeader;
        this.secret = b.secret;
        this.failOpenOnError = b.failOpenOnError;
        this.allowClientAssertedPrincipal = b.allowClientAssertedPrincipal;
        this.trustAgentMarker = b.trustAgentMarker;
        this.insecureTls = b.insecureTls;
        this.timeoutMillis = b.timeoutMillis;
        this.authenticatedPrincipalTypes = b.authenticatedPrincipalTypes;
        this.deploymentProfile = b.deploymentProfile;
    }

    public String getPdpUrl() { return pdpUrl; }
    public String getDomainPrefix() { return domainPrefix; }
    public String getService() { return service; }
    public String getAction() { return action; }
    public String getAttributePrefix() { return attributePrefix; }
    public boolean isPrefixAttributesWithType() { return prefixAttributesWithType; }
    public String getSecretHeader() { return secretHeader; }
    public String getSecret() { return secret; }

    /**
     * Whether an unreachable PDP grants the request as asked. Only a transport failure counts as
     * unreachable ({@link PdpUnavailableException}); a PDP that answers, and answers badly, is refused
     * whatever this says. Default false.
     */
    public boolean isFailOpenOnError() { return failOpenOnError; }

    /**
     * Whether a principal the CALLER asserted may be used as the decision subject: the {@code login_hint}
     * request parameter and the {@code _principal_sub} marker inside {@code authorization_details}. Both are
     * simply what the caller sent, so this is a development-only escape hatch: it takes effect only under
     * {@link #PROFILE_DEVELOPMENT} ({@link #isClientAssertedPrincipalHonoured()}) and goes at 1.0. Default
     * false.
     */
    public boolean isAllowClientAssertedPrincipal() { return allowClientAssertedPrincipal; }
    public boolean isTrustAgentMarker() { return trustAgentMarker; }
    public boolean isInsecureTls() { return insecureTls; }
    public int getTimeoutMillis() { return timeoutMillis; }

    /** The detail types refused before any PDP call unless the principal is a person PingFederate knows. */
    public Set<String> getAuthenticatedPrincipalTypes() { return authenticatedPrincipalTypes; }

    /** {@code OIDF_DEPLOYMENT_PROFILE} as read at configure time; unset reads as production. */
    public String getDeploymentProfile() { return deploymentProfile; }

    public boolean isDevelopment() { return PROFILE_DEVELOPMENT.equals(deploymentProfile); }

    /** The switch, AND the profile that lets it mean anything. */
    public boolean isClientAssertedPrincipalHonoured() { return allowClientAssertedPrincipal && isDevelopment(); }

    public static Builder builder() { return new Builder(); }

    /**
     * The profile a value of {@code OIDF_DEPLOYMENT_PROFILE} names: {@code development} for exactly that
     * (trimmed, any case), production for anything else including unset. There is no third profile here;
     * PR-1 (the platform library) centralises the profile and its parsing, and this plugin will read it from
     * there.
     */
    public static String profileOf(String value) {
        return value != null && value.trim().equalsIgnoreCase(PROFILE_DEVELOPMENT) ? PROFILE_DEVELOPMENT : PROFILE_PRODUCTION;
    }

    /**
     * The type list a field holds: comma- or whitespace-separated, blanks dropped, order kept. A null or
     * blank field is the default list; a field that names no type at all after trimming is an empty set,
     * which an operator writes deliberately as a single {@code -}.
     */
    public static Set<String> authenticatedPrincipalTypesOf(String field) {
        if (field == null || field.isBlank()) {
            return DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES;
        }
        Set<String> types = new LinkedHashSet<>();
        for (String type : field.split("[,\\s]+")) {
            if (!type.isBlank() && !"-".equals(type)) {
                types.add(type.trim());
            }
        }
        return Collections.unmodifiableSet(types);
    }

    /** Mutable builder with sensible defaults matching the reference plugin's conventions. */
    public static final class Builder {
        private String pdpUrl;
        private String domainPrefix = "";
        private String service = "Authorization";
        private String action = "authorize";
        private String attributePrefix = "";
        private boolean prefixAttributesWithType = true;
        private String secretHeader = "CLIENT-TOKEN";
        private String secret;
        private boolean failOpenOnError = false;
        private boolean allowClientAssertedPrincipal = false;
        private boolean trustAgentMarker = false;
        private boolean insecureTls = false;
        private int timeoutMillis = 10_000;
        private Set<String> authenticatedPrincipalTypes = DEFAULT_AUTHENTICATED_PRINCIPAL_TYPES;
        private String deploymentProfile = PROFILE_PRODUCTION;

        public Builder pdpUrl(String v) { this.pdpUrl = v; return this; }
        public Builder domainPrefix(String v) { if (v != null) this.domainPrefix = v; return this; }
        public Builder service(String v) { if (v != null && !v.isBlank()) this.service = v; return this; }
        public Builder action(String v) { if (v != null && !v.isBlank()) this.action = v; return this; }
        public Builder attributePrefix(String v) { if (v != null) this.attributePrefix = v; return this; }
        public Builder prefixAttributesWithType(boolean v) { this.prefixAttributesWithType = v; return this; }
        public Builder secretHeader(String v) { if (v != null && !v.isBlank()) this.secretHeader = v; return this; }
        public Builder secret(String v) { this.secret = v; return this; }
        public Builder failOpenOnError(boolean v) { this.failOpenOnError = v; return this; }
        public Builder allowClientAssertedPrincipal(boolean v) { this.allowClientAssertedPrincipal = v; return this; }
        public Builder trustAgentMarker(boolean v) { this.trustAgentMarker = v; return this; }
        public Builder insecureTls(boolean v) { this.insecureTls = v; return this; }
        public Builder timeoutMillis(int v) { if (v > 0) this.timeoutMillis = v; return this; }
        public Builder authenticatedPrincipalTypes(Set<String> v) {
            if (v != null) this.authenticatedPrincipalTypes = Collections.unmodifiableSet(new LinkedHashSet<>(v));
            return this;
        }
        public Builder deploymentProfile(String v) { this.deploymentProfile = profileOf(v); return this; }

        public GovernanceEngineConfig build() {
            if (pdpUrl == null || pdpUrl.isBlank()) {
                throw new IllegalStateException("pdpUrl is required");
            }
            return new GovernanceEngineConfig(this);
        }
    }
}
