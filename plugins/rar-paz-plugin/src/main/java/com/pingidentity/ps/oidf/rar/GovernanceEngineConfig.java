/*
 * Configuration for calling the PingAuthorize governance-engine decision API.
 */
package com.pingidentity.ps.oidf.rar;

/**
 * Immutable settings for the {@link GovernanceEngineClient} / {@link GovernanceEngineRequestBuilder}.
 *
 * <p>Mirrors the field set of the reference {@code RARAuthDetailsProcessor} (PDP URL, domain/service/action,
 * attribute prefix, shared-secret header) and adds the enforcement knobs the reference lacked:
 * {@code denyOnNonPermit} (honour the decision, not just enrich), {@code failOpenOnError}, and
 * {@code insecureTls} (a scoped dev flag instead of an always-on trust-all manager).
 */
public final class GovernanceEngineConfig {
    private final String pdpUrl;
    private final String domainPrefix;
    private final String service;
    private final String action;
    private final String attributePrefix;
    private final boolean prefixAttributesWithType;
    private final String secretHeader;
    private final String secret;
    private final boolean denyOnNonPermit;
    private final boolean failOpenOnError;
    private final boolean insecureTls;
    private final int timeoutMillis;

    private GovernanceEngineConfig(Builder b) {
        this.pdpUrl = b.pdpUrl;
        this.domainPrefix = b.domainPrefix;
        this.service = b.service;
        this.action = b.action;
        this.attributePrefix = b.attributePrefix;
        this.prefixAttributesWithType = b.prefixAttributesWithType;
        this.secretHeader = b.secretHeader;
        this.secret = b.secret;
        this.denyOnNonPermit = b.denyOnNonPermit;
        this.failOpenOnError = b.failOpenOnError;
        this.insecureTls = b.insecureTls;
        this.timeoutMillis = b.timeoutMillis;
    }

    public String getPdpUrl() { return pdpUrl; }
    public String getDomainPrefix() { return domainPrefix; }
    public String getService() { return service; }
    public String getAction() { return action; }
    public String getAttributePrefix() { return attributePrefix; }
    public boolean isPrefixAttributesWithType() { return prefixAttributesWithType; }
    public String getSecretHeader() { return secretHeader; }
    public String getSecret() { return secret; }
    public boolean isDenyOnNonPermit() { return denyOnNonPermit; }
    public boolean isFailOpenOnError() { return failOpenOnError; }
    public boolean isInsecureTls() { return insecureTls; }
    public int getTimeoutMillis() { return timeoutMillis; }

    public static Builder builder() { return new Builder(); }

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
        private boolean denyOnNonPermit = true;
        private boolean failOpenOnError = false;
        private boolean insecureTls = false;
        private int timeoutMillis = 10_000;

        public Builder pdpUrl(String v) { this.pdpUrl = v; return this; }
        public Builder domainPrefix(String v) { if (v != null) this.domainPrefix = v; return this; }
        public Builder service(String v) { if (v != null && !v.isBlank()) this.service = v; return this; }
        public Builder action(String v) { if (v != null && !v.isBlank()) this.action = v; return this; }
        public Builder attributePrefix(String v) { if (v != null) this.attributePrefix = v; return this; }
        public Builder prefixAttributesWithType(boolean v) { this.prefixAttributesWithType = v; return this; }
        public Builder secretHeader(String v) { if (v != null && !v.isBlank()) this.secretHeader = v; return this; }
        public Builder secret(String v) { this.secret = v; return this; }
        public Builder denyOnNonPermit(boolean v) { this.denyOnNonPermit = v; return this; }
        public Builder failOpenOnError(boolean v) { this.failOpenOnError = v; return this; }
        public Builder insecureTls(boolean v) { this.insecureTls = v; return this; }
        public Builder timeoutMillis(int v) { if (v > 0) this.timeoutMillis = v; return this; }

        public GovernanceEngineConfig build() {
            if (pdpUrl == null || pdpUrl.isBlank()) {
                throw new IllegalStateException("pdpUrl is required");
            }
            return new GovernanceEngineConfig(this);
        }
    }
}
