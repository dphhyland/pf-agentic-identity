/*
 * Verification policy for attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.common;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Immutable verification policy for {@link ClientAttestationVerifier}: which signing algorithms are
 * accepted for the attestation, PoP and DPoP JWTs; the clock-skew and freshness windows; the expected
 * PoP audiences and DPoP {@code htm}/{@code htu}; and whether a server-issued challenge is mandatory.
 * Built via {@link #builder()}.
 */
public final class ClientAttestationConfig {
    /** Asymmetric signature algorithms accepted by default (no {@code none}, no MACs). */
    public static final Set<String> DEFAULT_ASYMMETRIC_ALGORITHMS = Set.of(
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA");
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;
    public static final long DEFAULT_POP_MAX_AGE_SECONDS = 300L;
    public static final long DEFAULT_DPOP_MAX_AGE_SECONDS = 300L;
    public static final String DEFAULT_HTTP_METHOD = "POST";

    private final Set<String> attestationAlgorithms;
    private final Set<String> popAlgorithms;
    private final Set<String> dpopAlgorithms;
    private final int allowedClockSkewSeconds;
    private final long popMaxAgeSeconds;
    private final long dpopMaxAgeSeconds;
    private final Set<String> acceptedAudiences;
    private final String expectedHtu;
    private final String expectedHtm;
    private final boolean challengeRequired;
    private final boolean acceptSdJwt;
    private final boolean requireSdJwt;
    private final Set<String> requiredDisclosedClaims;

    private ClientAttestationConfig(Builder b) {
        this.attestationAlgorithms = Set.copyOf(b.attestationAlgorithms);
        this.popAlgorithms = Set.copyOf(b.popAlgorithms);
        this.dpopAlgorithms = Set.copyOf(b.dpopAlgorithms);
        this.allowedClockSkewSeconds = b.allowedClockSkewSeconds;
        this.popMaxAgeSeconds = b.popMaxAgeSeconds;
        this.dpopMaxAgeSeconds = b.dpopMaxAgeSeconds;
        this.acceptedAudiences = Set.copyOf(b.acceptedAudiences);
        this.expectedHtu = b.expectedHtu;
        this.expectedHtm = b.expectedHtm;
        this.challengeRequired = b.challengeRequired;
        this.acceptSdJwt = b.acceptSdJwt;
        this.requireSdJwt = b.requireSdJwt;
        this.requiredDisclosedClaims = Set.copyOf(b.requiredDisclosedClaims);
    }

    public static Builder builder() {
        return new Builder();
    }

    public Set<String> attestationAlgorithms() {
        return this.attestationAlgorithms;
    }

    public Set<String> popAlgorithms() {
        return this.popAlgorithms;
    }

    public Set<String> dpopAlgorithms() {
        return this.dpopAlgorithms;
    }

    public int allowedClockSkewSeconds() {
        return this.allowedClockSkewSeconds;
    }

    public long popMaxAgeSeconds() {
        return this.popMaxAgeSeconds;
    }

    public long dpopMaxAgeSeconds() {
        return this.dpopMaxAgeSeconds;
    }

    public Set<String> acceptedAudiences() {
        return this.acceptedAudiences;
    }

    public String expectedHtu() {
        return this.expectedHtu;
    }

    public String expectedHtm() {
        return this.expectedHtm;
    }

    public boolean challengeRequired() {
        return this.challengeRequired;
    }

    /** Whether an SD-JWT-encoded attestation presentation is accepted (default {@code true}). */
    public boolean acceptSdJwt() {
        return this.acceptSdJwt;
    }

    /** Whether a plain-JWT attestation is rejected in favour of SD-JWT (default {@code false}). */
    public boolean requireSdJwt() {
        return this.requireSdJwt;
    }

    /**
     * Top-level attestation claims this AS requires to be DISCLOSED (present and non-empty), even under
     * SD-JWT selective disclosure — e.g. {@code "workload"} or {@code "authorization_details"}. Empty =
     * no requirement (default). The AS side of federation-gated disclosure: the AS declares what it needs
     * and rejects a presentation that withholds it.
     */
    public Set<String> requiredDisclosedClaims() {
        return this.requiredDisclosedClaims;
    }

    public static final class Builder {
        private Set<String> attestationAlgorithms = new LinkedHashSet<>(DEFAULT_ASYMMETRIC_ALGORITHMS);
        private Set<String> popAlgorithms = new LinkedHashSet<>(DEFAULT_ASYMMETRIC_ALGORITHMS);
        private Set<String> dpopAlgorithms = new LinkedHashSet<>(DEFAULT_ASYMMETRIC_ALGORITHMS);
        private int allowedClockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
        private long popMaxAgeSeconds = DEFAULT_POP_MAX_AGE_SECONDS;
        private long dpopMaxAgeSeconds = DEFAULT_DPOP_MAX_AGE_SECONDS;
        private Set<String> acceptedAudiences = new LinkedHashSet<>();
        private String expectedHtu;
        private String expectedHtm = DEFAULT_HTTP_METHOD;
        private boolean challengeRequired;
        private boolean acceptSdJwt = true;
        private boolean requireSdJwt;
        private Set<String> requiredDisclosedClaims = new LinkedHashSet<>();

        private Builder() {
        }

        public Builder attestationAlgorithms(Set<String> algs) {
            if (algs != null && !algs.isEmpty()) {
                this.attestationAlgorithms = new LinkedHashSet<>(algs);
            }
            return this;
        }

        public Builder popAlgorithms(Set<String> algs) {
            if (algs != null && !algs.isEmpty()) {
                this.popAlgorithms = new LinkedHashSet<>(algs);
            }
            return this;
        }

        public Builder dpopAlgorithms(Set<String> algs) {
            if (algs != null && !algs.isEmpty()) {
                this.dpopAlgorithms = new LinkedHashSet<>(algs);
            }
            return this;
        }

        public Builder allowedClockSkewSeconds(int seconds) {
            this.allowedClockSkewSeconds = Math.max(0, seconds);
            return this;
        }

        public Builder popMaxAgeSeconds(long seconds) {
            this.popMaxAgeSeconds = seconds;
            return this;
        }

        public Builder dpopMaxAgeSeconds(long seconds) {
            this.dpopMaxAgeSeconds = seconds;
            return this;
        }

        public Builder acceptedAudiences(Set<String> audiences) {
            if (audiences != null) {
                this.acceptedAudiences = new LinkedHashSet<>(audiences);
            }
            return this;
        }

        public Builder addAcceptedAudience(String audience) {
            if (audience != null && !audience.isBlank()) {
                this.acceptedAudiences.add(audience);
            }
            return this;
        }

        public Builder expectedHtu(String htu) {
            this.expectedHtu = htu;
            return this;
        }

        public Builder expectedHtm(String htm) {
            if (htm != null && !htm.isBlank()) {
                this.expectedHtm = htm;
            }
            return this;
        }

        public Builder challengeRequired(boolean required) {
            this.challengeRequired = required;
            return this;
        }

        public Builder acceptSdJwt(boolean accept) {
            this.acceptSdJwt = accept;
            return this;
        }

        public Builder requireSdJwt(boolean required) {
            this.requireSdJwt = required;
            if (required) {
                this.acceptSdJwt = true;
            }
            return this;
        }

        public Builder requiredDisclosedClaims(Set<String> claims) {
            if (claims != null) {
                this.requiredDisclosedClaims = new LinkedHashSet<>(claims);
            }
            return this;
        }

        public ClientAttestationConfig build() {
            return new ClientAttestationConfig(this);
        }
    }
}
