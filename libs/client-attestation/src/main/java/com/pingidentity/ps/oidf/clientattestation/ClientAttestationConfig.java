/*
 * Verification policy for attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Immutable verification policy for {@link ClientAttestationVerifier}: which signing algorithms are
 * accepted for the attestation, PoP and DPoP JWTs; the clock-skew and freshness windows; the one PoP
 * audience this server answers to and the DPoP {@code htm}/{@code htu}; and whether a server-issued
 * challenge is mandatory. Built via {@link #builder()}.
 */
public final class ClientAttestationConfig {
    /** Asymmetric signature algorithms accepted by default (no {@code none}, no MACs). */
    public static final Set<String> DEFAULT_ASYMMETRIC_ALGORITHMS = Set.of(
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA");
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;
    public static final long DEFAULT_POP_MAX_AGE_SECONDS = 300L;
    public static final long DEFAULT_DPOP_MAX_AGE_SECONDS = 300L;
    public static final String DEFAULT_HTTP_METHOD = "POST";
    /** Sentinel for {@link #maxAttestationLifetimeSeconds()}: no ceiling on {@code exp - iat}. */
    public static final long NO_MAX_ATTESTATION_LIFETIME = 0L;

    private final Set<String> attestationAlgorithms;
    private final Set<String> popAlgorithms;
    private final Set<String> dpopAlgorithms;
    private final int allowedClockSkewSeconds;
    private final long popMaxAgeSeconds;
    private final long dpopMaxAgeSeconds;
    private final String expectedAudience;
    private final String expectedHtu;
    private final String expectedHtm;
    private final boolean challengeRequired;
    private final Set<String> requiredDisclosedClaims;
    private final long maxAttestationLifetimeSeconds;

    private ClientAttestationConfig(Builder b) {
        this.attestationAlgorithms = Set.copyOf(b.attestationAlgorithms);
        this.popAlgorithms = Set.copyOf(b.popAlgorithms);
        this.dpopAlgorithms = Set.copyOf(b.dpopAlgorithms);
        this.allowedClockSkewSeconds = b.allowedClockSkewSeconds;
        this.popMaxAgeSeconds = b.popMaxAgeSeconds;
        this.dpopMaxAgeSeconds = b.dpopMaxAgeSeconds;
        this.expectedAudience = b.expectedAudience;
        this.expectedHtu = b.expectedHtu;
        this.expectedHtm = b.expectedHtm;
        this.challengeRequired = b.challengeRequired;
        this.requiredDisclosedClaims = Set.copyOf(b.requiredDisclosedClaims);
        this.maxAttestationLifetimeSeconds = b.maxAttestationLifetimeSeconds;
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

    /**
     * The identifier of the server doing the verifying, which a Client Attestation PoP JWT must carry as its
     * only {@code aud}: an authorization server's RFC 8414 issuer identifier, or a resource server's RFC 9728
     * resource identifier. draft-ietf-oauth-attestation-based-client-auth-10 §5.1: "When the JWT is presented
     * to an Authorization Server, the [RFC8414] issuer identifier URL of the Authorization Server MUST be
     * used. [...] A Client Attestation PoP JWT is intended for a single audience, Clients MUST generate JWTs
     * for each target." One value, not a set: a server that also accepted, say, its token endpoint URL would
     * accept a PoP minted for another server that happens to share that URL's shape. {@code null} when
     * unset, and then PoP mode is refused as a misconfiguration rather than checked against nothing.
     */
    public String expectedAudience() {
        return this.expectedAudience;
    }

    /**
     * The URL of the endpoint the proof is presented to, which a DPoP proof's {@code htu} must name (RFC 9449
     * §4.3, item 9). It comes from this server's configuration - for PingFederate, the endpoint URL it
     * advertises for its issuer - and never from the request's {@code Host} header, {@code X-Forwarded-*} or
     * the request URL a servlet container rebuilds from them: those are the caller's to write, and a proof
     * minted for another server would otherwise pass with a {@code Host} header naming that server.
     */
    public String expectedHtu() {
        return this.expectedHtu;
    }

    public String expectedHtm() {
        return this.expectedHtm;
    }

    public boolean challengeRequired() {
        return this.challengeRequired;
    }

    /**
     * Top-level attestation claims this AS requires (present and non-empty) — e.g. {@code "workload"} or
     * {@code "authorization_details"}. Empty = no requirement (default). The AS declares what it needs
     * and rejects an attestation minted without it.
     */
    public Set<String> requiredDisclosedClaims() {
        return this.requiredDisclosedClaims;
    }

    /**
     * Ceiling on an attestation's own lifetime ({@code exp - iat}), in seconds, or
     * {@link #NO_MAX_ATTESTATION_LIFETIME} to accept whatever the attester minted (the default).
     * Distinct from {@code exp}, which is always enforced: this bounds how long a *stale posture* may
     * be presented as current, which an unexpired long-lived attestation otherwise does not.
     *
     * <p>When set, an attestation carrying no {@code iat} is rejected rather than exempted - the
     * ceiling cannot be evaluated without one, and skipping it would let an attester opt out of the
     * policy by omitting a claim.
     */
    public long maxAttestationLifetimeSeconds() {
        return this.maxAttestationLifetimeSeconds;
    }

    public static final class Builder {
        private Set<String> attestationAlgorithms = new LinkedHashSet<>(DEFAULT_ASYMMETRIC_ALGORITHMS);
        private Set<String> popAlgorithms = new LinkedHashSet<>(DEFAULT_ASYMMETRIC_ALGORITHMS);
        private Set<String> dpopAlgorithms = new LinkedHashSet<>(DEFAULT_ASYMMETRIC_ALGORITHMS);
        private int allowedClockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
        private long popMaxAgeSeconds = DEFAULT_POP_MAX_AGE_SECONDS;
        private long dpopMaxAgeSeconds = DEFAULT_DPOP_MAX_AGE_SECONDS;
        private String expectedAudience;
        private String expectedHtu;
        private String expectedHtm = DEFAULT_HTTP_METHOD;
        private boolean challengeRequired;
        private Set<String> requiredDisclosedClaims = new LinkedHashSet<>();
        private long maxAttestationLifetimeSeconds = NO_MAX_ATTESTATION_LIFETIME;

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

        /**
         * Sets the one PoP audience this server answers to (see {@link ClientAttestationConfig#expectedAudience()});
         * a blank value is treated as unset. This replaced a set of accepted audiences in 0.4.0.
         */
        public Builder expectedAudience(String audience) {
            this.expectedAudience = audience == null || audience.isBlank() ? null : audience;
            return this;
        }

        /** Sets the endpoint URL a DPoP proof's {@code htu} must name (see {@link ClientAttestationConfig#expectedHtu()}). */
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

        public Builder requiredDisclosedClaims(Set<String> claims) {
            if (claims != null) {
                this.requiredDisclosedClaims = new LinkedHashSet<>(claims);
            }
            return this;
        }

        /**
         * Sets the {@code exp - iat} ceiling in seconds; {@code 0} or less disables it (the default).
         */
        public Builder maxAttestationLifetimeSeconds(long seconds) {
            this.maxAttestationLifetimeSeconds = Math.max(NO_MAX_ATTESTATION_LIFETIME, seconds);
            return this;
        }

        public ClientAttestationConfig build() {
            return new ClientAttestationConfig(this);
        }
    }
}
