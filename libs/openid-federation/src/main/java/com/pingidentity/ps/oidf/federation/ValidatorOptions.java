/*
 * The limits and choices a trust chain validator runs with.
 */
package com.pingidentity.ps.oidf.federation;

import java.time.Clock;

/**
 * How a {@link TrustChainValidator} bounds its work and reads the places where OpenID Federation 1.0 leaves
 * a choice.
 *
 * @param maxFetches                 live fetches one validation may make, across every anchor it tries and
 *                                   any peer chain (§18.1 - a caller-supplied chain names the URLs)
 * @param maxAuthorityHints          how many {@code authority_hints} of one Entity Configuration are
 *                                   followed, after the configured anchors are moved to the front (§18.1)
 * @param clockSkewSeconds           leeway for {@code iat} and {@code exp} (§3.2 "some small leeway")
 * @param clock                      the clock time claims are evaluated against
 * @param requirePeerChainSameAnchor refuse a {@code peer_trust_chain} ending at a different anchor. §4.4
 *                                   says the two SHOULD be the same; this treats it as a MUST by default
 * @param maxRouteAttempts           how many routes that reach an anchor are validated in full before the
 *                                   first one's failure is reported. Presented statements cost no fetch, so
 *                                   without this a caller could hand over a lattice whose many paths each
 *                                   cost a round of signature checks
 */
public record ValidatorOptions(int maxFetches, int maxAuthorityHints, int clockSkewSeconds, Clock clock,
                               boolean requirePeerChainSameAnchor, int maxRouteAttempts) {

    public static final int DEFAULT_MAX_FETCHES = 24;
    public static final int DEFAULT_MAX_AUTHORITY_HINTS = 10;
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;
    public static final int DEFAULT_MAX_ROUTE_ATTEMPTS = 8;

    public ValidatorOptions {
        if (maxFetches < 1) {
            throw new IllegalArgumentException("maxFetches must be at least 1");
        }
        if (maxAuthorityHints < 1) {
            throw new IllegalArgumentException("maxAuthorityHints must be at least 1");
        }
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException("clockSkewSeconds must not be negative");
        }
        if (maxRouteAttempts < 1) {
            throw new IllegalArgumentException("maxRouteAttempts must be at least 1");
        }
        clock = clock == null ? Clock.systemUTC() : clock;
    }

    public static ValidatorOptions defaults() {
        return new ValidatorOptions(DEFAULT_MAX_FETCHES, DEFAULT_MAX_AUTHORITY_HINTS, DEFAULT_CLOCK_SKEW_SECONDS, null, true,
                DEFAULT_MAX_ROUTE_ATTEMPTS);
    }

    public ValidatorOptions withMaxFetches(int value) {
        return new ValidatorOptions(value, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts);
    }

    public ValidatorOptions withMaxAuthorityHints(int value) {
        return new ValidatorOptions(this.maxFetches, value, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts);
    }

    public ValidatorOptions withClockSkewSeconds(int value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, value, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts);
    }

    public ValidatorOptions withClock(Clock value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, value,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts);
    }

    public ValidatorOptions withRequirePeerChainSameAnchor(boolean value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                value, this.maxRouteAttempts);
    }

    public ValidatorOptions withMaxRouteAttempts(int value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, value);
    }
}
