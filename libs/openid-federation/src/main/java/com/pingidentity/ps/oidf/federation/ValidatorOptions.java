/*
 * The limits and choices a trust chain validator runs with.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * How a {@link TrustChainValidator} bounds its work and reads the places where OpenID Federation 1.0 leaves
 * a choice.
 *
 * <p>{@link #defaults()} reads the tuning limits from the {@code federation-resolution} settings catalogue
 * (plan item S5b), so every validator built with it follows the operator's settings; each has the default the
 * code had before, but the wall clock, which is new.
 *
 * @param maxFetches                 requests one resolution may spend (see {@link ResolutionBudget}), across every
 *                                   anchor it tries, any peer chain, and the gateway's own requests (§18.1 - a
 *                                   caller-supplied chain names the URLs)
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
 * @param resolutionWallClock        how long one resolution may spend on the network, from when it starts: every
 *                                   request it makes ends by then (see {@link ResolutionBudget})
 */
public record ValidatorOptions(int maxFetches, int maxAuthorityHints, int clockSkewSeconds, Clock clock,
                               boolean requirePeerChainSameAnchor, int maxRouteAttempts, Duration resolutionWallClock) {

    /** The settings catalogue the defaults are read from. */
    public static final String COMPONENT = "federation-resolution";
    public static final String MAX_REQUESTS_SETTING = "OIDF_FEDERATION_RESOLUTION_MAX_REQUESTS";
    public static final String MAX_AUTHORITY_HINTS_SETTING = "OIDF_FEDERATION_RESOLUTION_MAX_AUTHORITY_HINTS";
    public static final String MAX_ROUTE_ATTEMPTS_SETTING = "OIDF_FEDERATION_RESOLUTION_MAX_ROUTE_ATTEMPTS";
    public static final String CLOCK_SKEW_SETTING = "OIDF_FEDERATION_RESOLUTION_CLOCK_SKEW_SECONDS";
    public static final String WALL_CLOCK_SETTING = "OIDF_FEDERATION_RESOLUTION_WALL_CLOCK_SECONDS";

    public static final int DEFAULT_MAX_FETCHES = 24;
    public static final int DEFAULT_MAX_AUTHORITY_HINTS = 10;
    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;
    public static final int DEFAULT_MAX_ROUTE_ATTEMPTS = 8;
    /** The catalogue's default wall clock; the measurement behind it is in the module README. */
    public static final Duration DEFAULT_RESOLUTION_WALL_CLOCK = Duration.ofSeconds(45);

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
        Objects.requireNonNull(resolutionWallClock, "resolutionWallClock");
        if (resolutionWallClock.isNegative() || resolutionWallClock.isZero()) {
            throw new IllegalArgumentException("resolutionWallClock must be positive");
        }
        clock = clock == null ? Clock.systemUTC() : clock;
    }

    /**
     * The limits this process's {@code federation-resolution} settings name, each its catalogued default when unset.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.SettingRefused for a value its setting refuses
     */
    public static ValidatorOptions defaults() {
        return fromSettings(Settings.of(CatalogueHolder.CATALOGUE, Sources.process()));
    }

    /** The limits {@code settings} (a {@code federation-resolution} catalogue's) name. */
    public static ValidatorOptions fromSettings(Settings settings) {
        return new ValidatorOptions(settings.integer(MAX_REQUESTS_SETTING), settings.integer(MAX_AUTHORITY_HINTS_SETTING),
                Math.toIntExact(settings.duration(CLOCK_SKEW_SETTING).toSeconds()), null, true,
                settings.integer(MAX_ROUTE_ATTEMPTS_SETTING), settings.duration(WALL_CLOCK_SETTING));
    }

    public ValidatorOptions withMaxFetches(int value) {
        return new ValidatorOptions(value, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts, this.resolutionWallClock);
    }

    public ValidatorOptions withMaxAuthorityHints(int value) {
        return new ValidatorOptions(this.maxFetches, value, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts, this.resolutionWallClock);
    }

    public ValidatorOptions withClockSkewSeconds(int value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, value, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts, this.resolutionWallClock);
    }

    public ValidatorOptions withClock(Clock value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, value,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts, this.resolutionWallClock);
    }

    public ValidatorOptions withRequirePeerChainSameAnchor(boolean value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                value, this.maxRouteAttempts, this.resolutionWallClock);
    }

    public ValidatorOptions withMaxRouteAttempts(int value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, value, this.resolutionWallClock);
    }

    public ValidatorOptions withResolutionWallClock(Duration value) {
        return new ValidatorOptions(this.maxFetches, this.maxAuthorityHints, this.clockSkewSeconds, this.clock,
                this.requirePeerChainSameAnchor, this.maxRouteAttempts, value);
    }

    /** The catalogue, loaded once per loaded copy of this class and read from the process each time. */
    private static final class CatalogueHolder {
        static final Catalogue CATALOGUE = Catalogue.load(ValidatorOptions.class.getClassLoader(), COMPONENT);
    }
}
