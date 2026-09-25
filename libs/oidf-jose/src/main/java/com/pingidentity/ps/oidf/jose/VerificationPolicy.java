/*
 * What a JWT verification requires beyond the signature.
 */
package com.pingidentity.ps.oidf.jose;

import java.time.Clock;

/**
 * The per-kind rules {@link JwtCodec#verifyAgainstKeys(String, java.util.List, String, java.util.Set, VerificationPolicy)}
 * applies on top of signature, issuer, subject and expiry.
 *
 * <p>{@link #legacy()} is exactly what the four-argument overload has always done, so client
 * attestations and every other existing caller are unaffected. {@link #entityStatement()} is the
 * OpenID Federation 1.0 §3.2 profile: the {@code kid} header MUST be a non-zero length string that
 * exactly matches a key in the issuer's JWK Set (so the key is selected by {@code kid}, never guessed),
 * {@code iat} MUST be present and in the past, and {@code typ} MUST be {@code entity-statement+jwt}.
 *
 * @param requireKid       select the verification key by an exact {@code kid} match, refusing a token
 *                         without one
 * @param requireIssuedAt  require {@code iat} and refuse one later than now plus the skew
 * @param clockSkewSeconds leeway for {@code exp}, {@code nbf} and {@code iat}
 * @param expectedTyp      the required {@code typ} header, or {@code null} to not check it here
 * @param clock            the clock to evaluate time claims against, or {@code null} for the system clock
 */
public record VerificationPolicy(boolean requireKid, boolean requireIssuedAt, int clockSkewSeconds,
                                 String expectedTyp, Clock clock) {

    public static final int DEFAULT_CLOCK_SKEW_SECONDS = 60;

    public VerificationPolicy {
        if (clockSkewSeconds < 0) {
            throw new IllegalArgumentException("clockSkewSeconds must not be negative");
        }
    }

    /** Today's behaviour: no {@code kid}, {@code iat} or {@code typ} requirement, 60 s skew, system clock. */
    public static VerificationPolicy legacy() {
        return new VerificationPolicy(false, false, DEFAULT_CLOCK_SKEW_SECONDS, null, null);
    }

    /** OpenID Federation 1.0 §3.2 for Entity Statements. */
    public static VerificationPolicy entityStatement() {
        return new VerificationPolicy(true, true, DEFAULT_CLOCK_SKEW_SECONDS, "entity-statement+jwt", null);
    }

    /** OpenID Federation 1.0 §7.3 for Trust Marks. */
    public static VerificationPolicy trustMark() {
        return new VerificationPolicy(true, true, DEFAULT_CLOCK_SKEW_SECONDS, "trust-mark+jwt", null);
    }

    public VerificationPolicy withClock(Clock newClock) {
        return new VerificationPolicy(this.requireKid, this.requireIssuedAt, this.clockSkewSeconds, this.expectedTyp, newClock);
    }

    public VerificationPolicy withTyp(String typ) {
        return new VerificationPolicy(this.requireKid, this.requireIssuedAt, this.clockSkewSeconds, typ, this.clock);
    }

    public VerificationPolicy withClockSkewSeconds(int seconds) {
        return new VerificationPolicy(this.requireKid, this.requireIssuedAt, seconds, this.expectedTyp, this.clock);
    }

    /** The clock to use: the configured one, or the system UTC clock. */
    public Clock effectiveClock() {
        return this.clock == null ? Clock.systemUTC() : this.clock;
    }
}
