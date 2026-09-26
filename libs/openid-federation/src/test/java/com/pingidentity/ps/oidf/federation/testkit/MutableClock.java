/*
 * A clock a test can move.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A {@link Clock} fixed at an instant the test sets and advances; never reads the system time. */
public final class MutableClock extends Clock {
    private volatile Instant now;

    public MutableClock(Instant start) {
        this.now = start;
    }

    /** A clock at the current second, then under the test's control. */
    public static MutableClock startingNow() {
        return new MutableClock(Instant.ofEpochSecond(Instant.now().getEpochSecond()));
    }

    public MutableClock advance(Duration by) {
        this.now = this.now.plus(by);
        return this;
    }

    public MutableClock set(Instant instant) {
        this.now = instant;
        return this;
    }

    public long epochSecond() {
        return this.now.getEpochSecond();
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return this;
    }

    @Override
    public Instant instant() {
        return this.now;
    }
}
