/*
 * A point in time after which the work it bounds has run out of time.
 */
package com.pingidentity.ps.oidf.platform.http;

import java.time.Duration;
import java.util.Objects;
import java.util.function.LongSupplier;

/**
 * An absolute deadline on the monotonic clock ({@link System#nanoTime()}), so a wall-clock step does not stretch
 * or shorten it. It is made once, from a duration, and then only asked how much is left: every blocking step that
 * {@link OutboundHttp} takes is bounded by {@link #remaining()} at the moment it starts, so the total holds without
 * a watchdog thread.
 *
 * <p>Durations longer than {@value #MAX_NANOS} nanoseconds (about 73 years) are held at that, and zero or negative
 * ones give a deadline that has already passed. Two deadlines compare by what is left of each, so {@link #min} is
 * right even for deadlines made on different clocks (only tests make those).
 */
public final class Deadline {
    /** The longest deadline: a quarter of the clock's range, so {@code at - now} never wraps. */
    static final long MAX_NANOS = Long.MAX_VALUE / 4;

    private final LongSupplier clock;
    private final long at;

    private Deadline(LongSupplier clock, long at) {
        this.clock = clock;
        this.at = at;
    }

    /** A deadline {@code timeout} from now. */
    public static Deadline after(Duration timeout) {
        return after(timeout, System::nanoTime);
    }

    /** A deadline {@code timeout} from now on {@code clock}: a test seam. */
    static Deadline after(Duration timeout, LongSupplier clock) {
        Objects.requireNonNull(timeout, "timeout");
        Objects.requireNonNull(clock, "clock");
        return new Deadline(clock, clock.getAsLong() + nanos(timeout));
    }

    /** {@code timeout} in nanoseconds, held to {@code [0, MAX_NANOS]}. */
    static long nanos(Duration timeout) {
        if (timeout.isNegative() || timeout.isZero()) {
            return 0L;
        }
        if (timeout.compareTo(Duration.ofNanos(MAX_NANOS)) > 0) {
            return MAX_NANOS;
        }
        return timeout.toNanos();
    }

    /** What is left, in nanoseconds; zero once the deadline has passed. */
    public long remainingNanos() {
        long left = this.at - this.clock.getAsLong();
        return left > 0 ? left : 0L;
    }

    /** What is left; {@link Duration#ZERO} once the deadline has passed. */
    public Duration remaining() {
        return Duration.ofNanos(remainingNanos());
    }

    /** Whether the deadline has passed. */
    public boolean expired() {
        return remainingNanos() == 0L;
    }

    /** This deadline, or one {@code timeout} from now if that comes first. */
    public Deadline sooner(Duration timeout) {
        Deadline candidate = after(timeout, this.clock);
        return min(candidate);
    }

    /** Whichever of this and {@code other} has less left; this one when they are level. */
    public Deadline min(Deadline other) {
        Objects.requireNonNull(other, "other");
        return other.remainingNanos() < remainingNanos() ? other : this;
    }

    /**
     * What is left as a socket timeout in milliseconds: rounded up, so a deadline with 0.4 ms left waits 1 ms rather
     * than 0 (which a socket reads as "forever"), and held to {@link Integer#MAX_VALUE}. Zero only when the deadline
     * has passed; the caller must not hand zero to a socket.
     */
    int timeoutMillis() {
        long left = remainingNanos();
        if (left == 0L) {
            return 0;
        }
        long millis = (left + 999_999L) / 1_000_000L;
        return millis > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) millis;
    }

    @Override
    public String toString() {
        return "Deadline[remaining=" + remaining() + "]";
    }
}
