/*
 * How long something took: count, sum, max and fixed buckets.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.LongAccumulator;
import java.util.concurrent.atomic.LongAdder;

/**
 * A timer. Each recording adds to one of the fixed buckets, to the sum and to the max, with no lock (a
 * {@link LongAdder} per bucket and for the sum, a {@link LongAccumulator} for the max). The count is the sum of
 * the buckets, so it always equals the last cumulative bucket, as Prometheus requires of {@code _count} and
 * {@code le="+Inf"}.
 *
 * <p>The buckets are the same for every timer, {@link #BUCKETS_SECONDS}, so O-5's Prometheus text renders one
 * set of {@code le} values and a dashboard can compare any two timers. They run from 1 ms, for the decisions
 * made in process (an OGNL criterion, a signature check), through the tens and hundreds of milliseconds of a
 * database, Redis or federation call, to 60 s for a background run such as the registration sweeper. Changing
 * them changes every histogram's series, which breaks dashboards and alerts: it is a "Before you deploy" item.
 *
 * <p>The max is the longest recording since this copy of platform was loaded, not over a window.
 */
public final class Timer {

    /** The upper bounds of the buckets, in seconds; a last bucket, {@code +Inf}, takes everything longer. */
    public static final List<Double> BUCKETS_SECONDS = List.of(
            0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0);

    private static final long[] BOUNDS_NANOS = BUCKETS_SECONDS.stream().mapToLong(s -> Math.round(s * 1e9)).toArray();

    /**
     * The longest a recording counts as, one day: longer ones land in {@code +Inf} and add a day to the sum and
     * the max, so a stray {@code Long.MAX_VALUE} cannot send the sum negative.
     */
    static final long MAX_RECORDING_NANOS = Duration.ofDays(1).toNanos();

    /** One series' buckets, sum and max. */
    static final class Cell {
        final LongAdder[] buckets = new LongAdder[BOUNDS_NANOS.length + 1];
        final LongAdder sumNanos = new LongAdder();
        final LongAccumulator maxNanos = new LongAccumulator(Math::max, 0);

        Cell() {
            for (int i = 0; i < this.buckets.length; i++) {
                this.buckets[i] = new LongAdder();
            }
        }

        void record(long nanos) {
            long n = Math.min(Math.max(0, nanos), MAX_RECORDING_NANOS);
            this.buckets[bucketIndex(n)].increment();
            this.sumNanos.add(n);
            this.maxNanos.accumulate(n);
        }

        /** The buckets as Prometheus counts them: each includes every bucket below it; the last is the count. */
        long[] cumulative() {
            long[] out = new long[this.buckets.length];
            long running = 0;
            for (int i = 0; i < out.length; i++) {
                running += this.buckets[i].sum();
                out[i] = running;
            }
            return out;
        }
    }

    private final Family<Cell> family;

    Timer(Family<Cell> family) {
        this.family = family;
    }

    /** The bucket a recording falls in: the first whose bound it does not exceed ({@code le}), else the last. */
    static int bucketIndex(long nanos) {
        for (int i = 0; i < BOUNDS_NANOS.length; i++) {
            if (nanos <= BOUNDS_NANOS[i]) {
                return i;
            }
        }
        return BOUNDS_NANOS.length;
    }

    /** Records a duration in nanoseconds; a negative one counts as 0, one over a day as a day. */
    public void recordNanos(long nanos, String... labelValues) {
        this.family.cell(labelValues).record(nanos);
    }

    /** Records a duration; one too long for {@link Duration#toNanos()} counts as {@link #MAX_RECORDING_NANOS}. */
    public void record(Duration duration, String... labelValues) {
        long nanos;
        try {
            nanos = duration.toNanos();
        } catch (ArithmeticException tooLong) {
            nanos = duration.isNegative() ? 0 : MAX_RECORDING_NANOS;
        }
        recordNanos(nanos, labelValues);
    }

    /** Records the time since {@code startNanos}, a value {@link System#nanoTime()} returned. */
    public void recordSince(long startNanos, String... labelValues) {
        recordNanos(System.nanoTime() - startNanos, labelValues);
    }

    /** How many recordings there have been under these exact values; creates nothing. */
    public long count(String... labelValues) {
        Cell c = this.family.peek(labelValues);
        return c == null ? 0 : c.cumulative()[BOUNDS_NANOS.length];
    }

    public String name() {
        return this.family.name;
    }
}
