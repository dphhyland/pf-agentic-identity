/*
 * A timer's buckets are fixed, inclusive of their bound, and its count is the last of them.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class TimerTest {

    @Test
    void theBucketsAreTheDocumentedOnes() {
        assertEquals(List.of(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0), Timer.BUCKETS_SECONDS);
    }

    @Test
    void aRecordingFallsInTheFirstBucketItDoesNotExceed() {
        assertEquals(0, Timer.bucketIndex(0));
        assertEquals(0, Timer.bucketIndex(1_000_000), "exactly 1 ms is le 0.001");
        assertEquals(1, Timer.bucketIndex(1_000_001));
        assertEquals(1, Timer.bucketIndex(2_500_000));
        assertEquals(9, Timer.bucketIndex(1_000_000_000L), "exactly 1 s");
        assertEquals(14, Timer.bucketIndex(60_000_000_000L));
        assertEquals(15, Timer.bucketIndex(60_000_000_001L), "+Inf");
        assertEquals(15, Timer.bucketIndex(Long.MAX_VALUE));
    }

    @Test
    void recordsCountSumAndMax() {
        MetricRegistry r = new MetricRegistry();
        Timer t = r.timer("oidf_test_seconds", "h", Label.oneOf("o", "ok"));
        t.record(Duration.ofMillis(3), "ok");
        t.recordNanos(-5, "ok");
        t.recordNanos(700_000_000, "ok");
        long start = System.nanoTime();
        t.recordSince(start, "ok");
        assertEquals(4, t.count("ok"));
        assertEquals(0, t.count("nope"));
        assertEquals(0, t.count(), "the wrong number of values reads nothing");
        assertEquals("oidf_test_seconds", t.name());
        Timer.Cell cell = new Timer.Cell();
        cell.record(3_000_000);
        cell.record(-1);
        cell.record(700_000_000);
        assertEquals(700_000_000, cell.maxNanos.get());
        assertEquals(703_000_000, cell.sumNanos.sum(), "a negative duration counts as 0");
        assertArrayEquals(new long[] {1, 1, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3}, cell.cumulative());
    }

    @Test
    void aRecordingOverADayCountsAsADayAndCannotOverflowTheSum() {
        Timer.Cell cell = new Timer.Cell();
        cell.record(Long.MAX_VALUE);
        cell.record(Long.MAX_VALUE);
        assertEquals(Timer.MAX_RECORDING_NANOS, cell.maxNanos.get());
        assertEquals(2 * Timer.MAX_RECORDING_NANOS, cell.sumNanos.sum(), "the sum stays positive");
        assertEquals(2, cell.cumulative()[15], "both in +Inf");
        assertEquals(0, cell.cumulative()[14]);

        MetricRegistry r = new MetricRegistry();
        Timer t = r.timer("oidf_long_seconds", "h");
        t.record(Duration.ofSeconds(Long.MAX_VALUE));
        t.record(Duration.ofSeconds(Long.MIN_VALUE));
        t.record(Duration.ofDays(3));
        assertEquals(3, t.count(), "a Duration too long for nanoseconds is recorded, not thrown");
        MetricSnapshot snap = r.snapshot().stream().filter(m -> m.getName().equals("oidf_long_seconds")).findFirst().orElseThrow();
        assertEquals(2 * 86_400.0, snap.getSeries().get(0).getSumSeconds(), 1e-6, "two days and a negative counted as 0");
        assertEquals(86_400.0, snap.getSeries().get(0).getMaxSeconds(), 1e-6);
    }
}
