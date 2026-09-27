/*
 * One series of a metric, as read at one moment.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.List;
import javax.management.ConstructorParameters;

/**
 * One series: its label values, in the order of {@link MetricSnapshot#getLabelNames()}, and what it holds. A
 * counter's value is {@link #getCount()} (and {@link #getValue()} the same as a double); a gauge's is
 * {@link #getValue()}; a timer has {@link #getCount()}, {@link #getSumSeconds()}, {@link #getMaxSeconds()} and
 * {@link #getBucketCounts()}, cumulative and aligned to {@link Timer#BUCKETS_SECONDS} with {@code +Inf} last, so
 * the last equals the count. Fields a kind does not use are 0 (an empty array for the buckets).
 *
 * <p>A class with getters rather than a record, so the MXBean maps it to {@code CompositeData} on JDK 17 and a
 * reader in another loader can rebuild it through a proxy ({@link ConstructorParameters}).
 */
public final class SeriesSnapshot {

    private final List<String> labelValues;
    private final long count;
    private final double value;
    private final double sumSeconds;
    private final double maxSeconds;
    private final long[] bucketCounts;

    @ConstructorParameters({"labelValues", "count", "value", "sumSeconds", "maxSeconds", "bucketCounts"})
    public SeriesSnapshot(List<String> labelValues, long count, double value, double sumSeconds, double maxSeconds, long[] bucketCounts) {
        this.labelValues = List.copyOf(labelValues);
        this.count = count;
        this.value = value;
        this.sumSeconds = sumSeconds;
        this.maxSeconds = maxSeconds;
        this.bucketCounts = bucketCounts.clone();
    }

    public List<String> getLabelValues() {
        return this.labelValues;
    }

    public long getCount() {
        return this.count;
    }

    public double getValue() {
        return this.value;
    }

    public double getSumSeconds() {
        return this.sumSeconds;
    }

    public double getMaxSeconds() {
        return this.maxSeconds;
    }

    public long[] getBucketCounts() {
        return this.bucketCounts.clone();
    }
}
