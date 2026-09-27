/*
 * The three kinds of metric.
 */
package com.pingidentity.ps.oidf.platform.metrics;

/** What a metric counts, and how O-5's Prometheus text renders it. */
public enum Kind {
    /** A count that only rises; its name ends {@code _total}. */
    COUNTER,
    /** How long something took: count, sum, max and fixed buckets; its name ends {@code _seconds}. */
    TIMER,
    /** A value read from a supplier when the metrics are read. */
    GAUGE
}
