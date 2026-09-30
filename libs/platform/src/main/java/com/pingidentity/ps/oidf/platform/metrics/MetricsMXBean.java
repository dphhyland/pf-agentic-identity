/*
 * The JMX view of one loaded copy's metrics.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.List;
import java.util.Map;

/**
 * One copy of platform's metrics, as JMX shows them: registered under
 * {@code com.pingidentity.ps.oidf:type=Metrics,copy=<which copy>} in the platform MBean server, one per loader that
 * has registered a metric. Every attribute is an open type, so a JMX console, or a reader in another loader, sees
 * the same data without this interface on its classpath.
 */
public interface MetricsMXBean {

    /** Which copy of platform this is: its package, and the jar or directory it was loaded from. */
    String getCopy();

    /** {@code WEBAPP} once the webapp's lifecycle listener has marked this copy; {@code UNKNOWN} otherwise. */
    String getLoaderRole();

    int getMetricCount();

    int getSeriesCount();

    long getLabelFolds();

    long getRefusedRegistrations();

    /** The timers' bucket bounds in seconds, {@code +Inf} not included. */
    double[] getTimerBucketsSeconds();

    /** Every metric and series: what O-5's text renders. */
    List<MetricSnapshot> getMetrics();

    /** Every sample, keyed as a Prometheus line names it. */
    Map<String, Double> getSamples();
}
