/*
 * The MXBean over one registry.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import java.util.List;
import java.util.Map;

/** {@link MetricsMXBean} over a registry: every read is a fresh snapshot. */
final class MetricsView implements MetricsMXBean {

    private final MetricRegistry registry;
    private final String copy;

    MetricsView(MetricRegistry registry, String copy) {
        this.registry = registry;
        this.copy = copy;
    }

    @Override
    public String getCopy() {
        return this.copy;
    }

    @Override
    public String getLoaderRole() {
        return Lifecycle.current().loaderRole().name();
    }

    @Override
    public int getMetricCount() {
        return this.registry.size();
    }

    @Override
    public int getSeriesCount() {
        return this.registry.seriesCount();
    }

    @Override
    public long getLabelFolds() {
        return this.registry.labelFolds();
    }

    @Override
    public long getRefusedRegistrations() {
        return this.registry.refusedRegistrations();
    }

    @Override
    public double[] getTimerBucketsSeconds() {
        return Timer.BUCKETS_SECONDS.stream().mapToDouble(Double::doubleValue).toArray();
    }

    @Override
    public List<MetricSnapshot> getMetrics() {
        return this.registry.snapshot();
    }

    @Override
    public Map<String, Double> getSamples() {
        return Samples.flatten(this.registry.snapshot());
    }
}
