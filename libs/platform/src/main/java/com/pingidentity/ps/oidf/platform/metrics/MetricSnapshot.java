/*
 * One metric and all its series, as read at one moment.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.List;
import javax.management.ConstructorParameters;

/**
 * What O-5's Prometheus text renders for one metric - its {@code # HELP} and {@code # TYPE} lines and one line per
 * series (three plus the buckets for a timer) - with nothing left to compute but the formatting. The series are
 * ordered by their label values.
 */
public final class MetricSnapshot {

    private final String name;
    private final String help;
    private final Kind kind;
    private final List<String> labelNames;
    private final List<SeriesSnapshot> series;

    @ConstructorParameters({"name", "help", "kind", "labelNames", "series"})
    public MetricSnapshot(String name, String help, Kind kind, List<String> labelNames, List<SeriesSnapshot> series) {
        this.name = name;
        this.help = help;
        this.kind = kind;
        this.labelNames = List.copyOf(labelNames);
        this.series = List.copyOf(series);
    }

    public String getName() {
        return this.name;
    }

    public String getHelp() {
        return this.help;
    }

    public Kind getKind() {
        return this.kind;
    }

    public List<String> getLabelNames() {
        return this.labelNames;
    }

    public List<SeriesSnapshot> getSeries() {
        return this.series;
    }
}
