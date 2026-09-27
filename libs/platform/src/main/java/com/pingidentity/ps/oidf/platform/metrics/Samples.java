/*
 * Snapshots as flat samples, keyed the way a Prometheus line names them.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Flattens snapshots into one value per sample, keyed as a Prometheus text line names it -
 * {@code oidf_x_total{outcome="refused"}} - for the MXBean's {@code Samples} attribute, which a JMX console shows
 * as a table. A timer gives {@code _count}, {@code _sum} and {@code _max} (in seconds); its buckets are left to
 * {@link MetricSnapshot} and O-5's text.
 */
public final class Samples {

    private Samples() {
    }

    /** Every sample in these snapshots, ordered by key. */
    public static Map<String, Double> flatten(List<MetricSnapshot> snapshots) {
        Map<String, Double> out = new TreeMap<>();
        for (MetricSnapshot m : snapshots) {
            for (SeriesSnapshot s : m.getSeries()) {
                String labels = labels(m.getLabelNames(), s.getLabelValues());
                if (m.getKind() == Kind.TIMER) {
                    out.put(m.getName() + "_count" + labels, (double) s.getCount());
                    out.put(m.getName() + "_sum" + labels, s.getSumSeconds());
                    out.put(m.getName() + "_max" + labels, s.getMaxSeconds());
                } else {
                    out.put(m.getName() + labels, s.getValue());
                }
            }
        }
        return out;
    }

    /** {@code {a="x",b="y"}}, or empty for no labels, with each value escaped as the Prometheus text format does. */
    public static String labels(List<String> names, List<String> values) {
        if (names.isEmpty()) {
            return "";
        }
        StringBuilder b = new StringBuilder("{");
        for (int i = 0; i < names.size(); i++) {
            if (i > 0) {
                b.append(',');
            }
            b.append(names.get(i)).append("=\"").append(escape(values.get(i))).append('"');
        }
        return b.append('}').toString();
    }

    /** A label value with backslash, double quote and line feed escaped, as the Prometheus text format requires. */
    public static String escape(String value) {
        StringBuilder b = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '"') {
                b.append('\\').append(c);
            } else if (c == '\n') {
                b.append("\\n");
            } else {
                b.append(c);
            }
        }
        return b.toString();
    }
}
