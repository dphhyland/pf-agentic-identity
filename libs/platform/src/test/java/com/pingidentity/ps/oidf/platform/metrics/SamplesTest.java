/*
 * Snapshots flatten to one value per Prometheus sample name.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SamplesTest {

    @Test
    void everyKindFlattensToItsSamples() {
        MetricRegistry r = new MetricRegistry();
        r.counter("oidf_x_total", "h", Label.capped("client", 5), Label.oneOf("o", "ok")).inc("a\"b\\c", "ok");
        r.gauge("oidf_y", "h", () -> 1.5);
        r.timer("oidf_z_seconds", "h").recordNanos(1_500_000_000L);
        Map<String, Double> samples = Samples.flatten(r.snapshot());
        assertEquals(Map.of(
                "oidf_x_total{client=\"a\\\"b\\\\c\",o=\"ok\"}", 1.0,
                "oidf_y", 1.5,
                "oidf_z_seconds_count", 1.0,
                "oidf_z_seconds_sum", 1.5,
                "oidf_z_seconds_max", 1.5,
                "oidf_metrics_refused_total", 0.0), samples);
    }

    @Test
    void labelValuesAreEscapedAsTheTextFormatRequires() {
        assertEquals("", Samples.labels(List.of(), List.of()));
        assertEquals("{a=\"x\"}", Samples.labels(List.of("a"), List.of("x")));
        assertEquals("plain", Samples.escape("plain"));
        assertEquals("a\\\\b\\\"c\\nd", Samples.escape("a\\b\"c\nd"));
    }
}
