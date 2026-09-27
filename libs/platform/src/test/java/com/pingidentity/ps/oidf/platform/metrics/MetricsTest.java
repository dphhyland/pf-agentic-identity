/*
 * This loader's metrics register their MXBean on first use.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.management.ManagementFactory;
import javax.management.ObjectName;
import org.junit.jupiter.api.Test;

class MetricsTest {

    @Test
    void theFirstMetricRegistersThisCopysMXBean() throws Exception {
        Counter c = Metrics.counter("oidf_metrics_test_total", "h", Label.oneOf("o", "ok"));
        c.inc("ok");
        ObjectName name = Metrics.registerMXBean().orElseThrow();
        assertTrue(ManagementFactory.getPlatformMBeanServer().isRegistered(name));
        String copy = ObjectName.unquote(name.getKeyProperty("copy"));
        assertTrue(copy.startsWith("com.pingidentity.ps.oidf.platform.metrics from file:"), copy);
        assertSame(c, Metrics.registry().counter("oidf_metrics_test_total", "h", Label.oneOf("o", "ok")));
        Metrics.timer("oidf_metrics_test_seconds", "h").recordNanos(1);
        Metrics.gauge("oidf_metrics_test_open", "h", () -> 4).name();
        Metrics.gauge("oidf_metrics_test_pool", "h", Label.oneOf("p", "x")).set(() -> 1, "x");
        assertTrue(Metrics.snapshot().stream().anyMatch(m -> m.getName().equals("oidf_metrics_test_open")));
        assertTrue((Integer) ManagementFactory.getPlatformMBeanServer().getAttribute(name, "SeriesCount") >= 3);
    }
}
