/*
 * A gauge reads its supplier when the metrics are read, and a broken supplier reads NaN.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class GaugeTest {

    @Test
    void readsTheSupplierBoundToEachSeries() {
        MetricRegistry r = new MetricRegistry();
        AtomicInteger active = new AtomicInteger(2);
        Gauge g = r.gauge("oidf_test_pool_active", "h", Label.oneOf("pool", "redis", "jdbc"));
        g.set(active::get, "redis");
        assertEquals(2.0, g.read("redis"));
        active.set(5);
        assertEquals(5.0, g.read("redis"), "read when asked, not when bound");
        assertTrue(Double.isNaN(g.read("jdbc")), "nothing bound");
        g.set(() -> 7, "redis");
        assertEquals(7.0, g.read("redis"), "a new supplier replaces the old");
        assertThrows(NullPointerException.class, () -> g.set(null, "redis"));
        assertEquals("oidf_test_pool_active", g.name());
    }

    @Test
    void aSupplierThatThrowsOrFailsToLinkReadsNaN() {
        Gauge.Cell cell = new Gauge.Cell();
        assertTrue(Double.isNaN(cell.read()), "unbound");
        cell.supplier = () -> {
            throw new IllegalStateException("closed");
        };
        assertTrue(Double.isNaN(cell.read()));
        cell.supplier = () -> {
            throw new NoClassDefFoundError("gone");
        };
        assertTrue(Double.isNaN(cell.read()));
    }
}
