/*
 * The registry cannot be grown without bound, whatever a caller passes it.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class MetricRegistryTest {

    private static MetricSnapshot find(MetricRegistry r, String name) {
        return r.snapshot().stream().filter(m -> m.getName().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void aHundredThousandDistinctValuesUnderACapKeepTheCapAndFoldTheRest() {
        MetricRegistry r = new MetricRegistry();
        Counter c = r.counter("oidf_test_requests_total", "Requests", Label.capped("client", 100), Label.oneOf("outcome", "ok", "refused"));
        for (int i = 0; i < 100_000; i++) {
            c.inc("client-" + i, i % 2 == 0 ? "ok" : "refused");
        }
        assertEquals(100 + 2, r.seriesCount(), "the first 100 clients, one outcome each, and other by both outcomes");
        assertEquals(100_000 - 100, r.labelFolds());
        assertEquals(1, c.get("client-0", "ok"));
        assertEquals(0, c.get("client-0", "refused"));
        assertEquals((100_000 - 100) / 2, c.get("other", "ok"));
        MetricSnapshot folds = find(r, MetricRegistry.FOLDS);
        assertEquals(List.of("metric"), folds.getLabelNames());
        assertEquals(1, folds.getSeries().size());
        assertEquals(List.of("oidf_test_requests_total"), folds.getSeries().get(0).getLabelValues());
        assertEquals(100_000 - 100, folds.getSeries().get(0).getCount());
    }

    @Test
    void aHundredThousandDistinctValuesOutsideADeclaredSetAllFold() {
        MetricRegistry r = new MetricRegistry();
        Timer t = r.timer("oidf_test_decision_seconds", "Decisions", Label.oneOf("code", "a", "b"));
        for (int i = 0; i < 100_000; i++) {
            t.recordNanos(1000, "code-" + i);
        }
        t.recordNanos(1000, "a");
        assertEquals(2, r.seriesCount());
        assertEquals(100_000, r.labelFolds());
        assertEquals(100_000, t.count("other"));
        assertEquals(1, t.count("a"));
    }

    @Test
    void aHundredThousandDistinctNamesStopAtTheRegistryLimit() {
        MetricRegistry r = new MetricRegistry();
        List<Counter> refused = new ArrayList<>();
        for (int i = 0; i < 100_000; i++) {
            Counter c = r.counter("oidf_test_n" + i + "_total", "Generated");
            c.inc();
            if (i >= MetricRegistry.MAX_METRICS) {
                refused.add(c);
            }
        }
        assertEquals(MetricRegistry.MAX_METRICS, r.size());
        assertEquals(100_000 - MetricRegistry.MAX_METRICS, r.refusedRegistrations());
        assertEquals(MetricRegistry.MAX_METRICS + 2, r.snapshot().size(), "the registry's own two besides");
        assertEquals(1, refused.get(0).get(), "a refused metric still counts, unseen");
        assertEquals(100_000 - MetricRegistry.MAX_METRICS, find(r, MetricRegistry.REFUSED).getSeries().get(0).getCount());
    }

    @Test
    void theSeriesBudgetRefusesAMetricThatWouldExceedIt() {
        MetricRegistry r = new MetricRegistry();
        int each = 2048;
        int fit = MetricRegistry.MAX_SERIES / each;
        for (int i = 0; i < fit; i++) {
            r.counter("oidf_test_wide" + i + "_total", "Wide", Label.capped("a", 1023), Label.oneOf("b", "x"));
        }
        assertEquals(fit, r.size());
        r.counter("oidf_test_narrow_total", "Narrow");
        assertEquals(fit, r.size(), "no series left for even one more");
        assertEquals(1, r.refusedRegistrations());
    }

    @Test
    void oneMetricsLabelsMayNotAllowTooManySeries() {
        MetricRegistry r = new MetricRegistry();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> r.counter("oidf_test_huge_total", "Huge", Label.capped("a", 100), Label.capped("b", 100)));
        assertTrue(e.getMessage().contains("more than 2048 series"), e.getMessage());
        r.counter("oidf_test_ok_total", "Fits", Label.capped("a", 1023), Label.oneOf("b", "x"));
        assertEquals(1, r.size());
    }

    @Test
    void registeringAgainReturnsTheSameMetricOrRefusesAnotherShape() {
        AtomicInteger announced = new AtomicInteger();
        MetricRegistry r = new MetricRegistry(announced::incrementAndGet);
        Counter c = r.counter("oidf_test_a_total", "A", Label.oneOf("o", "x"));
        assertSame(c, r.counter("oidf_test_a_total", "Another help", Label.oneOf("o", "x")));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_a_total", "A", Label.oneOf("o", "y")));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_a_total", "A"));
        Gauge g = r.gauge("oidf_test_a", "A gauge", () -> 1);
        assertThrows(IllegalArgumentException.class, () -> r.timer("oidf_test_a", "A"), "a timer's name must end _seconds");
        assertSame(g, r.gauge("oidf_test_a", "A gauge", () -> 2));
        assertEquals(2.0, g.read(), "the latest supplier is read");
        Timer t = r.timer("oidf_test_a_seconds", "A");
        assertThrows(IllegalArgumentException.class, () -> r.gauge("oidf_test_a_seconds", "A"), "a gauge where a timer is");
        assertSame(t, r.timer("oidf_test_a_seconds", "A"));
        assertEquals(1, announced.get(), "the first registration is announced, once");
    }

    @Test
    void namesHelpAndLabelsAreChecked() {
        MetricRegistry r = new MetricRegistry();
        assertThrows(IllegalArgumentException.class, () -> r.counter(null, "h"));
        assertThrows(IllegalArgumentException.class, () -> r.counter("test_total", "h"), "oidf_ first");
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_Test_total", "h"));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_" + "a".repeat(124) + "_total", "h"));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test", "h"), "a counter ends _total");
        assertThrows(IllegalArgumentException.class, () -> r.timer("oidf_test_total", "h"), "a timer ends _seconds");
        for (String suffix : List.of("_total", "_count", "_sum", "_bucket", "_max")) {
            assertThrows(IllegalArgumentException.class, () -> r.gauge("oidf_test" + suffix, "h"), suffix);
        }
        assertThrows(IllegalArgumentException.class, () -> r.counter(MetricRegistry.FOLDS, "h"));
        assertThrows(IllegalArgumentException.class, () -> r.counter(MetricRegistry.REFUSED, "h"));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_total", null));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_total", " "));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_total", "h".repeat(257)));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_total", "two\nlines"));
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_total", "h", Label.oneOf("a", "x"), Label.capped("a", 2)));
        Label[] nine = new Label[9];
        for (int i = 0; i < nine.length; i++) {
            nine[i] = Label.oneOf("l" + i, "x");
        }
        assertThrows(IllegalArgumentException.class, () -> r.counter("oidf_test_total", "h", nine));
        assertThrows(NullPointerException.class, () -> r.counter("oidf_test_total", "h", (Label) null));
        r.counter("oidf_test_total", "h", (Label[]) null);
        r.gauge("oidf_test_seconds_budget", "h".repeat(256), Label.oneOf("l", "x"));
        r.counter("oidf_eight_total", "h", java.util.Arrays.copyOf(nine, 8));
        assertEquals(3, r.size());
    }

    @Test
    void theWrongNumberOfValuesIsACallersBug() {
        MetricRegistry r = new MetricRegistry();
        Counter c = r.counter("oidf_test_total", "h", Label.oneOf("o", "x"));
        assertThrows(IllegalArgumentException.class, c::inc);
        assertThrows(IllegalArgumentException.class, () -> c.inc("x", "y"));
        assertThrows(IllegalArgumentException.class, () -> c.inc((String[]) null));
        assertEquals(0, c.get(), "a read with the wrong number reads nothing");
        assertEquals(0, c.get((String[]) null));
        Counter bare = r.counter("oidf_bare_total", "h");
        bare.inc((String[]) null);
        assertEquals(1, bare.get());
    }

    @Test
    void countersOnlyRise() {
        MetricRegistry r = new MetricRegistry();
        Counter c = r.counter("oidf_test_total", "h", Label.oneOf("o", "x"));
        c.add(5, "x");
        c.add(0, "x");
        c.add(-3, "x");
        c.inc("x");
        assertEquals(6, c.get("x"));
        assertEquals(0, c.get("y"), "not a series");
        assertEquals(0, c.get((String) null), "null reads as other, which has nothing");
        c.inc((String) null);
        assertEquals(1, c.get("other"));
        assertEquals(1, c.get((String) null));
        assertEquals("oidf_test_total", c.name());
    }

    @Test
    void manyThreadsLoseNoIncrement() throws Exception {
        MetricRegistry r = new MetricRegistry();
        Counter c = r.counter("oidf_test_total", "h", Label.capped("t", 4));
        Timer t = r.timer("oidf_test_seconds", "h");
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            String name = "t" + (i % 4);
            threads.add(new Thread(() -> {
                for (int n = 0; n < 50_000; n++) {
                    c.inc(name);
                    t.recordNanos(n);
                }
            }));
        }
        threads.forEach(Thread::start);
        for (Thread th : threads) {
            th.join();
        }
        long total = 0;
        for (int i = 0; i < 4; i++) {
            total += c.get("t" + i);
        }
        assertEquals(400_000, total);
        assertEquals(400_000, t.count());
        assertEquals(0, r.labelFolds());
    }

    @Test
    void aSnapshotIsOrderedAndCarriesEveryKind() {
        MetricRegistry r = new MetricRegistry();
        Counter c = r.counter("oidf_b_total", "B", Label.oneOf("o", "x", "y"));
        c.inc("y");
        c.inc("x");
        c.inc("x");
        r.gauge("oidf_a_open", "A", () -> 3.5);
        Gauge broken = r.gauge("oidf_c_pool", "C", Label.oneOf("pool", "p"));
        broken.set(() -> {
            throw new IllegalStateException("closed");
        }, "p");
        Timer t = r.timer("oidf_d_seconds", "D");
        t.recordNanos(2_000_000);
        t.recordNanos(40_000_000_000L);
        List<MetricSnapshot> s = r.snapshot();
        assertEquals(List.of("oidf_a_open", "oidf_b_total", "oidf_c_pool", "oidf_d_seconds", MetricRegistry.FOLDS, MetricRegistry.REFUSED),
                s.stream().map(MetricSnapshot::getName).toList());
        MetricSnapshot b = s.get(1);
        assertEquals(Kind.COUNTER, b.getKind());
        assertEquals("B", b.getHelp());
        assertEquals(List.of("o"), b.getLabelNames());
        assertEquals(List.of(List.of("x"), List.of("y")), b.getSeries().stream().map(SeriesSnapshot::getLabelValues).toList());
        assertEquals(2, b.getSeries().get(0).getCount());
        assertEquals(2.0, b.getSeries().get(0).getValue());
        assertEquals(3.5, s.get(0).getSeries().get(0).getValue());
        assertTrue(Double.isNaN(s.get(2).getSeries().get(0).getValue()), "a supplier that throws reads NaN");
        SeriesSnapshot d = s.get(3).getSeries().get(0);
        assertEquals(2, d.getCount());
        assertEquals(40.002, d.getSumSeconds(), 1e-9);
        assertEquals(40.0, d.getMaxSeconds(), 1e-9);
        long[] buckets = d.getBucketCounts();
        assertEquals(Timer.BUCKETS_SECONDS.size() + 1, buckets.length);
        assertEquals(0, buckets[0], "le 0.001");
        assertEquals(1, buckets[1], "le 0.0025: 2 ms is here");
        assertEquals(1, buckets[12], "le 10");
        assertEquals(1, buckets[13], "le 30");
        assertEquals(2, buckets[14], "le 60: 40 s is here");
        assertEquals(2, buckets[15], "+Inf is the count");
        assertEquals(List.of(), s.get(4).getSeries(), "nothing folded");
        assertEquals(0, s.get(5).getSeries().get(0).getCount());
        assertEquals(0, r.labelFolds());
        assertEquals(4, r.size());
    }
}
