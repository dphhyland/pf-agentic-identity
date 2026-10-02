/*
 * One MXBean per copy, under a name no other copy has, registered once and unregistered through the lifecycle.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.security.CodeSource;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.management.JMX;
import javax.management.MBeanServer;
import javax.management.MBeanServerFactory;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeData;
import javax.management.openmbean.TabularData;
import org.junit.jupiter.api.Test;

class MXBeanRegistrationTest {

    private static final String PKG = "com.pingidentity.ps.oidf.platform.metrics";

    /** What a lifecycle was handed. */
    private final List<AutoCloseable> closes = new ArrayList<>();

    private static CodeSource at(String url) throws Exception {
        return new CodeSource(new URL(url), (Certificate[]) null);
    }

    private MXBeanRegistration registration(MBeanServer server, MetricRegistry registry, String copy, boolean shutDown) {
        return new MXBeanRegistration(() -> server, new MetricsView(registry, copy), copy, () -> shutDown, (n, c) -> this.closes.add(c));
    }

    @Test
    void theWebappTheEngineEachPluginAndAnotherWarAreNamedApart() throws Exception {
        ClassLoader loader = getClass().getClassLoader();
        String webapp = MXBeanRegistration.copyOf(PKG, at("file:/opt/out/instance/server/default/deploy2/pf-runtime.war/WEB-INF/lib/platform-0.5.0.jar"), loader);
        String engine = MXBeanRegistration.copyOf(PKG, at("file:/opt/out/instance/server/default/deploy/platform-0.5.0.jar"), loader);
        String plugin = MXBeanRegistration.copyOf("com.pingidentity.ps.oidf.rar.plugin.shaded.platform.metrics",
                at("file:/opt/out/instance/server/default/deploy/rar-paz-plugin-0.5.0.jar"), loader);
        String gmApi = MXBeanRegistration.copyOf(PKG, at("file:/opt/out/instance/server/default/deploy2/gm-api.war/WEB-INF/lib/platform-0.5.0.jar"), loader);
        assertEquals(PKG + " from file:/opt/out/instance/server/default/deploy/platform-0.5.0.jar", engine);
        Set<ObjectName> names = Set.of(MXBeanRegistration.objectName(webapp, 1), MXBeanRegistration.objectName(engine, 1),
                MXBeanRegistration.objectName(plugin, 1), MXBeanRegistration.objectName(gmApi, 1));
        assertEquals(4, names.size());
        for (ObjectName n : names) {
            assertEquals("com.pingidentity.ps.oidf", n.getDomain());
            assertEquals("Metrics", n.getKeyProperty("type"));
        }
        assertEquals(engine, ObjectName.unquote(MXBeanRegistration.objectName(engine, 1).getKeyProperty("copy")));
        assertEquals(engine + " #2", ObjectName.unquote(MXBeanRegistration.objectName(engine, 2).getKeyProperty("copy")));
    }

    @Test
    void aLoaderThatDoesNotSayWhereItLoadedFromIsNamedByIdentity() throws Exception {
        ClassLoader loader = new ClassLoader(null) { };
        String copy = MXBeanRegistration.copyOf(PKG, new CodeSource(null, (Certificate[]) null), loader);
        assertEquals(PKG + " from " + loader.getClass().getName() + "@" + Integer.toHexString(System.identityHashCode(loader)), copy);
        assertEquals(copy, MXBeanRegistration.copyOf(PKG, null, loader));
        assertEquals(PKG + " from the bootstrap loader", MXBeanRegistration.copyOf(PKG, null, null));
        assertNotEquals(copy, MXBeanRegistration.copyOf(PKG, null, new ClassLoader(null) { }));
    }

    @Test
    void registersOnceAndUnregistersThroughTheLifecycle() throws Exception {
        MBeanServer server = MBeanServerFactory.newMBeanServer();
        MetricRegistry registry = new MetricRegistry();
        MXBeanRegistration reg = registration(server, registry, "copy-a", false);
        ObjectName name = reg.ensure().orElseThrow();
        assertEquals(name, reg.ensure().orElseThrow(), "once");
        assertEquals(1, this.closes.size(), "one close handed to the lifecycle");
        assertTrue(server.isRegistered(name));
        this.closes.get(0).close();
        assertFalse(server.isRegistered(name));
        assertEquals(Optional.empty(), reg.ensure(), "not registered again after shutdown");
        reg.unregister(server, name);
        assertEquals(1, this.closes.size());
    }

    @Test
    void twoCopiesFromTheSamePlaceGetTwoNamesAndNeitherFailsTheOther() throws Exception {
        MBeanServer server = MBeanServerFactory.newMBeanServer();
        MXBeanRegistration a = registration(server, new MetricRegistry(), "same place", false);
        MXBeanRegistration b = registration(server, new MetricRegistry(), "same place", false);
        ObjectName na = a.ensure().orElseThrow();
        ObjectName nb = b.ensure().orElseThrow();
        assertEquals("same place", ObjectName.unquote(na.getKeyProperty("copy")));
        assertEquals("same place #2", ObjectName.unquote(nb.getKeyProperty("copy")));
        this.closes.get(0).close();
        assertFalse(server.isRegistered(na));
        assertTrue(server.isRegistered(nb), "closing one leaves the other");
    }

    @Test
    void whenEveryNameIsTakenTheMetricsStillWork() throws Exception {
        MBeanServer server = MBeanServerFactory.newMBeanServer();
        for (int i = 0; i < MXBeanRegistration.MAX_ATTEMPTS; i++) {
            registration(server, new MetricRegistry(), "crowded", false).ensure().orElseThrow();
        }
        this.closes.clear();
        MXBeanRegistration last = registration(server, new MetricRegistry(), "crowded", false);
        assertEquals(Optional.empty(), last.ensure());
        assertEquals(Optional.empty(), last.ensure(), "not retried");
        assertTrue(this.closes.isEmpty());
        assertNull(MXBeanRegistration.register(server, new MetricsView(new MetricRegistry(), "crowded"), "crowded"));
    }

    @Test
    void nothingIsRegisteredOnceTheLifecycleHasShutDownOrWhenJmxFails() {
        MBeanServer server = MBeanServerFactory.newMBeanServer();
        MXBeanRegistration late = registration(server, new MetricRegistry(), "late", true);
        assertEquals(Optional.empty(), late.ensure());
        assertEquals(0, server.queryNames(null, null).stream().filter(n -> n.getDomain().equals("com.pingidentity.ps.oidf")).count());
        MXBeanRegistration broken = new MXBeanRegistration(() -> {
            throw new SecurityException("no JMX here");
        }, new MetricsView(new MetricRegistry(), "broken"), "broken", () -> false, (n, c) -> this.closes.add(c));
        assertEquals(Optional.empty(), broken.ensure());
        assertEquals(Optional.empty(), broken.ensure());
        assertTrue(this.closes.isEmpty());
    }

    @Test
    void jmxShowsOpenTypesAndAProxyRebuildsTheSnapshot() throws Exception {
        MBeanServer server = MBeanServerFactory.newMBeanServer();
        MetricRegistry registry = new MetricRegistry();
        registry.counter("oidf_test_total", "h", Label.oneOf("o", "ok")).inc("ok");
        registry.timer("oidf_test_seconds", "h").recordNanos(2_000_000);
        registry.counter("oidf_fold_total", "h", Label.oneOf("o", "ok")).inc("no");
        ObjectName name = registration(server, registry, "jmx", false).ensure().orElseThrow();
        assertEquals("jmx", server.getAttribute(name, "Copy"));
        assertEquals("UNKNOWN", server.getAttribute(name, "LoaderRole"));
        assertEquals(3, server.getAttribute(name, "MetricCount"));
        assertEquals(3, server.getAttribute(name, "SeriesCount"));
        assertEquals(1L, server.getAttribute(name, "LabelFolds"));
        assertEquals(0L, server.getAttribute(name, "RefusedRegistrations"));
        assertArrayEquals(Timer.BUCKETS_SECONDS.stream().mapToDouble(Double::doubleValue).toArray(),
                (double[]) server.getAttribute(name, "TimerBucketsSeconds"));
        CompositeData[] metrics = (CompositeData[]) server.getAttribute(name, "Metrics");
        assertEquals("oidf_fold_total", metrics[0].get("name"));
        assertEquals("COUNTER", metrics[0].get("kind"));
        TabularData samples = (TabularData) server.getAttribute(name, "Samples");
        assertEquals(1.0, samples.get(new Object[] {"oidf_test_total{o=\"ok\"}"}).get("value"));

        MetricsMXBean proxy = JMX.newMXBeanProxy(server, name, MetricsMXBean.class);
        List<MetricSnapshot> rebuilt = proxy.getMetrics();
        MetricSnapshot timer = rebuilt.stream().filter(m -> m.getName().equals("oidf_test_seconds")).findFirst().orElseThrow();
        assertEquals(Kind.TIMER, timer.getKind());
        assertEquals(1, timer.getSeries().get(0).getCount());
        assertEquals(0.002, timer.getSeries().get(0).getSumSeconds(), 1e-12);
        assertEquals(1, timer.getSeries().get(0).getBucketCounts()[1]);
        Map<String, Double> flat = proxy.getSamples();
        assertEquals(1.0, flat.get("oidf_metrics_label_folds_total{metric=\"oidf_fold_total\"}"));
    }
}
