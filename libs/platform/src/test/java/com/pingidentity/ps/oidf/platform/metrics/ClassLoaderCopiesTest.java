/*
 * Two copies of platform in one JVM each register their own MXBean, and each copy's lifecycle removes only its own.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import java.lang.management.ManagementFactory;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.Duration;
import java.util.Optional;
import javax.management.MBeanServer;
import javax.management.ObjectName;
import org.junit.jupiter.api.Test;

class ClassLoaderCopiesTest {

    /** A copy of platform of its own: its statics, its registry, its lifecycle - as the webapp's and the engine's are. */
    private static URLClassLoader copy() {
        URL classes = Metrics.class.getProtectionDomain().getCodeSource().getLocation();
        return new URLClassLoader(new URL[] {classes}, ClassLoader.getPlatformClassLoader());
    }

    private static Object counter(ClassLoader loader, String name) throws Exception {
        Class<?> metrics = loader.loadClass(Metrics.class.getName());
        Class<?> label = loader.loadClass(Label.class.getName());
        Object labels = java.lang.reflect.Array.newInstance(label, 0);
        return metrics.getMethod("counter", String.class, String.class, labels.getClass()).invoke(null, name, "h", labels);
    }

    @SuppressWarnings("unchecked")
    private static Optional<ObjectName> mxBean(ClassLoader loader) throws Exception {
        return (Optional<ObjectName>) loader.loadClass(Metrics.class.getName()).getMethod("registerMXBean").invoke(null);
    }

    private static void shutdown(ClassLoader loader) throws Exception {
        Class<?> lifecycle = loader.loadClass(Lifecycle.class.getName());
        Object current = lifecycle.getMethod("current").invoke(null);
        lifecycle.getMethod("shutdown", Duration.class).invoke(current, Duration.ofSeconds(5));
    }

    @Test
    void twoLoadersRegisterTwoNamesAndShutDownOnlyTheirOwn() throws Exception {
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        try (URLClassLoader webapp = copy(); URLClassLoader engine = copy()) {
            assertNotEquals(Metrics.class, webapp.loadClass(Metrics.class.getName()), "a separate copy");
            Object c = counter(webapp, "oidf_copies_total");
            c.getClass().getMethod("inc", String[].class).invoke(c, (Object) new String[0]);
            ObjectName webappName = mxBean(webapp).orElseThrow();
            counter(engine, "oidf_copies_total");
            ObjectName engineName = mxBean(engine).orElseThrow();
            assertNotEquals(webappName, engineName, "the same classes directory, so the second takes the next name");
            assertTrue(server.isRegistered(webappName));
            assertTrue(server.isRegistered(engineName));
            assertEquals(1, server.getAttribute(webappName, "MetricCount"));
            assertEquals(1, server.getAttribute(engineName, "MetricCount"));
            assertEquals(1, server.getAttribute(webappName, "SeriesCount"), "the webapp's copy counted once");
            assertEquals(0, server.getAttribute(engineName, "SeriesCount"), "the engine's copy has its own registry");

            shutdown(webapp);
            assertFalse(server.isRegistered(webappName), "the webapp's listener shuts its lifecycle down, which unregisters it");
            assertTrue(server.isRegistered(engineName), "the engine's copy is untouched: nothing shuts it down");
            assertEquals(Optional.empty(), mxBean(webapp), "and a copy that has shut down registers nothing again");
            counter(webapp, "oidf_after_total");
            assertFalse(server.isRegistered(webappName));

            shutdown(engine);
            assertFalse(server.isRegistered(engineName));
        }
    }
}
