/*
 * Two copies of platform in one JVM - the webapp's and another loader's - never run the same job twice, and a copy's
 * lifecycle shutdown stops only its own.
 */
package com.pingidentity.ps.oidf.platform.exec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ExecutorCopiesTest {

    private static final String JOB = "copies-loop";

    /** A copy of platform of its own: its statics, its registry, its lifecycle. */
    private static URLClassLoader copy() {
        URL classes = ManagedExecutors.class.getProtectionDomain().getCodeSource().getLocation();
        return new URLClassLoader(new URL[] {classes}, ClassLoader.getPlatformClassLoader());
    }

    /** {@code ManagedExecutors.every(JOB, 1 h, no-op)} in that copy: whether it started. */
    private static boolean start(ClassLoader loader) throws Exception {
        Class<?> executors = loader.loadClass(ManagedExecutors.class.getName());
        Runnable task = () -> { };
        Optional<?> started = (Optional<?>) executors.getMethod("every", String.class, Duration.class, Runnable.class)
                .invoke(null, JOB, Duration.ofHours(1), task);
        return started.isPresent();
    }

    private static List<?> snapshot(ClassLoader loader) throws Exception {
        return (List<?>) loader.loadClass(ManagedExecutors.class.getName()).getMethod("snapshot").invoke(null);
    }

    private static void shutdown(ClassLoader loader) throws Exception {
        Class<?> lifecycle = loader.loadClass(Lifecycle.class.getName());
        Object current = lifecycle.getMethod("current").invoke(null);
        lifecycle.getMethod("shutdown", Duration.class).invoke(current, Duration.ofSeconds(5));
    }

    @AfterEach
    void tearDown() {
        System.clearProperty(ExecutorRegistry.OWNER_PREFIX + JOB);
    }

    @Test
    void aSecondClassloaderDoesNotStartASecondLoop() throws Exception {
        try (URLClassLoader webapp = copy(); URLClassLoader engine = copy()) {
            assertNotEquals(ManagedExecutors.class, webapp.loadClass(ManagedExecutors.class.getName()), "a separate copy");
            assertTrue(start(webapp));
            String owner = System.getProperty(ExecutorRegistry.OWNER_PREFIX + JOB);
            assertFalse(start(engine), "the job already runs in this JVM, in the other copy");
            assertEquals(1, snapshot(webapp).size());
            assertEquals(0, snapshot(engine).size());
            assertEquals(owner, System.getProperty(ExecutorRegistry.OWNER_PREFIX + JOB), "still the first copy's");

            shutdown(engine);
            assertEquals(1, snapshot(webapp).size(), "the other copy's shutdown stops nothing of this one's");

            shutdown(webapp);
            assertEquals(0, snapshot(webapp).size(), "the lifecycle closes the executors it registered");
            assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + JOB), "and the name is given back");
            assertFalse(start(webapp), "a copy that has shut down starts nothing again");
            assertNull(System.getProperty(ExecutorRegistry.OWNER_PREFIX + JOB));
        }
    }
}
