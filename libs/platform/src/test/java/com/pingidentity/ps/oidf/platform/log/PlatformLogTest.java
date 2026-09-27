/*
 * Platform logs through commons-logging where it can, and loads and logs where it cannot.
 */
package com.pingidentity.ps.oidf.platform.log;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;

class PlatformLogTest {

    /** Records what reaches a java.util.logging logger, where both routes end up on a test classpath without log4j. */
    private static final class Capture extends Handler {
        final List<LogRecord> records = new ArrayList<>();

        @Override
        public void publish(LogRecord record) {
            this.records.add(record);
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }

    /** A loader that says which classes it has loaded. */
    private static final class Bare extends URLClassLoader {
        Bare(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        boolean loaded(String name) {
            return findLoadedClass(name) != null;
        }
    }

    private static Capture capture(String name) {
        Logger jul = Logger.getLogger(name);
        jul.setUseParentHandlers(false);
        jul.setLevel(Level.ALL);
        Capture c = new Capture();
        jul.addHandler(c);
        return c;
    }

    private static void writeEveryLevel(PlatformLog log, RuntimeException boom) {
        log.debug("d");
        log.info("i");
        log.warn("w");
        log.warn("w2", boom);
        log.error("e", boom);
    }

    @Test
    void commonsLoggingIsChosenWhereTheLoaderCanSeeIt() {
        assertTrue(PlatformLog.commonsLoggingVisible(PlatformLog.class.getClassLoader()), "provided scope puts it on the test classpath");
        assertTrue(PlatformLog.viaCommonsLogging());
        assertFalse(PlatformLog.commonsLoggingVisible(new URLClassLoader(new URL[0], null)), "the bootstrap loader has no commons-logging");
    }

    /** commons-logging 1.1.1 with no log4j beside it writes to java.util.logging, so the capture sees its lines. */
    @Test
    void theCommonsRouteWritesEveryLevel() {
        String name = "platform.test.commons";
        Capture c = capture(name);
        PlatformLog log = PlatformLog.of(name, true);
        assertTrue(log.isDebugEnabled());
        RuntimeException boom = new IllegalStateException("boom");
        writeEveryLevel(log, boom);
        assertEquals(List.of(Level.FINE, Level.INFO, Level.WARNING, Level.WARNING, Level.SEVERE),
                c.records.stream().map(LogRecord::getLevel).toList());
        assertEquals(List.of("d", "i", "w", "w2", "e"), c.records.stream().map(LogRecord::getMessage).toList());
        assertNull(c.records.get(2).getThrown());
        assertSame(boom, c.records.get(4).getThrown());
    }

    @Test
    void theJdkRouteWritesEveryLevelThroughSystemLogger() {
        String name = "platform.test.jdk";
        Capture c = capture(name);
        PlatformLog log = PlatformLog.of(name, false);
        assertTrue(log.isDebugEnabled());
        RuntimeException boom = new IllegalStateException("boom");
        writeEveryLevel(log, boom);
        assertEquals(List.of(Level.FINE, Level.INFO, Level.WARNING, Level.WARNING, Level.SEVERE),
                c.records.stream().map(LogRecord::getLevel).toList());
        assertNull(c.records.get(1).getThrown());
        assertSame(boom, c.records.get(3).getThrown());
        Logger.getLogger(name).setLevel(Level.INFO);
        assertFalse(log.isDebugEnabled());
    }

    /**
     * The jar needs nothing but the JDK: loaded by a loader that cannot see commons-logging, platform chooses
     * System.Logger, logs, and never links the commons-logging sink.
     */
    @Test
    void aLoaderWithoutCommonsLoggingStillLoadsAndLogs() throws Exception {
        URL classes = PlatformLog.class.getProtectionDomain().getCodeSource().getLocation();
        try (Bare bare = new Bare(new URL[] {classes}, ClassLoader.getPlatformClassLoader())) {
            Class<?> copy = bare.loadClass(PlatformLog.class.getName());
            assertFalse((Boolean) copy.getMethod("viaCommonsLogging").invoke(null));
            Object log = copy.getMethod("get", Class.class).invoke(null, copy);
            Method warn = copy.getMethod("warn", String.class, Throwable.class);
            warn.invoke(log, "logged by a copy with no commons-logging", new IllegalStateException("expected in this test"));
            Class<?> lifecycle = bare.loadClass("com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle");
            Object current = lifecycle.getMethod("current").invoke(null);
            lifecycle.getMethod("register", String.class, AutoCloseable.class).invoke(current, "noop", (AutoCloseable) () -> { });
            assertEquals(1, ((List<?>) lifecycle.getMethod("shutdown").invoke(current)).size());
            assertTrue(bare.loaded(PlatformLog.class.getName()));
            assertFalse(bare.loaded("com.pingidentity.ps.oidf.platform.log.CommonsLoggingSink"));
        }
    }
}
