/*
 * The server-side lines that hold a refusal's detail, captured for a test.
 */
package com.pingidentity.ps.oidf.servlet.oauth;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Captures what {@link PublicErrors} and {@code FederationErrors} log while it is open. On the test classpath
 * commons-logging 1.1.1 (PingFederate's) writes through {@code java.util.logging}, so a handler on the two loggers sees
 * every line. Use it in a try-with-resources.
 */
public final class RefusalLog implements AutoCloseable {
    private static final List<String> NAMES = List.of(PublicErrors.class.getName(),
            "com.pingidentity.ps.oidf.servlet.trustanchor.FederationErrors");

    private final List<String> lines = new CopyOnWriteArrayList<>();
    private final Handler handler = new Handler() {
        @Override
        public void publish(LogRecord record) {
            RefusalLog.this.lines.add(record.getMessage());
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    };

    private RefusalLog() {
        for (String name : NAMES) {
            Logger logger = Logger.getLogger(name);
            logger.setLevel(Level.ALL);
            logger.addHandler(this.handler);
        }
    }

    public static RefusalLog open() {
        return new RefusalLog();
    }

    public List<String> lines() {
        return List.copyOf(this.lines);
    }

    /** The last line captured. */
    public String last() {
        assertTrue(!this.lines.isEmpty(), "no refusal was logged");
        return this.lines.get(this.lines.size() - 1);
    }

    /** Asserts the last line holds {@code detail}. */
    public void assertDetail(String detail) {
        String line = this.last();
        assertTrue(line.contains(detail), "the log line holds the detail '" + detail + "': " + line);
    }

    @Override
    public void close() {
        for (String name : NAMES) {
            Logger.getLogger(name).removeHandler(this.handler);
        }
    }
}
