/*
 * PingFederate's tracking id, read on request threads and supplied on our own.
 */
package com.pingidentity.ps.oidf.pf;

import java.util.UUID;
import org.apache.logging.log4j.ThreadContext;

/**
 * PingFederate puts a {@code trackingid} in the log4j2 ThreadContext of every request thread, and its
 * {@code server.log} and {@code audit.log} patterns print it ({@code %X{trackingid}}). That is how a
 * support engineer follows one request through every log line.
 *
 * <p>Lines written on this module's own threads - the subordinate refresher, the registration sweeper -
 * have no request, so {@link #decorate} gives each run a generated id with a recognisable prefix. The key
 * is read through log4j's public ThreadContext, not PF's internal {@code TrackingIdSupport} class.
 */
public final class PfTracking {
    /** The MDC key PingFederate's log patterns print. */
    public static final String TRACKING_ID_KEY = "trackingid";

    private PfTracking() {
    }

    /** The current thread's tracking id, or {@code null} off a request thread. */
    public static String trackingId() {
        try {
            String id = ThreadContext.get(TRACKING_ID_KEY);
            return id == null || id.isBlank() ? null : id;
        } catch (LinkageError e) {
            return null;
        }
    }

    /** The current tracking id, or a fresh {@code <prefix>-<8 hex>} when there is none. */
    public static String trackingIdOr(String prefix) {
        String id = trackingId();
        return id != null ? id : prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
    }

    /**
     * Wraps {@code work} so each run carries a generated tracking id {@code <prefix>-<8 hex>}, removed again
     * afterwards. For daemon threads, whose lines would otherwise have no tracking id at all.
     */
    public static Runnable decorate(String prefix, Runnable work) {
        return () -> {
            String previous = trackingId();
            boolean set = false;
            try {
                ThreadContext.put(TRACKING_ID_KEY, prefix + "-" + UUID.randomUUID().toString().substring(0, 8));
                set = true;
            } catch (LinkageError ignored) {
                // No log4j on this classpath: run without a tracking id rather than not at all.
            }
            try {
                work.run();
            } finally {
                if (set) {
                    if (previous == null) {
                        ThreadContext.remove(TRACKING_ID_KEY);
                    } else {
                        ThreadContext.put(TRACKING_ID_KEY, previous);
                    }
                }
            }
        };
    }
}
