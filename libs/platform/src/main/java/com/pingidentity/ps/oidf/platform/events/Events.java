/*
 * This loader's event sink.
 */
package com.pingidentity.ps.oidf.platform.events;

import com.pingidentity.ps.oidf.platform.log.PlatformLog;

/**
 * Holds the one {@link EventSink} of the loader this copy of platform was loaded by, and hands it every event.
 *
 * <p>The first {@link #configure} wins and a later one is ignored, because the servlets, the filters and the OGNL
 * helpers all reach for the sink and the order they initialise in is not under anyone's control. Until something
 * configures one, events go to a {@link LoggingSink}. Statics are per loader: the engine loader (OGNL issuance
 * criteria) and the webapp loader each hold their own copy of this class, and each configures its own sink
 * (docs/development/classloaders.md).
 *
 * <p>{@link #emit} admits the event through this loader's catalogues first ({@link EventCatalogues#admit}), so no
 * sink - a test's capture included - is handed a field the event's code does not declare.
 */
public final class Events {
    private static final PlatformLog LOG = PlatformLog.get(Events.class);
    private static final Object LOCK = new Object();
    private static volatile EventSink sink;
    private static volatile boolean configured;

    private Events() {
    }

    /** Installs the sink for this loader. The first call wins; later calls are ignored (a different sink at DEBUG). */
    public static void configure(EventSink newSink) {
        synchronized (LOCK) {
            if (configured) {
                if (newSink != sink) {
                    LOG.debug("The event sink is already configured; a second configuration was ignored");
                }
                return;
            }
            sink = newSink;
            configured = true;
        }
    }

    /** True once {@link #configure} has installed a sink. */
    public static boolean isConfigured() {
        return configured;
    }

    /** The sink events currently go to. */
    public static EventSink sink() {
        EventSink local = sink;
        return local != null ? local : defaultSink();
    }

    private static EventSink defaultSink() {
        synchronized (LOCK) {
            if (sink == null) {
                sink = new LoggingSink();
            }
            return sink;
        }
    }

    /** Admits {@code event} through this loader's catalogues and hands it to the sink; never throws. */
    public static void emit(Event event) {
        if (event == null) {
            return;
        }
        try {
            sink().emit(EventCatalogues.current().admit(event));
        } catch (RuntimeException ignored) {
            // A failing sink never fails the request the event describes.
        }
    }

    /** Starts an event of {@code code} for {@code component}; see {@link Event#builder}. */
    public static Event.Builder event(String component, String code) {
        return Event.builder(component, code);
    }

    /** Tests only: forget the configured sink, so the next {@link #configure} wins, and the loaded catalogues. */
    public static void reset() {
        synchronized (LOCK) {
            sink = null;
            configured = false;
        }
        EventCatalogues.forget();
    }
}
