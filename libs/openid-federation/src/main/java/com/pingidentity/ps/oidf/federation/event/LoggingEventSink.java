/*
 * The default event sink: one line per event in the server log - a façade over platform's LoggingSink.
 */
package com.pingidentity.ps.oidf.federation.event;

import com.pingidentity.ps.oidf.platform.events.LoggingSink;
import java.util.Objects;

/**
 * Writes each event as one line in {@code server.log}, through platform's {@link LoggingSink}:
 *
 * <pre>event=federation.registration.created outcome=success subject=https://rp.example partner=https://ta.example type=automatic desc="registered from trust chain"</pre>
 *
 * <p>The logger is {@code com.pingidentity.ps.oidf.federation.event.<category>} - the {@code logger} the
 * federation catalogue names - so an operator can raise or lower one family ({@code ...event.fetch} is chatty)
 * without touching the rest. A failure that belongs in the audit log is written at WARN, a code the catalogue
 * marks {@code debug} (fetches) at DEBUG, everything else at INFO. A field the event's code does not declare is
 * dropped and counted, and every value goes through {@link LogSafe}.
 *
 * @deprecated Use {@link LoggingSink}; plan item O-2 (Phase 3) removes this façade.
 */
@Deprecated(since = "0.5.0", forRemoval = true)
@SuppressWarnings("removal")
public final class LoggingEventSink implements FederationEventSink {
    public static final String LOGGER_PREFIX = "com.pingidentity.ps.oidf.federation.event.";

    private final LoggingSink delegate;

    public LoggingEventSink() {
        this(new LoggingSink());
    }

    LoggingEventSink(LoggingSink delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
    }

    @Override
    public void emit(FederationEvent event) {
        this.delegate.emit(event.toEvent());
    }

    /** The line this sink writes for {@code event}, every field it carries included. */
    public static String format(FederationEvent event) {
        return LoggingSink.format(event.toEvent());
    }
}
