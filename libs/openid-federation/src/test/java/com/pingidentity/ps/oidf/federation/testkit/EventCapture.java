/*
 * Captures federation events for assertions.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import com.pingidentity.ps.oidf.federation.event.FederationEvent;
import com.pingidentity.ps.oidf.federation.event.FederationEventSink;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import com.pingidentity.ps.oidf.federation.event.LoggingEventSink;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A {@link FederationEventSink} that keeps every event, plus the assertions every logging test makes: no
 * token and no stack trace ever reaches a recorded line.
 *
 * <p>{@link #install()} replaces the process sink for the duration of a test; {@link #close()} resets it.
 */
public final class EventCapture implements FederationEventSink, AutoCloseable {
    private static final Pattern COMPACT_JWT = Pattern.compile("eyJ[A-Za-z0-9_-]{2,}\\.[A-Za-z0-9_-]+\\.");

    private final List<FederationEvent> events = java.util.Collections.synchronizedList(new ArrayList<>());

    /** Installs a fresh capture as the process sink. */
    public static EventCapture install() {
        EventCapture capture = new EventCapture();
        FederationEvents.reset();
        FederationEvents.configure(capture);
        return capture;
    }

    @Override
    public void emit(FederationEvent event) {
        this.events.add(event);
    }

    public List<FederationEvent> events() {
        synchronized (this.events) {
            return List.copyOf(this.events);
        }
    }

    public List<FederationEvent> withCode(String code) {
        return this.events().stream().filter(e -> e.code().equals(code)).toList();
    }

    /** The single event with {@code code}; fails when there is none or more than one. */
    public FederationEvent only(String code) {
        List<FederationEvent> matching = this.withCode(code);
        if (matching.size() != 1) {
            throw new AssertionError("expected exactly one " + code + " event, got " + matching.size() + ": " + this.codes());
        }
        return matching.get(0);
    }

    public List<String> codes() {
        return this.events().stream().map(FederationEvent::code).toList();
    }

    /** Fails if any rendered event line carries something shaped like a compact JWT. */
    public void assertNoJwtIn() {
        for (FederationEvent event : this.events()) {
            String line = LoggingEventSink.format(event);
            if (COMPACT_JWT.matcher(line).find()) {
                throw new AssertionError("event line carries a token: " + line);
            }
        }
    }

    /** Fails if any rendered event line carries a stack frame. */
    public void assertNoStackTraceIn() {
        for (FederationEvent event : this.events()) {
            String line = LoggingEventSink.format(event);
            if (line.contains("\tat ") || line.contains("Exception:") && line.contains("at com.")) {
                throw new AssertionError("event line carries a stack trace: " + line);
            }
        }
    }

    public void clear() {
        this.events.clear();
    }

    @Override
    public void close() {
        FederationEvents.reset();
    }
}
