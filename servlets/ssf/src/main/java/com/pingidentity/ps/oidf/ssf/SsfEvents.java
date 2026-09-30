/*
 * The transmitter's own events (plan item O-2): the ssf catalogue, META-INF/oidf-events/ssf.json.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.events.Events;

/**
 * Emits the {@value #COMPONENT} catalogue's events through platform, which counts each one in
 * {@code oidf_events_total} before any sink runs. No field carries a SET, its {@code jti}, its {@code txn}, a subject or
 * a token: {@code event_type} is the event type's last path segment, the rest are this module's own words.
 */
public final class SsfEvents {

    static final String COMPONENT = "ssf";
    static final String SET_EMITTED = "ssf.set.emitted";
    static final String SET_DROPPED = "ssf.set.dropped";
    static final String LOGOUT_REFUSED = "ssf.logout.signal.refused";
    static final String AUDIT_ATTACHED = "ssf.audit.source.attached";
    static final String AUDIT_DETACHED = "ssf.audit.source.detached";

    /** A {@link #SET_DROPPED} reason: the same event type and subject within the bridge's window. */
    public static final String DUPLICATE = "duplicate";
    /** A {@link #SET_DROPPED} reason: the transmitter is not running. */
    public static final String NOT_STARTED = "not_started";
    /** A {@link #SET_DROPPED} reason: minting or queueing threw. */
    public static final String FAILED = "failed";
    /** A {@link #SET_DROPPED} reason: a credential that is not one of CAEP 1.0's registered types. */
    public static final String CREDENTIAL_TYPE = "credential_type";
    /** A {@link #SET_DROPPED} reason: the Kafka side channel failed (the streams have the SET). */
    public static final String KAFKA = "kafka";

    private SsfEvents() {
    }

    /** One SET queued for one stream. */
    static void setEmitted(String eventType) {
        Events.event(COMPONENT, SET_EMITTED).field("event_type", shortName(eventType)).emit();
    }

    /** A PingFederate event that raised no SET, with the {@code source} that saw it (audit, logout, bridge). */
    public static void setDropped(String eventType, String source, String reason) {
        Events.event(COMPONENT, SET_DROPPED).failure(reason).field("event_type", shortName(eventType))
                .field("source", source).emit();
    }

    /** A logout that raised no signal, and why. */
    public static void logoutRefused(String reason) {
        Events.event(COMPONENT, LOGOUT_REFUSED).failure(reason).emit();
    }

    /** The audit source attached to {@code loggers} of PingFederate's audit loggers. */
    public static void auditAttached(int loggers, String trigger) {
        Events.event(COMPONENT, AUDIT_ATTACHED).field("loggers", loggers).field("trigger", trigger).emit();
    }

    /** The audit source detached. */
    public static void auditDetached(String trigger) {
        Events.event(COMPONENT, AUDIT_DETACHED).field("trigger", trigger).emit();
    }

    /** An event type URI's last path segment ({@code session-revoked}); the text itself when it has no slash. */
    static String shortName(String eventType) {
        if (eventType == null) {
            return null;
        }
        int slash = eventType.lastIndexOf('/');
        return slash < 0 ? eventType : eventType.substring(slash + 1);
    }
}
