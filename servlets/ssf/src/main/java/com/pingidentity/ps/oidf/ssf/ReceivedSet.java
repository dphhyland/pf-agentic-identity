/*
 * A verified, parsed inbound Security Event Token (receiver side).
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * The receiver-side counterpart of {@link SecurityEventToken}: an inbound SET that has passed signature and
 * claim verification. Carries the claims a handler needs to act — issuer, {@code jti}, {@code iat}, the
 * subject ({@code sub_id}, may be absent e.g. for verification events), and the {@code events} map keyed by
 * event-type URI.
 */
public final class ReceivedSet {

    private final String issuer;
    private final String jti;
    private final long issuedAt;
    private final SubjectId subjectId;
    private final Map<String, Object> events;
    private final String rawJws;

    public ReceivedSet(String issuer, String jti, long issuedAt, SubjectId subjectId,
                       Map<String, Object> events, String rawJws) {
        this.issuer = Objects.requireNonNull(issuer, "issuer");
        this.jti = Objects.requireNonNull(jti, "jti");
        this.issuedAt = issuedAt;
        this.subjectId = subjectId;
        this.events = events != null ? Map.copyOf(events) : Map.of();
        this.rawJws = rawJws;
    }

    public String issuer() {
        return this.issuer;
    }

    public String jti() {
        return this.jti;
    }

    public long issuedAt() {
        return this.issuedAt;
    }

    /** May be null — verification events carry no subject. */
    public SubjectId subjectId() {
        return this.subjectId;
    }

    /** The {@code events} claim: event-type URI → event payload object. */
    public Map<String, Object> events() {
        return this.events;
    }

    public boolean hasEvent(String eventTypeUri) {
        return this.events.containsKey(eventTypeUri);
    }

    /** The event payload for a type URI (empty map if the payload is not an object). */
    @SuppressWarnings("unchecked")
    public Map<String, Object> eventPayload(String eventTypeUri) {
        Object p = this.events.get(eventTypeUri);
        return p instanceof Map ? (Map<String, Object>) p : new LinkedHashMap<>();
    }

    public String rawJws() {
        return this.rawJws;
    }
}
