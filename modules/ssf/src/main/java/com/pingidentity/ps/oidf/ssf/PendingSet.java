/*
 * A signed SET queued for delivery to one stream (poll queue / push retry queue).
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.Objects;

/**
 * One signed Security Event Token awaiting delivery on a specific stream. Poll streams hold these until the
 * receiver acks them (RFC 8936); push streams hold them across retry/backoff until a successful POST
 * (RFC 8935). {@code deliveryAttempts} and {@code nextAttemptAt} drive push backoff; {@code expiresAt} lets the
 * store evict SETs older than {@code setTtlSeconds}.
 *
 * <p>Immutable; the store replaces the entry (via {@link #withAttempt}) rather than mutating in place.
 */
public final class PendingSet {

    private final String jti;
    private final String streamId;
    private final String subjectKey;
    private final String eventType;
    private final String setJws;
    private final long issuedAt;
    private final long expiresAt;
    private final int deliveryAttempts;
    private final long nextAttemptAt;

    public PendingSet(String jti, String streamId, String subjectKey, String eventType, String setJws,
                      long issuedAt, long expiresAt, int deliveryAttempts, long nextAttemptAt) {
        this.jti = Objects.requireNonNull(jti, "jti");
        this.streamId = Objects.requireNonNull(streamId, "streamId");
        this.subjectKey = subjectKey;
        this.eventType = eventType;
        this.setJws = Objects.requireNonNull(setJws, "setJws");
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
        this.deliveryAttempts = deliveryAttempts;
        this.nextAttemptAt = nextAttemptAt;
    }

    /** Newly minted SET, not yet attempted. */
    public static PendingSet fresh(String jti, String streamId, String subjectKey, String eventType,
                                   String setJws, long issuedAt, long expiresAt) {
        return new PendingSet(jti, streamId, subjectKey, eventType, setJws, issuedAt, expiresAt, 0, issuedAt);
    }

    /** Copy recording another failed delivery attempt and the next eligible attempt time. */
    public PendingSet withAttempt(long nextAttemptAt) {
        return new PendingSet(this.jti, this.streamId, this.subjectKey, this.eventType, this.setJws,
                this.issuedAt, this.expiresAt, this.deliveryAttempts + 1, nextAttemptAt);
    }

    public String jti() {
        return this.jti;
    }

    public String streamId() {
        return this.streamId;
    }

    public String subjectKey() {
        return this.subjectKey;
    }

    public String eventType() {
        return this.eventType;
    }

    public String setJws() {
        return this.setJws;
    }

    public long issuedAt() {
        return this.issuedAt;
    }

    public long expiresAt() {
        return this.expiresAt;
    }

    public int deliveryAttempts() {
        return this.deliveryAttempts;
    }

    public long nextAttemptAt() {
        return this.nextAttemptAt;
    }
}
