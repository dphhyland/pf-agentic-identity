/*
 * RFC 8417 Security Event Token (SET) value object, shaped for SSF/CAEP/RISC delivery.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * An unsigned Security Event Token per RFC 8417, carrying exactly one event (the common case for CAEP/RISC
 * transmission). Immutable; build via {@link #builder()} and hand to {@link SetMinter} to produce the signed
 * compact JWS.
 *
 * <p>Claim layout: {@code iss}, {@code aud}, {@code iat}, {@code jti}, top-level {@code sub_id} (SSF places the
 * subject at the token level), and {@code events} keyed by the event-type URI. An optional {@code txn}
 * correlates a batch of related SETs.
 */
public final class SecurityEventToken {

    private final String issuer;
    private final String audience;
    private final String jti;
    private final long issuedAt;
    private final SubjectId subjectId;
    private final String eventType;
    private final Map<String, Object> eventPayload;
    private final String txn;

    private SecurityEventToken(Builder b) {
        this.issuer = Objects.requireNonNull(b.issuer, "iss");
        this.audience = Objects.requireNonNull(b.audience, "aud");
        this.jti = Objects.requireNonNull(b.jti, "jti");
        this.issuedAt = b.issuedAt;
        this.subjectId = Objects.requireNonNull(b.subjectId, "sub_id");
        this.eventType = Objects.requireNonNull(b.eventType, "eventType");
        this.eventPayload = b.eventPayload != null ? Map.copyOf(b.eventPayload) : Map.of();
        this.txn = b.txn;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String issuer() {
        return this.issuer;
    }

    public String audience() {
        return this.audience;
    }

    public String jti() {
        return this.jti;
    }

    public long issuedAt() {
        return this.issuedAt;
    }

    public SubjectId subjectId() {
        return this.subjectId;
    }

    public String eventType() {
        return this.eventType;
    }

    /** The SET as an ordered, JSON-serialisable claims map (RFC 8417). */
    public Map<String, Object> toClaims() {
        LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", this.issuer);
        claims.put("aud", this.audience);
        claims.put("iat", this.issuedAt);
        claims.put("jti", this.jti);
        claims.put("sub_id", this.subjectId.toMap());
        if (this.txn != null && !this.txn.isBlank()) {
            claims.put("txn", this.txn);
        }
        claims.put("events", Map.of(this.eventType, this.eventPayload));
        return claims;
    }

    public static final class Builder {
        private String issuer;
        private String audience;
        private String jti;
        private long issuedAt;
        private SubjectId subjectId;
        private String eventType;
        private Map<String, Object> eventPayload;
        private String txn;

        private Builder() {
        }

        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder audience(String audience) {
            this.audience = audience;
            return this;
        }

        public Builder jti(String jti) {
            this.jti = jti;
            return this;
        }

        public Builder issuedAt(long epochSeconds) {
            this.issuedAt = epochSeconds;
            return this;
        }

        public Builder subjectId(SubjectId subjectId) {
            this.subjectId = subjectId;
            return this;
        }

        /** The single event: its type URI and its (possibly empty) event-specific payload object. */
        public Builder event(String eventType, Map<String, Object> payload) {
            this.eventType = eventType;
            this.eventPayload = payload;
            return this;
        }

        public Builder txn(String txn) {
            this.txn = txn;
            return this;
        }

        public SecurityEventToken build() {
            return new SecurityEventToken(this);
        }
    }
}
