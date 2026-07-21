/*
 * A configured SSF stream (receiver subscription + delivery configuration).
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.List;
import java.util.Objects;

/**
 * An SSF stream: a receiver's subscription to a set of event types, plus how the transmitter delivers them.
 * Immutable — mutations return a copy — so the store can swap references atomically without external locking.
 *
 * <p>{@code audience} is the SET {@code aud}. For {@link DeliveryMethod#PUSH} streams, {@code pushEndpointUrl}
 * and (optionally) {@code pushAuthorizationHeader} carry the receiver's RFC 8935 endpoint and bearer credential.
 * {@code eventsDelivered} is the transmitter-narrowed subset of {@code eventsRequested} it will actually emit.
 */
public final class Stream {

    private final String id;
    private final String audience;
    private final DeliveryMethod deliveryMethod;
    private final String pushEndpointUrl;
    private final String pushAuthorizationHeader;
    private final List<String> eventsRequested;
    private final List<String> eventsDelivered;
    private final StreamStatus status;
    private final String statusReason;
    private final long createdAt;
    private final long updatedAt;

    private Stream(Builder b) {
        this.id = Objects.requireNonNull(b.id, "id");
        this.audience = Objects.requireNonNull(b.audience, "audience");
        this.deliveryMethod = Objects.requireNonNull(b.deliveryMethod, "deliveryMethod");
        this.pushEndpointUrl = b.pushEndpointUrl;
        this.pushAuthorizationHeader = b.pushAuthorizationHeader;
        this.eventsRequested = b.eventsRequested != null ? List.copyOf(b.eventsRequested) : List.of();
        this.eventsDelivered = b.eventsDelivered != null ? List.copyOf(b.eventsDelivered) : this.eventsRequested;
        this.status = b.status != null ? b.status : StreamStatus.ENABLED;
        this.statusReason = b.statusReason;
        this.createdAt = b.createdAt;
        this.updatedAt = b.updatedAt;
        if (this.deliveryMethod == DeliveryMethod.PUSH && (this.pushEndpointUrl == null || this.pushEndpointUrl.isBlank())) {
            throw new IllegalArgumentException("push streams require a delivery endpoint URL");
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Start a builder pre-populated from this stream (for copy-with-change). */
    public Builder toBuilder() {
        return new Builder()
                .id(this.id)
                .audience(this.audience)
                .deliveryMethod(this.deliveryMethod)
                .pushEndpointUrl(this.pushEndpointUrl)
                .pushAuthorizationHeader(this.pushAuthorizationHeader)
                .eventsRequested(this.eventsRequested)
                .eventsDelivered(this.eventsDelivered)
                .status(this.status)
                .statusReason(this.statusReason)
                .createdAt(this.createdAt)
                .updatedAt(this.updatedAt);
    }

    /** Copy with a new status/reason and a bumped {@code updatedAt}. */
    public Stream withStatus(StreamStatus newStatus, String reason, long updatedAt) {
        return toBuilder().status(newStatus).statusReason(reason).updatedAt(updatedAt).build();
    }

    public String id() {
        return this.id;
    }

    public String audience() {
        return this.audience;
    }

    public DeliveryMethod deliveryMethod() {
        return this.deliveryMethod;
    }

    public String pushEndpointUrl() {
        return this.pushEndpointUrl;
    }

    public String pushAuthorizationHeader() {
        return this.pushAuthorizationHeader;
    }

    public List<String> eventsRequested() {
        return this.eventsRequested;
    }

    public List<String> eventsDelivered() {
        return this.eventsDelivered;
    }

    public StreamStatus status() {
        return this.status;
    }

    public String statusReason() {
        return this.statusReason;
    }

    public long createdAt() {
        return this.createdAt;
    }

    public long updatedAt() {
        return this.updatedAt;
    }

    public boolean deliversEvent(String eventType) {
        return this.eventsDelivered.contains(eventType);
    }

    public static final class Builder {
        private String id;
        private String audience;
        private DeliveryMethod deliveryMethod;
        private String pushEndpointUrl;
        private String pushAuthorizationHeader;
        private List<String> eventsRequested;
        private List<String> eventsDelivered;
        private StreamStatus status;
        private String statusReason;
        private long createdAt;
        private long updatedAt;

        public Builder id(String v) {
            this.id = v;
            return this;
        }

        public Builder audience(String v) {
            this.audience = v;
            return this;
        }

        public Builder deliveryMethod(DeliveryMethod v) {
            this.deliveryMethod = v;
            return this;
        }

        public Builder pushEndpointUrl(String v) {
            this.pushEndpointUrl = v;
            return this;
        }

        public Builder pushAuthorizationHeader(String v) {
            this.pushAuthorizationHeader = v;
            return this;
        }

        public Builder eventsRequested(List<String> v) {
            this.eventsRequested = v;
            return this;
        }

        public Builder eventsDelivered(List<String> v) {
            this.eventsDelivered = v;
            return this;
        }

        public Builder status(StreamStatus v) {
            this.status = v;
            return this;
        }

        public Builder statusReason(String v) {
            this.statusReason = v;
            return this;
        }

        public Builder createdAt(long v) {
            this.createdAt = v;
            return this;
        }

        public Builder updatedAt(long v) {
            this.updatedAt = v;
            return this;
        }

        public Stream build() {
            return new Stream(this);
        }
    }
}
