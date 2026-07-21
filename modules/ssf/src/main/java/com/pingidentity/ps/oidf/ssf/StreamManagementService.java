/*
 * SSF 1.0 Stream Management + poll delivery core (transport-free, so it unit-tests without a servlet).
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.lang.JoseException;

/**
 * The behaviour behind the SSF stream servlets: stream CRUD and status (SSF §Stream Configuration/Status),
 * subject add/remove, the verification event (SSF §Verification), and poll delivery/ack (RFC 8936). Operates
 * on an {@link SsfStore} + {@link SetMinter}; the servlets are thin HTTP adapters over this, and it is tested
 * directly. All stream configs are returned/accepted as JSON-shaped {@code Map}s.
 */
public final class StreamManagementService {

    /** A requested stream/subject/event that does not exist — servlets map to 404. */
    public static final class NotFoundException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public NotFoundException(String message) {
            super(message);
        }
    }

    private final SsfStore store;
    private final SetMinter minter;
    private final SsfConfiguration config;
    private final SetPublisher publisher;

    public StreamManagementService(SsfStore store, SetMinter minter, SsfConfiguration config) {
        this(store, minter, config, SetPublisher.NOOP);
    }

    public StreamManagementService(SsfStore store, SetMinter minter, SsfConfiguration config, SetPublisher publisher) {
        this.store = store;
        this.minter = minter;
        this.config = config;
        this.publisher = publisher != null ? publisher : SetPublisher.NOOP;
    }

    // ─────────────────────────────── stream CRUD ───────────────────────────────

    /** Create a stream from an SSF stream-configuration request body. Returns the stored config as JSON. */
    public Map<String, Object> createStream(Map<String, Object> body) {
        DeliveryMethod method = parseDeliveryMethod(body);
        String audience = requireString(body, "aud");
        List<String> requested = parseEvents(body.get("events_requested"));
        List<String> delivered = narrowToDeliverable(requested);
        long now = SetMinter.nowSeconds();

        Stream.Builder b = Stream.builder()
                .id(UUID.randomUUID().toString())
                .audience(audience)
                .deliveryMethod(method)
                .eventsRequested(requested)
                .eventsDelivered(delivered)
                .status(StreamStatus.ENABLED)
                .createdAt(now)
                .updatedAt(now);
        if (method == DeliveryMethod.PUSH) {
            Map<String, Object> delivery = asMap(body.get("delivery"));
            b.pushEndpointUrl(requireString(delivery, "endpoint_url"));
            b.pushAuthorizationHeader(optString(delivery, "authorization_header"));
        }
        Stream stream = this.store.createStream(b.build());
        return streamToJson(stream);
    }

    public Map<String, Object> getStream(String streamId) {
        return streamToJson(requireStream(streamId));
    }

    public List<Map<String, Object>> listStreams() {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Stream s : this.store.listStreams()) {
            out.add(streamToJson(s));
        }
        return out;
    }

    /** PATCH: update mutable fields (events_requested, delivery endpoint) of an existing stream. */
    public Map<String, Object> updateStream(String streamId, Map<String, Object> body) {
        Stream existing = requireStream(streamId);
        Stream.Builder b = existing.toBuilder().updatedAt(SetMinter.nowSeconds());
        if (body.containsKey("events_requested")) {
            List<String> requested = parseEvents(body.get("events_requested"));
            b.eventsRequested(requested).eventsDelivered(narrowToDeliverable(requested));
        }
        if (body.containsKey("delivery")) {
            Map<String, Object> delivery = asMap(body.get("delivery"));
            String url = optString(delivery, "endpoint_url");
            if (url != null) {
                b.pushEndpointUrl(url);
            }
            String auth = optString(delivery, "authorization_header");
            if (auth != null) {
                b.pushAuthorizationHeader(auth);
            }
        }
        return streamToJson(this.store.updateStream(b.build()));
    }

    public void deleteStream(String streamId) {
        if (!this.store.deleteStream(streamId)) {
            throw new NotFoundException("no such stream: " + streamId);
        }
    }

    // ─────────────────────────────── status ───────────────────────────────

    public Map<String, Object> getStatus(String streamId) {
        Stream s = requireStream(streamId);
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("stream_id", s.id());
        m.put("status", s.status().value());
        if (s.statusReason() != null) {
            m.put("reason", s.statusReason());
        }
        return m;
    }

    /** Set stream status (enabled/paused/disabled) per SSF §Updating a Stream's Status. */
    public Map<String, Object> setStatus(String streamId, String status, String reason) {
        Stream s = requireStream(streamId);
        StreamStatus next = StreamStatus.fromValue(status);
        this.store.updateStream(s.withStatus(next, reason, SetMinter.nowSeconds()));
        return getStatus(streamId);
    }

    // ─────────────────────────────── subjects ───────────────────────────────

    public void addSubject(String streamId, SubjectId subject) {
        requireStream(streamId);
        this.store.addSubject(streamId, subject);
    }

    public void removeSubject(String streamId, SubjectId subject) {
        requireStream(streamId);
        this.store.removeSubject(streamId, subject);
    }

    // ─────────────────────────────── verification ───────────────────────────────

    /**
     * Emit a verification SET for a stream (SSF §Verification): mint a signed SET carrying the verification
     * event with the receiver's {@code state} echoed, and enqueue it. Poll streams drain it via {@link #poll};
     * push streams via the push executor (later phase). Returns the SET's {@code jti} for correlation.
     */
    public String verify(String streamId, String state) throws JoseException {
        Stream s = requireStream(streamId);
        if (!this.config.verificationEventEnabled()) {
            throw new IllegalStateException("verification events are disabled");
        }
        LinkedHashMap<String, Object> payload = new LinkedHashMap<>();
        if (state != null && !state.isBlank()) {
            payload.put("state", state);
        }
        long now = SetMinter.nowSeconds();
        String jti = SetMinter.newJti();
        SecurityEventToken set = SecurityEventToken.builder()
                .issuer(this.config.issuer())
                .audience(s.audience())
                .jti(jti)
                .issuedAt(now)
                .event(SsfEventTypes.VERIFICATION, payload) // no sub_id — verification carries none
                .build();
        String jws = this.minter.sign(set);
        long expiresAt = this.config.setTtlSeconds() > 0 ? now + this.config.setTtlSeconds() : 0;
        this.store.enqueue(PendingSet.fresh(jti, streamId, null, SsfEventTypes.VERIFICATION, jws, now, expiresAt));
        this.publisher.publish(SsfEventTypes.VERIFICATION, null, jws, now);
        return jti;
    }

    // ─────────────────────────────── poll delivery (RFC 8936) ───────────────────────────────

    /**
     * Poll for pending SETs and ack previously-received ones (RFC 8936). Acked jtis are deleted first, then up
     * to {@code maxEvents} pending SETs are returned as {@code {jti: jws}}. {@code returnImmediately} is honoured
     * trivially here (this store never long-polls). Returns {@code {sets, moreAvailable}}.
     */
    public Map<String, Object> poll(String streamId, List<String> acks, Integer maxEvents, boolean returnImmediately) {
        requireStream(streamId);
        if (acks != null && !acks.isEmpty()) {
            this.store.ack(streamId, acks);
        }
        int cap = maxEvents != null && maxEvents > 0 ? maxEvents : this.config.pollMaxEvents();
        List<PendingSet> pending = this.store.peek(streamId, cap + 1);
        boolean more = pending.size() > cap;
        LinkedHashMap<String, Object> sets = new LinkedHashMap<>();
        int n = Math.min(cap, pending.size());
        for (int i = 0; i < n; i++) {
            sets.put(pending.get(i).jti(), pending.get(i).setJws());
        }
        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        out.put("sets", sets);
        out.put("moreAvailable", more);
        return out;
    }

    // ─────────────────────────────── helpers ───────────────────────────────

    private Stream requireStream(String streamId) {
        return this.store.getStream(streamId)
                .orElseThrow(() -> new NotFoundException("no such stream: " + streamId));
    }

    /** The subset of requested events this transmitter recognises and will deliver. */
    private List<String> narrowToDeliverable(List<String> requested) {
        List<String> delivered = new ArrayList<>();
        for (String e : requested) {
            if (SsfEventTypes.isKnown(e)) {
                delivered.add(e);
            }
        }
        return delivered;
    }

    private Map<String, Object> streamToJson(Stream s) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("stream_id", s.id());
        m.put("iss", this.config.issuer());
        m.put("aud", s.audience());
        m.put("events_requested", s.eventsRequested());
        m.put("events_delivered", s.eventsDelivered());
        LinkedHashMap<String, Object> delivery = new LinkedHashMap<>();
        delivery.put("method", s.deliveryMethod().urn());
        if (s.deliveryMethod() == DeliveryMethod.PUSH) {
            delivery.put("endpoint_url", s.pushEndpointUrl());
        } else {
            // Poll streams are addressed by the transmitter-assigned poll URL (RFC 8936); the receiver
            // POSTs the RFC 8936 body (maxEvents/returnImmediately/ack) there.
            delivery.put("endpoint_url", this.config.issuer() + this.config.basePath() + "/poll?stream_id=" + s.id());
        }
        m.put("delivery", delivery);
        m.put("status", s.status().value());
        return m;
    }

    private static DeliveryMethod parseDeliveryMethod(Map<String, Object> body) {
        Map<String, Object> delivery = asMap(body.get("delivery"));
        return DeliveryMethod.fromUrn(requireString(delivery, "method"));
    }

    private static List<String> parseEvents(Object raw) {
        List<String> out = new ArrayList<>();
        if (raw instanceof Iterable) {
            for (Object e : (Iterable<?>) raw) {
                if (e != null) {
                    out.add(e.toString());
                }
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        if (!(o instanceof Map)) {
            throw new IllegalArgumentException("expected a JSON object");
        }
        return (Map<String, Object>) o;
    }

    private static String requireString(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        if (!(v instanceof String) || ((String) v).isBlank()) {
            throw new IllegalArgumentException("missing required field: " + key);
        }
        return (String) v;
    }

    private static String optString(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v instanceof String && !((String) v).isBlank() ? (String) v : null;
    }
}
