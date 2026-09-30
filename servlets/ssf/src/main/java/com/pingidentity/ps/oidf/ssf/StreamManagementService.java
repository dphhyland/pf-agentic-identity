/*
 * SSF 1.0 Stream Management + poll delivery core (transport-free, so it unit-tests without a servlet).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.events.Events;
import com.pingidentity.ps.oidf.platform.events.LogSafe;
import com.pingidentity.ps.oidf.signals.SecurityEventToken;
import com.pingidentity.ps.oidf.signals.SetMinter;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.lang.JoseException;

/**
 * The behaviour behind the SSF stream servlets: stream CRUD and status (SSF §Stream Configuration/Status),
 * subject add/remove, the verification event (SSF §Verification), and poll delivery/ack (RFC 8936). Operates
 * on an {@link SsfStore} + {@link SetMinter}; the servlets are thin HTTP adapters over this, and it is tested
 * directly. All stream configs are returned/accepted as JSON-shaped {@code Map}s.
 *
 * <p>Every operation takes the receiver it is performed for, and there is deliberately no variant that
 * does not: a stream is visible to the client that created it and to nobody else ({@link StreamAccess}).
 * The caller is an {@link AuthContext} rather than a client id so that it cannot be transposed with the
 * {@code stream_id} or {@code reason} beside it, both of which arrive in the request.
 */
public final class StreamManagementService {

    private static final Log LOGGER = LogFactory.getLog(StreamManagementService.class);

    /**
     * A requested stream/subject/event that does not exist — servlets map to 404. A stream that belongs to
     * another receiver is reported with this exception and this message too, so an id that is taken cannot
     * be told from one that is free.
     */
    public static final class NotFoundException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public NotFoundException(String message) {
            super(message);
        }
    }

    /**
     * The receiver already has as many streams as {@code OIDF_SSF_MAX_STREAMS_PER_CLIENT} allows - servlets map to 409.
     * SSF 1.0 §8.1.1.1 names a status for a transmitter that allows a receiver no second stream: "If the Transmitter
     * does not allow multiple streams with the same Receiver, it MUST respond with HTTP status code "409 Conflict"."
     * It names none for a limit above one, and a cap is that rule with a larger number: a cap of 1 has to answer 409,
     * and the receiver's way out is the same whatever the cap - "The Receiver MAY then GET the existing stream
     * configuration and, if desired, use PATCH or PUT to update or replace the existing stream configuration", or
     * delete one. Not 429, which says waiting helps; it does not.
     */
    public static final class StreamLimitException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public StreamLimitException(String message) {
            super(message);
        }
    }

    /**
     * A verification request sooner than the stream's {@code min_verification_interval} after its last one - servlets
     * map to 429 with {@code Retry-After} (SSF 1.0 §8.1.1 and Table 10). {@link #retryAfterSeconds()} is how long until
     * the next one is accepted, rounded up, and at least 1.
     */
    public static final class TooManyRequestsException extends RuntimeException {
        private static final long serialVersionUID = 1L;
        private final long retryAfterSeconds;

        public TooManyRequestsException(String message, long retryAfterSeconds) {
            super(message);
            this.retryAfterSeconds = retryAfterSeconds;
        }

        public long retryAfterSeconds() {
            return this.retryAfterSeconds;
        }
    }

    /** The receiver is authenticated but may not do this — servlets map to 403. */
    public static final class ForbiddenException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public ForbiddenException(String message) {
            super(message);
        }
    }

    private final SsfStore store;
    private final SetMinter minter;
    private final SsfConfiguration config;
    private final SetPublisher publisher;
    private final OutboundUrlPolicy outboundPolicy;
    private final StreamAccess access;
    private final LongSupplier nowMillis;
    /**
     * When each stream's last accepted verification request came, in epoch milliseconds, for its
     * {@code min_verification_interval}. In memory and per node, which the Phase 3 plan (decision 9) allows a rate
     * limit: counted per node, a receiver spreading its requests over n nodes gets n verifications per interval,
     * which is weaker and not unsafe. A stream's entry goes when the stream is deleted here.
     */
    private final ConcurrentHashMap<String, Long> lastVerification = new ConcurrentHashMap<>();

    /** The longest {@code description} kept; SSF 1.0 §8.1.1: "The transmitter MAY truncate the string beyond an allowed max length." */
    static final int DESCRIPTION_MAX = 1024;

    public StreamManagementService(SsfStore store, SetMinter minter, SsfConfiguration config) {
        this(store, minter, config, SetPublisher.NOOP);
    }

    public StreamManagementService(SsfStore store, SetMinter minter, SsfConfiguration config, SetPublisher publisher) {
        this(store, minter, config, publisher, OutboundUrlPolicy.fromEnvironment());
    }

    /** Test seam: a stubbed-resolver policy, so endpoint screening is exercised without real DNS. */
    public StreamManagementService(SsfStore store, SetMinter minter, SsfConfiguration config, SetPublisher publisher,
            OutboundUrlPolicy outboundPolicy) {
        this(store, minter, config, publisher, outboundPolicy, System::currentTimeMillis);
    }

    /** Test seam: a clock for the verification interval, in epoch milliseconds. */
    StreamManagementService(SsfStore store, SetMinter minter, SsfConfiguration config, SetPublisher publisher,
            OutboundUrlPolicy outboundPolicy, LongSupplier nowMillis) {
        this.nowMillis = nowMillis;
        this.store = store;
        this.minter = minter;
        this.config = config;
        this.publisher = publisher != null ? publisher : SetPublisher.NOOP;
        this.outboundPolicy = outboundPolicy != null ? outboundPolicy : OutboundUrlPolicy.fromEnvironment();
        this.access = new StreamAccess(config);
    }

    /**
     * Screens a receiver-supplied push {@code endpoint_url} before it is ever stored.
     *
     * <p>A push stream is a standing instruction to POST signed events at a URL the <em>receiver</em>
     * chose. Without this, {@code http://169.254.169.254/latest/meta-data/} or
     * {@code http://redis.railway.internal:6379/} is an accepted stream configuration, and the
     * transmitter becomes a request forwarder into its own network — authenticated, but authentication
     * is not authorisation to reach an arbitrary address.
     *
     * <p>Refused at CREATE and PATCH rather than only at delivery: a rejection the caller sees on the
     * API call it just made is actionable, whereas one surfacing later in a background delivery tick is
     * a log line nobody reads. {@code PushDeliveryService} screens again at send time regardless — a
     * stream may have been stored before this existed, or written straight into the store.
     */
    private void requireDeliverableEndpoint(String endpointUrl) {
        try {
            this.outboundPolicy.check(endpointUrl);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("delivery.endpoint_url is not an acceptable push destination: "
                    + e.getMessage(), e);
        }
    }

    // ─────────────────────────────── stream CRUD ───────────────────────────────

    /**
     * Create a stream from an SSF stream-configuration request body. Returns the stored config as JSON.
     *
     * <p>The stream belongs to the client {@code caller}'s token identifies. A token that names no client is
     * refused before anything here reads the body (SSF §8.1.1.1, 403): a stream stored with no owner would
     * be one its own creator could not read or delete, still collecting events.
     *
     * <p>{@code aud} is Transmitter-Supplied (SSF §8.1.1), so a receiver that sends none - as a conformant
     * one does - is assigned that same client id. One that sends {@code aud} is not choosing it: the value
     * is accepted only where it is that client id, or an audience the operator has agreed for that client
     * ({@link SsfConfiguration#allowedAudiences}), and is otherwise a 400. Every SET on the stream is signed
     * to this {@code aud}, so a receiver free to pick it could have SETs minted that another receiver
     * accepts as its own.
     *
     * <p>A body with no {@code delivery} is a poll stream. SSF 1.0 §8.1.1.1: "If the request does not contain the
     * delivery property, then the Transmitter MUST assume that the method is "urn:ietf:rfc:8936" (poll)."
     *
     * <p>The optional members (SSF 1.0 §8.1.1, plan item H-SSF-3): {@code description} is the receiver's, a string,
     * truncated to {@value #DESCRIPTION_MAX} characters; {@code min_verification_interval} and
     * {@code inactivity_timeout} are "Transmitter-Supplied", so what a receiver sends for them here is ignored, as for
     * the other Transmitter-Supplied members, and the stream is given this transmitter's settings.
     *
     * <p>A receiver that already has {@code OIDF_SSF_MAX_STREAMS_PER_CLIENT} streams is refused another
     * ({@link StreamLimitException}, 409). Counted before the insert, so two creates racing past the count can leave
     * the receiver one stream over, on a store no other node is writing to at that moment; the cap bounds what one
     * receiver can make the transmitter hold, which that does not undo.
     */
    public Map<String, Object> createStream(Map<String, Object> body, AuthContext caller) {
        String owner = StreamAccess.clientIdOf(caller);
        if (owner == null) {
            throw new ForbiddenException("the token names no client, so there is nobody for a stream to belong to");
        }
        requireRoomForAnotherStream(owner);
        DeliveryMethod method = body.containsKey("delivery") ? parseDeliveryMethod(body) : DeliveryMethod.POLL;
        String audience = resolveAudience(body, caller, owner);
        List<String> requested = parseEvents(body.get("events_requested"));
        List<String> delivered = narrowToDeliverable(requested);
        long now = SetMinter.nowSeconds();

        Stream.Builder b = Stream.builder()
                .id(UUID.randomUUID().toString())
                .audience(audience)
                .ownerClientId(owner)
                .deliveryMethod(method)
                .eventsRequested(requested)
                .eventsDelivered(delivered)
                .status(StreamStatus.ENABLED)
                .createdAt(now)
                .updatedAt(now)
                .description(parseDescription(body))
                .minVerificationInterval(this.config.minVerificationIntervalSeconds() > 0
                        ? this.config.minVerificationIntervalSeconds() : null)
                .inactivityTimeout(this.config.inactivityTimeoutSeconds() > 0 ? this.config.inactivityTimeoutSeconds() : null);
        if (method == DeliveryMethod.PUSH) {
            Map<String, Object> delivery = asMap(body.get("delivery"));
            String pushUrl = requireString(delivery, "endpoint_url");
            requireDeliverableEndpoint(pushUrl);
            b.pushEndpointUrl(pushUrl);
            b.pushAuthorizationHeader(optString(delivery, "authorization_header"));
        }
        Stream stream = this.store.createStream(b.build());
        return streamToJson(stream);
    }

    public Map<String, Object> getStream(String streamId, AuthContext caller) {
        return streamToJson(requireStream(streamId, caller));
    }

    /** The streams available to this receiver (SSF §8.1.1.2) - its own, which may be none. */
    public List<Map<String, Object>> listStreams(AuthContext caller) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Stream s : this.store.listStreams()) {
            if (this.access.admits(s, caller)) {
                out.add(streamToJson(s));
            }
        }
        return out;
    }

    /**
     * PATCH: update the Receiver-Supplied members the body names (events_requested, the delivery endpoint,
     * description); SSF 1.0 §8.1.1.3: "Any properties missing in the request MUST NOT be changed by the Transmitter."
     * A {@code description} of {@code null} is present, and removes it.
     */
    public Map<String, Object> updateStream(String streamId, Map<String, Object> body, AuthContext caller) {
        Stream existing = requireStream(streamId, caller);
        requireTransmitterSuppliedToMatch(existing, body);
        Stream.Builder b = existing.toBuilder().updatedAt(SetMinter.nowSeconds());
        if (body.containsKey("description")) {
            b.description(parseDescription(body));
        }
        if (body.containsKey("events_requested")) {
            List<String> requested = parseEvents(body.get("events_requested"));
            b.eventsRequested(requested).eventsDelivered(narrowToDeliverable(requested));
        }
        if (body.containsKey("delivery")) {
            Map<String, Object> delivery = asMap(body.get("delivery"));
            String url = optString(delivery, "endpoint_url");
            if (url != null) {
                requireDeliverableEndpoint(url);
                b.pushEndpointUrl(url);
            }
            String auth = optString(delivery, "authorization_header");
            if (auth != null) {
                b.pushAuthorizationHeader(auth);
            }
        }
        return streamToJson(this.store.updateStream(b.build()));
    }

    /**
     * PUT: replace a stream's configuration (SSF §8.1.1.4). Unlike {@link #updateStream}, the body is the
     * whole set of Receiver-Supplied properties, and one that is missing is a request to delete it: no
     * {@code events_requested} leaves the stream delivering nothing, and a push stream replaced without
     * an {@code authorization_header} stops sending one.
     *
     * <p>{@code description} is Receiver-Supplied too, so a PUT without one removes it.
     *
     * <p>{@code delivery} cannot be deleted - a stream with no delivery is not a stream - so its absence
     * is a 400. Nor can its method change here: a receiver moving between push and poll deletes the
     * stream and creates another, which leaves no question about SETs already queued for the old method.
     */
    public Map<String, Object> replaceStream(String streamId, Map<String, Object> body, AuthContext caller) {
        Stream existing = requireStream(streamId, caller);
        requireTransmitterSuppliedToMatch(existing, body);
        if (!body.containsKey("delivery")) {
            throw new IllegalArgumentException("missing required field: delivery");
        }
        DeliveryMethod method = parseDeliveryMethod(body);
        if (method != existing.deliveryMethod()) {
            throw new IllegalArgumentException("delivery.method cannot be replaced; delete the stream and create another");
        }
        List<String> requested = parseEvents(body.get("events_requested"));
        Stream.Builder b = existing.toBuilder()
                .eventsRequested(requested)
                .eventsDelivered(narrowToDeliverable(requested))
                .description(parseDescription(body))
                .updatedAt(SetMinter.nowSeconds());
        if (method == DeliveryMethod.PUSH) {
            Map<String, Object> delivery = asMap(body.get("delivery"));
            String pushUrl = requireString(delivery, "endpoint_url");
            requireDeliverableEndpoint(pushUrl);
            b.pushEndpointUrl(pushUrl);
            b.pushAuthorizationHeader(optString(delivery, "authorization_header"));
        }
        return streamToJson(this.store.updateStream(b.build()));
    }

    public void deleteStream(String streamId, AuthContext caller) {
        requireStream(streamId, caller);
        if (!this.store.deleteStream(streamId)) {
            throw new NotFoundException("no such stream: " + streamId);
        }
        this.lastVerification.remove(streamId);
    }

    // ─────────────────────────────── status ───────────────────────────────

    public Map<String, Object> getStatus(String streamId, AuthContext caller) {
        Stream s = requireStream(streamId, caller);
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("stream_id", s.id());
        m.put("status", s.status().value());
        if (s.statusReason() != null) {
            m.put("reason", s.statusReason());
        }
        return m;
    }

    /** Set stream status (enabled/paused/disabled) per SSF §Updating a Stream's Status. */
    public Map<String, Object> setStatus(String streamId, String status, String reason, AuthContext caller) {
        Stream s = requireStream(streamId, caller);
        StreamStatus next = StreamStatus.fromValue(status);
        this.store.updateStream(s.withStatus(next, reason, SetMinter.nowSeconds()));
        return getStatus(streamId, caller);
    }

    // ─────────────────────────────── subjects ───────────────────────────────

    public void addSubject(String streamId, SubjectId subject, AuthContext caller) {
        requireStream(streamId, caller);
        this.store.addSubject(streamId, subject);
    }

    public void removeSubject(String streamId, SubjectId subject, AuthContext caller) {
        requireStream(streamId, caller);
        this.store.removeSubject(streamId, subject);
    }

    // ─────────────────────────────── verification ───────────────────────────────

    /**
     * Emit a verification SET for a stream (SSF §Verification): mint a signed SET carrying the verification
     * event with the receiver's {@code state} echoed, and enqueue it. Poll streams drain it via {@link #poll};
     * push streams via the push executor (later phase). Returns the SET's {@code jti} for correlation.
     *
     * <p>A request sooner than the stream's {@code min_verification_interval} after the last one accepted is refused
     * with {@link TooManyRequestsException} (429) and nothing is minted. SSF 1.0 §8.1.1: "If an Event Receiver submits
     * verification requests more frequently than this, the Event Transmitter MAY respond with a 429 status code. An
     * Event Transmitter SHOULD NOT respond with a 429 status code if an Event Receiver is not exceeding this
     * frequency." So a request exactly the interval after the last is accepted, and a refused one does not restart
     * the interval.
     */
    public String verify(String streamId, String state, AuthContext caller) throws JoseException {
        Stream s = requireStream(streamId, caller);
        if (!this.config.verificationEventEnabled()) {
            throw new IllegalStateException("verification events are disabled");
        }
        admitVerification(s);
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
                // SSF §8.1.4.1: the subject of a verification event is the stream itself.
                .subjectId(SubjectId.opaque(streamId))
                .event(SsfEventTypes.VERIFICATION, payload)
                .build();
        String jws = this.minter.sign(set);
        long expiresAt = this.config.setTtlSeconds() > 0 ? now + this.config.setTtlSeconds() : 0;
        this.store.enqueue(PendingSet.fresh(jti, streamId, null, SsfEventTypes.VERIFICATION, jws, now, expiresAt));
        this.publisher.publish(SsfEventTypes.VERIFICATION, null, jws, now);
        return jti;
    }

    // ─────────────────────────────── poll delivery (RFC 8936) ───────────────────────────────

    /** One RFC 8936 §2.2 poll request, as the poll endpoint read it. */
    public record PollRequest(List<String> acks, Map<String, Map<String, Object>> setErrs, Integer maxEvents,
            boolean returnImmediately) {
    }

    /**
     * A poll's answer: the RFC 8936 §2.3 body, and how long the endpoint may hold a long poll for more - the
     * configured wait when nothing was returned, SETs were asked for and the stream is enabled, otherwise zero.
     */
    public record Polled(Map<String, Object> body, Duration hold) {
    }

    /** The RFC 8935 §2.4 error codes a {@code setErrs} entry is counted under; any other counts as {@code other}. */
    static final Set<String> SET_ERROR_CODES = Set.of("invalid_request", "invalid_key", "invalid_issuer",
            "invalid_audience", "authentication_failed", "access_denied");

    static final String POLL_EVENTS = "ssf-poll";
    static final String SET_ERROR = "ssf.poll.set_error";

    /**
     * {@link #poll(String, PollRequest, AuthContext)} for a request with no {@code setErrs}; its body.
     */
    public Map<String, Object> poll(String streamId, List<String> acks, Integer maxEvents, boolean returnImmediately,
            AuthContext caller) {
        return poll(streamId, new PollRequest(acks, Map.of(), maxEvents, returnImmediately), caller).body();
    }

    /**
     * Poll for pending SETs and ack previously-received ones (RFC 8936, plan item H-SSF-2). Acked jtis are deleted
     * first, then up to the request's {@code maxEvents} pending SETs are returned as {@code {jti: jws}}, with
     * {@code moreAvailable}.
     *
     * <p>{@code maxEvents} is capped at {@code OIDF_SSF_POLL_MAX_EVENTS_CAP}: RFC 8936 §2.2 has the transmitter
     * "SHOULD NOT send more SETs than the specified maximum" and lets it choose which to return first, and
     * {@code moreAvailable} says there are more. Absent (RFC 8936: "no limit is placed") or negative, it is
     * {@code OIDF_SSF_POLL_MAX_EVENTS}, capped the same way. A {@code maxEvents} of 0 is an acknowledge-only request
     * (RFC 8936 §2.2) and returns no SETs.
     *
     * <p>{@code setErrs} (RFC 8936 §2.2: "A JSON object with one or more members whose keys are the "jti" values of
     * invalid SETs received") is recorded per SET: logged with the receiver's {@code err} and {@code description},
     * counted as an {@value #SET_ERROR} event under the error code, and the SET released as the receiver reported it
     * - removed from the stream's queue like an acknowledged one, since redelivering a SET its receiver cannot
     * validate cannot succeed. The store keeps no record of a SET once released; the dead-letter record is S-10's.
     *
     * <p>A stream that is not enabled returns no SETs. SSF 1.0 §8.1.2.1: for {@code paused}, "The Transmitter MUST NOT
     * transmit events over the stream. The Transmitter SHOULD hold any events it would have transmitted while paused,
     * and SHOULD transmit them when the stream's status becomes "enabled""; for {@code disabled}, "The Transmitter
     * MUST NOT transmit events over the stream and will not hold any events for later transmission". The poll still
     * acknowledges: a receiver that paused its stream can release what it was already given.
     *
     * <p>SETs past {@code setTtlSeconds} are evicted before the queue is read, so none is handed over because
     * the background loop had not reached it yet - or was not running. Evicted rather than skipped: dropping
     * them from the page read would leave {@code moreAvailable} counting SETs that will never be returned,
     * and a queue headed by expired SETs would hide the live ones behind them.
     *
     * <p>The stream is the caller's or the poll goes no further - before the acks, not only before the
     * SETs. Acknowledging is deleting: another receiver's poll would not just read this one's events, it
     * would consume them, and the receiver they were meant for would never learn they had existed.
     */
    public Polled poll(String streamId, PollRequest request, AuthContext caller) {
        Stream stream = requireStream(streamId, caller);
        if (request.acks() != null && !request.acks().isEmpty()) {
            this.store.ack(streamId, request.acks());
        }
        if (request.setErrs() != null && !request.setErrs().isEmpty()) {
            recordSetErrors(streamId, request.setErrs());
        }
        LinkedHashMap<String, Object> sets = new LinkedHashMap<>();
        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        out.put("sets", sets);
        if (stream.status() != StreamStatus.ENABLED) {
            out.put("moreAvailable", false);
            return new Polled(out, Duration.ZERO);
        }
        int asked = request.maxEvents() != null && request.maxEvents() >= 0 ? request.maxEvents()
                : this.config.pollMaxEvents() > 0 ? this.config.pollMaxEvents() : 100;
        int cap = Math.min(asked, this.config.pollMaxEventsCap());
        this.store.evictExpired(SetMinter.nowSeconds());
        List<PendingSet> pending = this.store.peek(streamId, cap + 1);
        boolean more = pending.size() > cap;
        int n = Math.min(cap, pending.size());
        for (int i = 0; i < n; i++) {
            sets.put(pending.get(i).jti(), pending.get(i).setJws());
        }
        out.put("moreAvailable", more);
        return new Polled(out, n == 0 && cap > 0 ? Duration.ofSeconds(this.config.pollLongPollWaitSeconds()) : Duration.ZERO);
    }

    /**
     * Whether the stream has a SET queued: the long poll's cheap check between polls, one row at most. An expired SET
     * counts; the full poll it triggers evicts it and returns nothing, and the poll goes on waiting.
     */
    public boolean hasPending(String streamId) {
        return !this.store.peek(streamId, 1).isEmpty();
    }

    private void recordSetErrors(String streamId, Map<String, Map<String, Object>> setErrs) {
        for (Map.Entry<String, Map<String, Object>> e : setErrs.entrySet()) {
            Object err = e.getValue().get("err");
            String code = err instanceof String && SET_ERROR_CODES.contains(err) ? (String) err : "other";
            Object description = e.getValue().get("description");
            LOGGER.warn((Object) ("SSF poll: the receiver of stream " + streamId + " reported SET " + LogSafe.value(e.getKey())
                    + " invalid (" + code + (description instanceof String ? ": " + LogSafe.value((String) description) : "")
                    + "); released"));
            Events.event(POLL_EVENTS, SET_ERROR).failure(code).emit();
        }
        this.store.ack(streamId, setErrs.keySet());
    }

    // ─────────────────────────────── helpers ───────────────────────────────

    /** Refuses a create that would take {@code owner} past {@code OIDF_SSF_MAX_STREAMS_PER_CLIENT} streams. */
    private void requireRoomForAnotherStream(String owner) {
        int max = this.config.maxStreamsPerClient();
        int held = 0;
        for (Stream s : this.store.listStreams()) {
            if (owner.equals(s.ownerClientId())) {
                held++;
            }
        }
        if (held >= max) {
            throw new StreamLimitException("this receiver already has " + held + " streams, the most this transmitter "
                    + "allows one receiver (" + max + "); delete one, or update or replace an existing stream");
        }
    }

    /**
     * Records this verification request as the stream's last, or refuses it if it comes within the stream's
     * interval of the last one. Atomic per stream: two requests arriving together cannot both be admitted.
     */
    private void admitVerification(Stream s) {
        Integer interval = effectiveMinVerificationInterval(s);
        if (interval == null) {
            return;
        }
        long now = this.nowMillis.getAsLong();
        long intervalMillis = interval * 1000L;
        long[] wait = {0};
        this.lastVerification.compute(s.id(), (id, last) -> {
            if (last != null && now - last < intervalMillis) {
                wait[0] = last + intervalMillis - now;
                return last;
            }
            return now;
        });
        if (wait[0] > 0) {
            long seconds = Math.max(1, (wait[0] + 999) / 1000);
            throw new TooManyRequestsException("verification requested again within the stream's "
                    + "min_verification_interval of " + interval + " seconds", seconds);
        }
    }

    /**
     * The stream's {@code min_verification_interval}: what it was given when it was created, or, for a stream stored
     * before 0.6.0 with none, this transmitter's current setting; {@code null} when that is 0.
     */
    private Integer effectiveMinVerificationInterval(Stream s) {
        if (s.minVerificationInterval() != null) {
            return s.minVerificationInterval();
        }
        return this.config.minVerificationIntervalSeconds() > 0 ? this.config.minVerificationIntervalSeconds() : null;
    }

    /** As {@link #effectiveMinVerificationInterval}, for {@code inactivity_timeout}. */
    private Long effectiveInactivityTimeout(Stream s) {
        if (s.inactivityTimeout() != null) {
            return s.inactivityTimeout();
        }
        return this.config.inactivityTimeoutSeconds() > 0 ? this.config.inactivityTimeoutSeconds() : null;
    }

    /**
     * The body's {@code description}: absent or {@code null} is none; anything but a string is a 400; a longer string
     * is cut at {@value #DESCRIPTION_MAX} characters, never inside a surrogate pair.
     */
    private static String parseDescription(Map<String, Object> body) {
        Object d = body.get("description");
        if (d == null) {
            return null;
        }
        if (!(d instanceof String)) {
            throw new IllegalArgumentException("description must be a string");
        }
        String text = (String) d;
        if (text.length() <= DESCRIPTION_MAX) {
            return text;
        }
        int end = Character.isHighSurrogate(text.charAt(DESCRIPTION_MAX - 1)) ? DESCRIPTION_MAX - 1 : DESCRIPTION_MAX;
        return text.substring(0, end);
    }

    /**
     * The stream, if it exists and is the caller's. One exception and one message for both failures, thrown
     * from one place: a stream that belongs to someone else has to look exactly like one that was never
     * created, or probing ids tells a receiver which of them are in use.
     */
    private Stream requireStream(String streamId, AuthContext caller) {
        Stream stream = this.store.getStream(streamId).orElse(null);
        if (stream == null || !this.access.admits(stream, caller)) {
            throw new NotFoundException("no such stream: " + streamId);
        }
        return stream;
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
        // What narrowToDeliverable will accept, so events_delivered is always a subset of it.
        m.put("events_supported", SsfEventTypes.ALL);
        m.put("events_requested", s.eventsRequested());
        m.put("events_delivered", s.eventsDelivered());
        LinkedHashMap<String, Object> delivery = new LinkedHashMap<>();
        delivery.put("method", s.deliveryMethod().urn());
        if (s.deliveryMethod() == DeliveryMethod.PUSH) {
            delivery.put("endpoint_url", s.pushEndpointUrl());
        } else {
            // Poll streams are addressed by the transmitter-assigned poll URL (RFC 8936); the receiver
            // POSTs the RFC 8936 body (maxEvents/returnImmediately/ack) there.
            delivery.put("endpoint_url", this.config.issuer() + SsfPaths.POLL + "?stream_id=" + s.id());
        }
        m.put("delivery", delivery);
        m.put("status", s.status().value());
        if (s.description() != null) {
            m.put("description", s.description());
        }
        Integer interval = effectiveMinVerificationInterval(s);
        if (interval != null) {
            m.put("min_verification_interval", interval);
        }
        Long timeout = effectiveInactivityTimeout(s);
        if (timeout != null) {
            m.put("inactivity_timeout", timeout);
        }
        return m;
    }

    /** The receiver's own {@code aud} if it sent one, otherwise the client its token identifies. */
    /**
     * Anything under {@code aud} that is not a string the caller may use is refused, an array or a blank
     * included - reading those as "none sent" would quietly turn a request for one audience into another.
     */
    private String resolveAudience(Map<String, Object> body, AuthContext caller, String owner) {
        Object supplied = body.get("aud");
        if (supplied == null) {
            return owner;
        }
        if (!(supplied instanceof String) || !this.access.mayAddress(caller, (String) supplied)) {
            throw new IllegalArgumentException("aud is Transmitter-Supplied: omit it, or send your client id or an "
                    + "audience this transmitter has agreed for your client");
        }
        return (String) supplied;
    }

    /**
     * A receiver may echo Transmitter-Supplied properties back on PATCH and PUT, but only as they stand
     * (SSF §8.1.1.3, §8.1.1.4); absent ones are ignored. Checked before anything is applied, so a request
     * that tries to move {@code aud} - which "cannot be updated" - changes nothing else either.
     */
    private void requireTransmitterSuppliedToMatch(Stream existing, Map<String, Object> body) {
        requireMatch(body, "iss", this.config.issuer());
        requireMatch(body, "aud", existing.audience());
        if (body.containsKey("events_delivered") && !parseEvents(body.get("events_delivered")).equals(existing.eventsDelivered())) {
            throw new IllegalArgumentException("events_delivered does not match the stream");
        }
        requireNumberMatch(body, "min_verification_interval", effectiveMinVerificationInterval(existing));
        requireNumberMatch(body, "inactivity_timeout", effectiveInactivityTimeout(existing));
    }

    /**
     * A Transmitter-Supplied number echoed back must be the stream's (SSF 1.0 §8.1.1.3: "they MUST match the expected
     * value"); one the stream does not have matches only {@code null}.
     */
    private static void requireNumberMatch(Map<String, Object> body, String key, Number expected) {
        if (!body.containsKey(key)) {
            return;
        }
        Object sent = body.get(key);
        boolean matches = sent == null ? expected == null
                : sent instanceof Number n && expected != null && n.doubleValue() == expected.doubleValue();
        if (!matches) {
            throw new IllegalArgumentException(key + " is Transmitter-Supplied and does not match the stream");
        }
    }

    private static void requireMatch(Map<String, Object> body, String key, String expected) {
        if (body.containsKey(key) && !expected.equals(body.get(key))) {
            throw new IllegalArgumentException(key + " is Transmitter-Supplied and does not match the stream");
        }
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
