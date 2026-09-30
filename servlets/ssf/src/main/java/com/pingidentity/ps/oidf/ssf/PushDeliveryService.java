/*
 * Push delivery of SETs (RFC 8935): background executor with retry/backoff and dead-letter -> pause. The same
 * executor expires undelivered SETs, push and poll alike.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import com.pingidentity.ps.oidf.signals.SetMinter;
import java.net.URI;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Delivers queued SETs to push streams' endpoints (RFC 8935): {@code POST} with
 * {@code Content-Type: application/secevent+jwt} and the stream's authorization header. A 2xx acks (deletes)
 * the SET; a malformed-SET 400 drops just that SET; any other failure is retried with exponential backoff, and
 * once a SET reaches {@code pushRetryMaxAttempts} the stream is dead-lettered — flipped to {@code paused} with a
 * recorded reason. The HTTP call is behind {@link SetDeliveryClient} so the retry/backoff/pause logic
 * ({@link #runOnce}) is unit-tested without a network; the real one sends through platform's
 * {@link OutboundHttp} (plan item S5d).
 *
 * <p>One loop, one thread, and every stream behind it - so what one stream can cost the others is bounded
 * here (the Phase 1 stopgap for B5; S-10 replaces the loop with a leased engine): the store hands over only
 * the SETs of enabled push streams, a stream whose delivery fails waits out that SET's backoff as a whole,
 * and no attempt outlives {@link #REQUEST_TIMEOUT}.
 */
public final class PushDeliveryService {

    private static final Log LOGGER = LogFactory.getLog(PushDeliveryService.class);
    private static final int BATCH = 500;

    /**
     * The deadlines of one push POST, and how much of its answer is read. Constants until S-5 makes them
     * settings; the values are the plan's (S-10, "Deadlines: connect 2 s, total 10 s"). Without them a
     * receiver that accepts the connection and never answers holds this loop's one thread for as long as
     * the socket lives, and no stream is delivered to (B5).
     */
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(10);
    /**
     * The most of a receiver's answer that is read: RFC 8935 §2.2, "The body of the response MUST be empty", and a
     * 400's is a small JSON error (§2.3), so a larger body is a failed attempt, retried, and never read past the cap.
     */
    static final long RESPONSE_BODY_CAP = 64L * 1024L;
    /** Only a 400's body is used, for the log line, and only this much of it. */
    static final int LOGGED_BODY_CHARS = 4096;

    public enum Outcome { DELIVERED, RETRYABLE, PERMANENT }

    /** The result of one delivery attempt. */
    public static final class DeliveryResult {
        private final Outcome outcome;
        private final int statusCode;
        private final String message;

        private DeliveryResult(Outcome outcome, int statusCode, String message) {
            this.outcome = outcome;
            this.statusCode = statusCode;
            this.message = message;
        }

        public static DeliveryResult delivered() {
            return new DeliveryResult(Outcome.DELIVERED, 202, null);
        }

        public static DeliveryResult retryable(int statusCode, String message) {
            return new DeliveryResult(Outcome.RETRYABLE, statusCode, message);
        }

        public static DeliveryResult permanent(int statusCode, String message) {
            return new DeliveryResult(Outcome.PERMANENT, statusCode, message);
        }

        public Outcome outcome() {
            return this.outcome;
        }

        /** The receiver's status line, or 0 when no response was read. */
        public int statusCode() {
            return this.statusCode;
        }

        /** What went wrong, for the log; null on success. */
        public String message() {
            return this.message;
        }
    }

    /** The RFC 8935 POST, isolated for testing. */
    public interface SetDeliveryClient {
        DeliveryResult deliver(String endpointUrl, String authorizationHeader, String setJws);
    }

    private final SsfStore store;
    private final SsfConfiguration config;
    private final SetDeliveryClient client;
    private volatile ManagedExecutor scheduler;

    public PushDeliveryService(SsfStore store, SsfConfiguration config, SetDeliveryClient client) {
        this.store = store;
        this.config = config;
        this.client = client;
    }

    /**
     * Evict every SET past its TTL, then attempt delivery of every push SET due at {@code now}. Returns the
     * number successfully delivered. Deterministic and synchronous — the scheduler simply calls this on a timer.
     *
     * <p>Eviction is here because this is the one loop the transmitter runs, and it runs whether or not any
     * push stream exists — so a poll stream nobody drains is emptied too. It comes first and is not caught:
     * what is read for delivery is read after the expired SETs are gone, and a tick that cannot evict
     * delivers nothing rather than something it was configured to have discarded.
     *
     * <p>A stream that fails is held, whole. After a retryable failure nothing more of that stream is tried
     * in the tick, and in later ticks nothing of it is tried while its first SET is still waiting out the
     * backoff that failure set: its later SETs are due, but posting them would put them in front of the one
     * that failed. So a receiver that is down costs one attempt (at most {@link #REQUEST_TIMEOUT}) per backoff
     * step, not one per queued SET or one per tick, and when it is back its SETs arrive in the store's order
     * ({@link SsfStore#peek}: oldest first, and a second's SETs by {@code jti}) - from the one that failed,
     * which is retried before anything behind it. Attempts are counted on the SET that was tried, the first,
     * so the stream dead-letters when that SET has failed {@code pushRetryMaxAttempts} times, on the same
     * backoff as before, however many SETs were issued in its second.
     *
     * <p>A tick whose thread is interrupted - {@link #stop} - posts nothing after the attempt in flight.
     */
    public int runOnce(long now) {
        evictExpired(now);
        int delivered = 0;
        Set<String> held = new HashSet<>();   // streams that get no more attempts this tick
        Set<String> looked = new HashSet<>(); // streams whose oldest SET has been looked at this tick
        for (PendingSet p : this.store.dueForPush(now, BATCH)) {
            if (Thread.currentThread().isInterrupted()) {
                break; // the loop was stopped: nothing more is posted, and nothing more counted as failed
            }
            if (held.contains(p.streamId())) {
                continue;
            }
            Optional<Stream> so = this.store.getStream(p.streamId());
            if (so.isEmpty()) {
                this.store.ack(p.streamId(), List.of(p.jti())); // orphaned SET
                continue;
            }
            Stream s = so.get();
            if (!s.isPushEnabled()) {
                continue; // the store selects enabled push streams; this is the stream as it is now
            }
            if (looked.add(s.id()) && oldestIsBackingOff(s.id(), now)) {
                held.add(s.id());
                continue;
            }
            DeliveryResult r = safeDeliver(s, p);
            switch (r.outcome) {
                case DELIVERED:
                    this.store.ack(s.id(), List.of(p.jti()));
                    delivered++;
                    break;
                case PERMANENT:
                    LOGGER.warn((Object) ("dropping SET " + p.jti() + " on stream " + s.id()
                            + " — permanent delivery failure (HTTP " + r.statusCode + ")"));
                    this.store.ack(s.id(), List.of(p.jti()));
                    break;
                case RETRYABLE:
                default:
                    handleRetry(s, p, r, now);
                    held.add(s.id());
                    break;
            }
        }
        return delivered;
    }

    /**
     * Whether the stream's first queued SET is not due yet - a failed attempt's backoff - so that the due
     * SETs behind it wait too. Asked once per stream per tick, before its first attempt. {@code peek} and
     * {@code dueForPush} share one order ({@link SsfStore#peek}), so a first SET that is due is also the
     * stream's first in the batch, and a stream whose first SET is due is never held here; one whose first
     * SET is gone (delivered or evicted since the batch was read) is not either.
     */
    private boolean oldestIsBackingOff(String streamId, long now) {
        List<PendingSet> oldest = this.store.peek(streamId, 1);
        return !oldest.isEmpty() && oldest.get(0).nextAttemptAt() > now;
    }

    /**
     * Drop pending SETs whose {@code setTtlSeconds} has run out, on every stream and either delivery method.
     * One DELETE; a SET stamped with no expiry ({@code setTtlSeconds <= 0}) is never touched.
     */
    private void evictExpired(long now) {
        int evicted = this.store.evictExpired(now);
        if (evicted > 0) {
            LOGGER.info((Object) ("evicted " + evicted + " undelivered SET(s) past setTtlSeconds"));
        }
    }

    private DeliveryResult safeDeliver(Stream s, PendingSet p) {
        try {
            return this.client.deliver(s.pushEndpointUrl(), s.pushAuthorizationHeader(), p.setJws());
        } catch (Exception e) {
            return DeliveryResult.retryable(0, e.getMessage()); // treat client errors as retryable
        }
    }

    private void handleRetry(Stream s, PendingSet p, DeliveryResult r, long now) {
        int attemptsAfter = p.deliveryAttempts() + 1;
        long next = now + backoffSeconds(attemptsAfter);
        this.store.recordAttempt(p, next);
        if (attemptsAfter >= this.config.pushRetryMaxAttempts()) {
            String reason = "dead-letter: " + attemptsAfter + " failed push attempts (last HTTP "
                    + r.statusCode + ")";
            this.store.updateStream(s.withStatus(StreamStatus.PAUSED, reason, now));
            LOGGER.warn((Object) ("stream " + s.id() + " paused — " + reason));
        }
    }

    /** Exponential backoff: {@code base * 2^(attempts-1)}, capped at 2^10 multiples. */
    private long backoffSeconds(int attempts) {
        long base = Math.max(1, this.config.pushRetryBackoffSeconds());
        long mult = 1L << Math.min(Math.max(attempts - 1, 0), 10);
        return base * mult;
    }

    // ─────────────────────────────── lifecycle ───────────────────────────────

    /** The loop's managed executor; its thread is {@code oidf-ssf-push-delivery-1}. */
    static final String EXECUTOR_NAME = "ssf-push-delivery";

    /**
     * Start the background loop (idempotent). Ticks every {@code pushRetryBackoffSeconds}, the first one tick from
     * now, each starting one tick after the last ended; it runs once in the JVM, so a start that finds it running
     * elsewhere starts nothing. Each tick is
     * {@link #runOnce}, so it is also what expires SETs on a transmitter with no push stream at all.
     * Nothing here touches the store or the network, so nothing here throws: the first tick is where a
     * store that is down is met, and a tick's failure is logged and the next tick tries again.
     */
    public synchronized void start() {
        if (this.scheduler != null) {
            return;
        }
        long tick = Math.max(1, this.config.pushRetryBackoffSeconds());
        Optional<ManagedExecutor> started = ManagedExecutors.every(EXECUTOR_NAME, Duration.ofSeconds(tick), () -> {
            try {
                runOnce(SetMinter.nowSeconds());
            } catch (Exception e) {
                LOGGER.warn((Object) ("push delivery tick failed: " + e.getMessage()));
            }
        });
        if (started.isEmpty()) {
            return;
        }
        this.scheduler = started.get();
        LOGGER.info((Object) ("SSF push delivery executor started (tick " + tick + "s)"));
    }

    /**
     * Stops the loop: a tick in progress is interrupted - an exchange in flight is cancelled, which closes its
     * connection (U-0077) - and waited for, briefly, outside this service's lock.
     */
    public void stop() {
        ManagedExecutor running;
        synchronized (this) {
            running = this.scheduler;
            this.scheduler = null;
        }
        if (running != null) {
            running.close();
        }
    }

    /** Whether {@link #start} has run and {@link #stop} has not. */
    public boolean isRunning() {
        return this.scheduler != null;
    }

    // ─────────────────────────────── real HTTP client ───────────────────────────────

    /** The RFC 8935 POST through platform's {@link OutboundHttp}, with the outbound policy the settings give. */
    public static SetDeliveryClient httpClient() {
        return httpClient(OutboundUrlPolicy.fromEnvironment());
    }

    /**
     * As {@link #httpClient()} but with an explicit outbound policy — the test seam, and the way an
     * operator-configured internal receiver is exempted ({@code policy.trusting(url)}).
     *
     * <p>The endpoint is screened on every attempt, not only when the stream was configured. A stream
     * may predate the screening in {@code StreamManagementService}, or have been written straight into
     * the store; and a hostname that resolved publicly at configuration time can resolve to a private
     * address later. The policy resolves the host once, checks every address and the connection goes to a
     * checked address, so a name cannot resolve publicly for the check and privately for the connection.
     */
    public static SetDeliveryClient httpClient(OutboundUrlPolicy policy) {
        return httpClient(policy, CONNECT_TIMEOUT, REQUEST_TIMEOUT, RESPONSE_BODY_CAP);
    }

    /** The deadlines and the body cap as parameters: the test seam, so a stalled receiver is a short test. */
    static SetDeliveryClient httpClient(OutboundUrlPolicy policy, Duration connectTimeout, Duration requestTimeout,
                                        long bodyCap) {
        return httpClient(policy, TlsTrust.jvmDefault(), connectTimeout, requestTimeout, bodyCap);
    }

    /**
     * The trust as well: the test seam for a receiver whose certificate a test CA signed. At run time it is the JVM's
     * trust store; the certificate must name the host the endpoint URL names.
     */
    static SetDeliveryClient httpClient(OutboundUrlPolicy policy, TlsTrust trust, Duration connectTimeout,
                                        Duration requestTimeout, long bodyCap) {
        OutboundUrlPolicy outbound = policy != null ? policy : OutboundUrlPolicy.fromEnvironment();
        OutboundHttp http = OutboundHttp.builder(outbound.addressPolicy())
                .tls(trust)
                .connectTimeout(connectTimeout)
                .headerTimeout(requestTimeout)
                .maxBodyBytes(bodyCap)
                .build();
        return (url, authHeader, jws) -> deliver(http, outbound, requestTimeout, url, authHeader, jws);
    }

    /**
     * One POST, bounded as a whole by {@code deadline}: connecting (2 s at most), the status line and headers,
     * and the body, which is read up to the cap and no further. A receiver that answers slowly, a byte at a
     * time, or with more than the cap costs one attempt of at most {@link #REQUEST_TIMEOUT}, and the socket is
     * closed when it ends. An interrupt - {@link #stop} - ends the wait within platform's 250 ms read slice and
     * leaves the interrupt set, so {@link #runOnce} posts nothing after it.
     */
    static DeliveryResult deliver(OutboundHttp http, OutboundUrlPolicy policy, Duration deadline, String url,
                                  String authHeader, String jws) {
        OutboundResponse response;
        try {
            OutboundRequest.Builder request = OutboundRequest.post(url)
                    .header("Accept", "application/json")
                    .body("application/secevent+jwt", jws);
            if (authHeader != null && !authHeader.isBlank()) {
                request.header("Authorization", authHeader);
            }
            response = http.send(request.build(), Deadline.after(deadline));
        } catch (OutboundHttpException e) {
            IllegalArgumentException refused = policy.refusal(e, URI.create(url));
            if (refused != null) {
                // PERMANENT, deliberately: a destination the policy refuses will never become acceptable by
                // trying again, and retrying it would re-attempt an SSRF every backoff tick until the stream
                // dead-letters.
                LOGGER.warn((Object) ("refusing push delivery to " + url + ": " + refused.getMessage()));
                return DeliveryResult.permanent(0, "endpoint refused by outbound policy: " + refused.getMessage());
            }
            LOGGER.warn((Object) ("push delivery to " + url + " failed, to be retried: " + e.reason() + ": "
                    + e.getMessage()));
            return DeliveryResult.retryable(0, e.reason() + ": " + e.getMessage());
        } catch (IllegalArgumentException e) {
            // A URL that does not parse, or an authorization header that could split the request: neither
            // changes by trying again.
            LOGGER.warn((Object) ("refusing push delivery to " + url + ": " + e.getMessage()));
            return DeliveryResult.permanent(0, "endpoint refused: " + e.getMessage());
        }
        int code = response.status();
        if (code == 200 || code == 202) {
            return DeliveryResult.delivered();
        }
        if (code == 400) {
            // Malformed SET: it won't succeed on retry. The body goes in the log, clipped.
            String body = response.bodyText();
            return DeliveryResult.permanent(code, body.substring(0, Math.min(body.length(), LOGGED_BODY_CHARS)));
        }
        return DeliveryResult.retryable(code, "HTTP " + code);
    }
}
