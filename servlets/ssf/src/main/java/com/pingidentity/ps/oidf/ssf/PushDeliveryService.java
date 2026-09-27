/*
 * Push delivery of SETs (RFC 8935): background executor with retry/backoff and dead-letter -> pause. The same
 * executor expires undelivered SETs, push and poll alike.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Delivers queued SETs to push streams' endpoints (RFC 8935): {@code POST} with
 * {@code Content-Type: application/secevent+jwt} and the stream's authorization header. A 2xx acks (deletes)
 * the SET; a malformed-SET 400 drops just that SET; any other failure is retried with exponential backoff, and
 * once a SET reaches {@code pushRetryMaxAttempts} the stream is dead-lettered — flipped to {@code paused} with a
 * recorded reason. The HTTP call is behind {@link SetDeliveryClient} so the retry/backoff/pause logic
 * ({@link #runOnce}) is unit-tested without a network.
 *
 * <p>One loop, one thread, and every stream behind it - so what one stream can cost the others is bounded
 * here (the Phase 1 stopgap for B5; S-10 replaces the loop with a leased engine): the store hands over only
 * the SETs of enabled push streams, a stream that fails a delivery gets no second attempt in the same tick,
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
    /** Only a 400's body is used, for the log line; a receiver cannot make the loop read more than this of it. */
    static final int RESPONSE_BODY_CAP = 4096;

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
    private volatile ScheduledExecutorService scheduler;

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
     * <p>A stream gets one failed attempt per tick. After a retryable failure its remaining SETs in the batch
     * are left as they are - still due, still oldest first, read again next tick - so a receiver that is down
     * costs one attempt (at most {@link #REQUEST_TIMEOUT}) per tick, not one per queued SET, and its SETs are
     * delivered in order when it is back. Attempts are counted only on the SET that was tried, so a stream
     * dead-letters after {@code pushRetryMaxAttempts} failed ticks, as before.
     */
    public int runOnce(long now) {
        evictExpired(now);
        int delivered = 0;
        Set<String> failedThisTick = new HashSet<>();
        for (PendingSet p : this.store.dueForPush(now, BATCH)) {
            if (failedThisTick.contains(p.streamId())) {
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
                    failedThisTick.add(s.id());
                    break;
            }
        }
        return delivered;
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

    /**
     * Start the background loop (idempotent). Ticks every {@code pushRetryBackoffSeconds}; each tick is
     * {@link #runOnce}, so it is also what expires SETs on a transmitter with no push stream at all.
     * Nothing here touches the store or the network, so nothing here throws: the first tick is where a
     * store that is down is met, and a tick's failure is logged and the next tick tries again.
     */
    public synchronized void start() {
        if (this.scheduler != null) {
            return;
        }
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ssf-push-delivery");
            t.setDaemon(true);
            return t;
        });
        long tick = Math.max(1, this.config.pushRetryBackoffSeconds());
        this.scheduler.scheduleWithFixedDelay(() -> {
            try {
                runOnce(SetMinter.nowSeconds());
            } catch (Exception e) {
                LOGGER.warn((Object) ("push delivery tick failed: " + e.getMessage()));
            }
        }, tick, tick, TimeUnit.SECONDS);
        LOGGER.info((Object) ("SSF push delivery executor started (tick " + tick + "s)"));
    }

    public synchronized void stop() {
        if (this.scheduler != null) {
            this.scheduler.shutdownNow();
            this.scheduler = null;
        }
    }

    /** Whether {@link #start} has run and {@link #stop} has not. */
    public boolean isRunning() {
        return this.scheduler != null;
    }

    // ─────────────────────────────── real HTTP client ───────────────────────────────

    /** A JDK-HttpClient delivery client implementing the RFC 8935 POST + response classification. */
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
     * address later. This is the check that is actually adjacent to the request.
     */
    public static SetDeliveryClient httpClient(OutboundUrlPolicy policy) {
        return httpClient(policy, CONNECT_TIMEOUT, REQUEST_TIMEOUT, RESPONSE_BODY_CAP);
    }

    /** The deadlines and the body cap as parameters: the test seam, so a stalled receiver is a short test. */
    static SetDeliveryClient httpClient(OutboundUrlPolicy policy, Duration connectTimeout, Duration requestTimeout,
                                        int bodyCap) {
        OutboundUrlPolicy outbound = policy != null ? policy : OutboundUrlPolicy.fromEnvironment();
        HttpClient http = HttpClient.newBuilder().connectTimeout(connectTimeout).build();
        return (url, authHeader, jws) -> {
            try {
                outbound.check(url);
            } catch (IllegalArgumentException e) {
                // PERMANENT, deliberately. The generic catch below classifies everything as retryable,
                // which for a refused destination would mean re-attempting an SSRF every backoff tick
                // until the stream dead-letters. A destination the policy refuses will never become
                // acceptable by trying again.
                LOGGER.warn((Object) ("refusing push delivery to " + url + ": " + e.getMessage()));
                return DeliveryResult.permanent(0, "endpoint refused by outbound policy: " + e.getMessage());
            }
            try {
                HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                        .timeout(requestTimeout)
                        .header("Content-Type", "application/secevent+jwt")
                        .header("Accept", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jws));
                if (authHeader != null && !authHeader.isBlank()) {
                    b.header("Authorization", authHeader);
                }
                HttpResponse<String> resp = send(http, b.build(), requestTimeout, bodyCap);
                int code = resp.statusCode();
                if (code == 200 || code == 202) {
                    return DeliveryResult.delivered();
                }
                if (code == 400) {
                    return DeliveryResult.permanent(code, resp.body()); // malformed SET — won't succeed on retry
                }
                return DeliveryResult.retryable(code, "HTTP " + code);
            } catch (Exception e) {
                return DeliveryResult.retryable(0, e.getMessage()); // network error — retry
            }
        };
    }

    /**
     * One exchange, bounded as a whole. {@code HttpRequest.timeout} is the wait for the response headers
     * and nothing after them: a receiver that sends its status line and then holds the body open would hold
     * the delivery thread past any deadline set on the request. So the future is waited on for the whole
     * exchange and cancelled when the deadline passes - which the JDK client honours from 16 on, closing the
     * connection - and the body is read up to {@code bodyCap} bytes and not one more.
     */
    static HttpResponse<String> send(HttpClient http, HttpRequest request, Duration deadline, int bodyCap)
            throws Exception {
        CompletableFuture<HttpResponse<String>> exchange =
                http.sendAsync(request, info -> new CappedBody(bodyCap));
        try {
            return exchange.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            exchange.cancel(true);
            throw new HttpTimeoutException("no complete response within " + deadline.toMillis() + " ms");
        }
    }

    /**
     * A body subscriber that keeps the first {@code cap} bytes and cancels the rest. Completes on the cap as
     * well as on the end of the body, so a response whose body never ends is over once the cap is reached.
     */
    static final class CappedBody implements HttpResponse.BodySubscriber<String> {

        private final int cap;
        private final ByteArrayOutputStream kept = new ByteArrayOutputStream();
        private final CompletableFuture<String> body = new CompletableFuture<>();
        private Flow.Subscription subscription;

        CappedBody(int cap) {
            this.cap = cap;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                int room = this.cap - this.kept.size();
                if (room <= 0) {
                    break;
                }
                byte[] chunk = new byte[Math.min(room, buffer.remaining())];
                buffer.get(chunk);
                this.kept.write(chunk, 0, chunk.length);
            }
            if (this.kept.size() >= this.cap) {
                this.subscription.cancel();
                this.body.complete(this.kept.toString(StandardCharsets.UTF_8));
            }
        }

        @Override
        public void onError(Throwable throwable) {
            this.body.completeExceptionally(throwable);
        }

        @Override
        public void onComplete() {
            this.body.complete(this.kept.toString(StandardCharsets.UTF_8));
        }

        @Override
        public CompletionStage<String> getBody() {
            return this.body;
        }
    }
}
