/*
 * Push delivery of SETs (RFC 8935): background executor with retry/backoff and dead-letter -> pause.
 */
package com.pingidentity.ps.oidf.ssf;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Delivers queued SETs to push streams' endpoints (RFC 8935): {@code POST} with
 * {@code Content-Type: application/secevent+jwt} and the stream's authorization header. A 2xx acks (deletes)
 * the SET; a malformed-SET 400 drops just that SET; any other failure is retried with exponential backoff, and
 * once a SET reaches {@code pushRetryMaxAttempts} the stream is dead-lettered — flipped to {@code paused} with a
 * recorded reason. The HTTP call is behind {@link SetDeliveryClient} so the retry/backoff/pause logic
 * ({@link #runOnce}) is unit-tested without a network.
 */
public final class PushDeliveryService {

    private static final Log LOGGER = LogFactory.getLog(PushDeliveryService.class);
    private static final int BATCH = 500;

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
     * Attempt delivery of every push SET due at {@code now}. Returns the number successfully delivered. Deterministic
     * and synchronous — the scheduler simply calls this on a timer.
     */
    public int runOnce(long now) {
        int delivered = 0;
        for (PendingSet p : this.store.dueForPush(now, BATCH)) {
            Optional<Stream> so = this.store.getStream(p.streamId());
            if (so.isEmpty()) {
                this.store.ack(p.streamId(), List.of(p.jti())); // orphaned SET
                continue;
            }
            Stream s = so.get();
            if (s.deliveryMethod() != DeliveryMethod.PUSH || s.status() != StreamStatus.ENABLED) {
                continue; // poll streams drain via /poll; paused/disabled streams don't deliver
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
                    break;
            }
        }
        return delivered;
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

    /** Start the background delivery loop (idempotent). Ticks every {@code pushRetryBackoffSeconds}. */
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

    // ─────────────────────────────── real HTTP client ───────────────────────────────

    /** A JDK-HttpClient delivery client implementing the RFC 8935 POST + response classification. */
    public static SetDeliveryClient httpClient() {
        HttpClient http = HttpClient.newHttpClient();
        return (url, authHeader, jws) -> {
            try {
                HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                        .header("Content-Type", "application/secevent+jwt")
                        .header("Accept", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(jws));
                if (authHeader != null && !authHeader.isBlank()) {
                    b.header("Authorization", authHeader);
                }
                HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
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
}
