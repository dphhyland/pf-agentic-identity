/*
 * RFC 8936 poll CLIENT: pulls SETs from a remote transmitter's poll endpoint into the receiver pipeline.
 */
package com.pingidentity.ps.oidf.ssf;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * The receiver's poll loop for transmitters we poll rather than receive push from (RFC 8936): each tick
 * POSTs {@code {maxEvents, returnImmediately: true, ack: [...]}} to the remote poll endpoint with the
 * receiver's bearer, feeds every returned SET through {@link SsfReceiverService} (verify → dedupe →
 * dispatch), and acks the processed {@code jti}s on the next tick. A SET that fails verification is still
 * acked (redelivering it can never succeed — the RFC 8936 equivalent of a permanent failure). The HTTP call
 * is behind {@link PollTransport} so {@link #runOnce()} is unit-testable.
 */
public final class PollReceiverClient {

    /** The poll POST: body JSON in, response JSON out. */
    public interface PollTransport {
        String poll(String bodyJson) throws Exception;
    }

    private static final Log LOGGER = LogFactory.getLog(PollReceiverClient.class);

    private final SsfReceiverService receiver;
    private final PollTransport transport;
    private final int maxEvents;
    private final List<String> pendingAcks = new ArrayList<>();
    private volatile ScheduledExecutorService scheduler;

    public PollReceiverClient(SsfReceiverService receiver, PollTransport transport, int maxEvents) {
        this.receiver = Objects.requireNonNull(receiver, "receiver");
        this.transport = Objects.requireNonNull(transport, "transport");
        this.maxEvents = maxEvents > 0 ? maxEvents : 100;
    }

    /** One poll cycle: ack the previous batch, receive the next. Returns the number of SETs processed. */
    public synchronized int runOnce() {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("maxEvents", this.maxEvents);
        body.put("returnImmediately", true);
        if (!this.pendingAcks.isEmpty()) {
            body.put("ack", new ArrayList<>(this.pendingAcks));
        }
        String response;
        try {
            response = this.transport.poll(JsonUtil.toJson(body));
        } catch (Exception e) {
            LOGGER.warn((Object) ("SSF poll client: poll failed: " + e.getMessage()));
            return 0; // keep pendingAcks — retried next tick
        }
        this.pendingAcks.clear();
        Map<String, Object> parsed;
        try {
            parsed = JsonUtil.parseJson(response);
        } catch (Exception e) {
            LOGGER.warn((Object) "SSF poll client: response is not JSON");
            return 0;
        }
        Object sets = parsed.get("sets");
        if (!(sets instanceof Map)) {
            return 0;
        }
        int processed = 0;
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) sets).entrySet()) {
            String jti = String.valueOf(entry.getKey());
            try {
                this.receiver.receive(String.valueOf(entry.getValue()));
                processed++;
            } catch (SetVerifier.SetVerificationException e) {
                LOGGER.warn((Object) ("SSF poll client: SET " + jti + " rejected (" + e.errorCode()
                        + ") — acking anyway, redelivery cannot succeed"));
            }
            this.pendingAcks.add(jti); // ack processed AND permanently-failed SETs
        }
        return processed;
    }

    /** Start the background poll loop (idempotent). */
    public synchronized void start(long intervalSeconds) {
        if (this.scheduler != null) {
            return;
        }
        long tick = Math.max(1, intervalSeconds);
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ssf-poll-receiver");
            t.setDaemon(true);
            return t;
        });
        this.scheduler.scheduleWithFixedDelay(() -> {
            try {
                runOnce();
            } catch (Exception e) {
                LOGGER.warn((Object) ("SSF poll client tick failed: " + e.getMessage()));
            }
        }, tick, tick, TimeUnit.SECONDS);
        LOGGER.info((Object) ("SSF poll receiver started (tick " + tick + "s)"));
    }

    public synchronized void stop() {
        if (this.scheduler != null) {
            this.scheduler.shutdownNow();
            this.scheduler = null;
        }
    }

    /** Runtime transport: POST JSON to the remote poll endpoint with a bearer token. */
    public static PollTransport httpTransport(String pollUrl, String bearerToken, boolean insecureTls) {
        HttpClient http = insecureTls ? TrustAll.client() : HttpClient.newHttpClient();
        return bodyJson -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(pollUrl))
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(bodyJson));
            if (bearerToken != null && !bearerToken.isBlank()) {
                b.header("Authorization", "Bearer " + bearerToken);
            }
            HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("poll endpoint returned HTTP " + resp.statusCode());
            }
            return resp.body();
        };
    }

    /** Shared dev trust-all HTTP client builder. */
    static final class TrustAll {
        private TrustAll() {
        }

        static HttpClient client() {
            try {
                javax.net.ssl.TrustManager[] trustAll = {new javax.net.ssl.X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {
                        // dev trust-all
                    }

                    public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {
                        // dev trust-all
                    }

                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                }};
                javax.net.ssl.SSLContext ssl = javax.net.ssl.SSLContext.getInstance("TLS");
                ssl.init(null, trustAll, new java.security.SecureRandom());
                return HttpClient.newBuilder().sslContext(ssl).build();
            } catch (Exception e) {
                throw new IllegalStateException("failed to build trust-all HTTP client", e);
            }
        }
    }
}
