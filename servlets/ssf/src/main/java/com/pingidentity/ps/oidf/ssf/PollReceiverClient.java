/*
 * RFC 8936 poll CLIENT: pulls SETs from a remote transmitter's poll endpoint into the receiver pipeline.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * The receiver's poll loop for transmitters we poll rather than receive push from (RFC 8936): each tick
 * POSTs {@code {maxEvents, returnImmediately: true, ack: [...], setErrs: {...}}} to the remote poll endpoint with
 * the receiver's bearer, feeds every returned SET through {@link SsfReceiverService} (verify → dedupe →
 * dispatch), and reports each on the next tick. A SET the receiver took (accepted, a duplicate, or discarded for a
 * critical subject member) is acknowledged in {@code ack}; one it refused is reported in {@code setErrs} with its
 * RFC 8935 error code and description, not acknowledged - RFC 8936 §2: "The SET Recipient SHALL NOT use the event
 * acknowledgement mechanism to report event errors other than those relating to the parsing and validation of the
 * SET", and §2.2 defines {@code setErrs} as "the "jti" values of invalid SETs received". Either way it is not
 * delivered again. The HTTP call is behind {@link PollTransport} so {@link #runOnce()} is unit-testable.
 */
public final class PollReceiverClient {

    /** The poll POST: body JSON in, response JSON out; null when there is nowhere to poll yet. */
    public interface PollTransport {
        String poll(String bodyJson) throws Exception;
    }

    private static final Log LOGGER = LogFactory.getLog(PollReceiverClient.class);

    private final SsfReceiverService receiver;
    private final PollTransport transport;
    private final int maxEvents;
    private final List<String> pendingAcks = new ArrayList<>();
    private final Map<String, Object> pendingErrs = new LinkedHashMap<>();
    private volatile ManagedExecutor scheduler;

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
        if (!this.pendingErrs.isEmpty()) {
            body.put("setErrs", new LinkedHashMap<>(this.pendingErrs));
        }
        String response;
        try {
            response = this.transport.poll(JsonUtil.toJson(body));
        } catch (Exception e) {
            LOGGER.warn((Object) ("SSF poll client: poll failed: " + e.getMessage()));
            return 0; // keep pendingAcks — retried next tick
        }
        if (response == null) {
            return 0; // nowhere to poll yet: the receiver's stream is not set up
        }
        this.pendingAcks.clear();
        this.pendingErrs.clear();
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
                this.pendingAcks.add(jti);
            } catch (SetVerifier.SetVerificationException e) {
                LOGGER.warn((Object) ("SSF poll client: SET " + jti + " rejected (" + e.errorCode()
                        + "); reported in setErrs, redelivery cannot succeed"));
                LinkedHashMap<String, Object> err = new LinkedHashMap<>();
                err.put("err", e.errorCode());
                err.put("description", e.getMessage());
                this.pendingErrs.put(jti, err);
            }
        }
        return processed;
    }

    /** The poll loop's managed executor; its thread is {@code oidf-ssf-poll-receiver-1}. */
    static final String EXECUTOR_NAME = "ssf-poll-receiver";

    /**
     * Start the background poll loop (idempotent): a tick every {@code intervalSeconds} (at least 1), the first one
     * interval from now, each starting one interval after the last ended. It runs once in the JVM; a start that finds
     * it running elsewhere starts nothing.
     */
    public synchronized void start(long intervalSeconds) {
        if (this.scheduler != null) {
            return;
        }
        long tick = Math.max(1, intervalSeconds);
        Optional<ManagedExecutor> started = ManagedExecutors.every(EXECUTOR_NAME, Duration.ofSeconds(tick), () -> {
            try {
                runOnce();
            } catch (Exception e) {
                LOGGER.warn((Object) ("SSF poll client tick failed: " + e.getMessage()));
            }
        });
        if (started.isEmpty()) {
            return;
        }
        this.scheduler = started.get();
        LOGGER.info((Object) ("SSF poll receiver started (tick " + tick + "s)"));
    }

    /** Stops the loop: a tick in progress is interrupted and waited for, briefly, outside this client's lock. */
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

    /**
     * The receiver's switch that trusts any certificate on its outbound calls (init-param {@code receiverInsecureTls}),
     * as InsecureTls names it.
     */
    static final String RECEIVER_INSECURE_TLS = "OIDF_SSF_RECEIVER_INSECURE_TLS";

    /**
     * Runtime transport: POST JSON to the remote poll endpoint with the receiver's bearer - {@code bearer}'s token,
     * asked again once after a 401 - or nothing when {@code pollUrl} has none yet. {@code insecureTls} trusts any
     * certificate chain through platform's {@link InsecureTls}; the host name is still checked.
     */
    public static PollTransport httpTransport(Supplier<String> pollUrl, ReceiverBearer bearer, boolean insecureTls) {
        HttpClient http = InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), RECEIVER_INSECURE_TLS, insecureTls).build();
        return bodyJson -> {
            String url = pollUrl.get();
            if (url == null) {
                return null;
            }
            HttpResponse<String> resp = send(http, url, bodyJson, bearer.token());
            if (resp.statusCode() == 401) {
                bearer.rejected(bearerOf(resp));
                resp = send(http, url, bodyJson, bearer.token());
            }
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("poll endpoint returned HTTP " + resp.statusCode());
            }
            return resp.body();
        };
    }

    private static HttpResponse<String> send(HttpClient http, String url, String bodyJson, String token) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(bodyJson));
        if (token != null && !token.isBlank()) {
            b.header("Authorization", "Bearer " + token);
        }
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** The token a request carried, read back from the request its response answers. */
    static String bearerOf(HttpResponse<?> resp) {
        String header = resp.request().headers().firstValue("Authorization").orElse("");
        return header.startsWith("Bearer ") ? header.substring(7) : null;
    }
}
