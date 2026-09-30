/*
 * RFC 8936 poll CLIENT: pulls SETs from a remote transmitter's poll endpoint into the receiver pipeline.
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.exec.ManagedExecutor;
import com.pingidentity.ps.oidf.platform.exec.ManagedExecutors;
import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import com.pingidentity.ps.oidf.signals.SetVerifier;
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
     * The deadlines of one poll: connecting (TLS included) within 1 s, and the whole exchange within 5 s. The poll
     * asks {@code returnImmediately}, so the transmitter has nothing to wait for; a long poll would add its wait to the
     * total.
     */
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(1);
    static final Duration TOTAL_TIMEOUT = Duration.ofSeconds(5);
    /**
     * The largest poll response read: the default {@code maxEvents} of 100 at 40 KiB a SET. A larger answer is a
     * failed poll - logged, and asked again next tick with the same acknowledgements.
     */
    static final long MAX_BODY_BYTES = 4L * 1024L * 1024L;

    /**
     * The receiver's outbound rules, for its poll, stream management and JWKS calls: its peer is the transmitter the
     * operator named, which may be internal by design, so any address is allowed, still resolved once and pinned. A
     * scheme is the settings' to govern: the production profile refuses an http transmitter configuration URL, and
     * {@link ReceiverStreamClient#requireTls} refuses an http URL the transmitter names unless that URL was http.
     */
    static AddressPolicy receiverPolicy() {
        return AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build();
    }

    /** The receiver's transport: {@code insecureTls} trusts any chain through platform's InsecureTls; the name is still checked. */
    static OutboundHttp receiverHttp(AddressPolicy policy, boolean insecureTls, Duration connect, long maxBody) {
        return OutboundHttp.builder(policy)
                .tls(TlsTrust.insecureIf(RECEIVER_INSECURE_TLS, insecureTls))
                .connectTimeout(connect)
                .maxBodyBytes(maxBody)
                .build();
    }

    /**
     * Runtime transport: POST JSON to the remote poll endpoint with the receiver's bearer - {@code bearer}'s token,
     * asked again once after a 401 - or nothing when {@code pollUrl} has none yet, through platform's
     * {@link OutboundHttp} ({@link #CONNECT_TIMEOUT}, {@link #TOTAL_TIMEOUT}, {@link #MAX_BODY_BYTES}).
     * {@code insecureTls} trusts any certificate chain through platform's {@link InsecureTls}; the host name is still
     * checked.
     */
    public static PollTransport httpTransport(Supplier<String> pollUrl, ReceiverBearer bearer, boolean insecureTls) {
        return httpTransport(pollUrl, bearer, receiverHttp(receiverPolicy(), insecureTls, CONNECT_TIMEOUT, MAX_BODY_BYTES),
                TOTAL_TIMEOUT);
    }

    /** The transport over {@code http}, each exchange within {@code total}: the test seam. */
    static PollTransport httpTransport(Supplier<String> pollUrl, ReceiverBearer bearer, OutboundHttp http, Duration total) {
        return bodyJson -> {
            String url = pollUrl.get();
            if (url == null) {
                return null;
            }
            String token = bearer.token();
            OutboundResponse resp = send(http, url, bodyJson, token, total);
            if (resp.status() == 401) {
                bearer.rejected(token);
                resp = send(http, url, bodyJson, bearer.token(), total);
            }
            if (resp.status() != 200) {
                throw new IllegalStateException("poll endpoint returned HTTP " + resp.status());
            }
            return resp.bodyText();
        };
    }

    private static OutboundResponse send(OutboundHttp http, String url, String bodyJson, String token, Duration total)
            throws OutboundHttpException {
        OutboundRequest.Builder b = OutboundRequest.post(url)
                .header("Accept", "application/json")
                .body("application/json", bodyJson);
        if (token != null && !token.isBlank()) {
            b.header("Authorization", "Bearer " + token);
        }
        return withReason(http, b.build(), total);
    }

    /**
     * Sends {@code request} by {@code total}; a failure keeps its type and gains its reason ({@code HEADER_TIMEOUT},
     * {@code DEADLINE}, {@code TLS} and the rest) at the front of its message, which is what the receiver's log shows.
     */
    static OutboundResponse withReason(OutboundHttp http, OutboundRequest request, Duration total)
            throws OutboundHttpException {
        try {
            return http.send(request, Deadline.after(total));
        } catch (OutboundHttpException e) {
            throw new OutboundHttpException(e.reason(), e.reason() + ": " + request.method() + " " + request.uri() + ": "
                    + e.getMessage(), e);
        }
    }
}
