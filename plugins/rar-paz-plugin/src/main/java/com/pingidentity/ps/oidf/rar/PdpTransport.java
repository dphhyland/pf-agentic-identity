/*
 * The PDP call on platform's outbound HTTP client: deadlines, a body cap, the instance's TLS trust, a bulkhead.
 */
package com.pingidentity.ps.oidf.rar;

import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.Bulkhead;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;

import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.nio.channels.ClosedChannelException;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

/**
 * Posts to the PDP through platform's {@link OutboundHttp} (plan item S2c, and S5d's call site in this plugin), which
 * replaced the JDK's {@code java.net.http} client here in 0.6.0:
 *
 * <ul>
 *   <li>a total deadline for the whole exchange, body included ("Request timeout (ms)", 2500 by default, held to
 *       {@value #MIN_TOTAL_MILLIS}-{@value #MAX_TOTAL_MILLIS}); connecting, TLS included, gets at most
 *       {@link #CONNECT_TIMEOUT} of it. The JDK client's timeout ended when the headers arrived, so a PDP that
 *       dribbled its body could hold the token request for as long as it liked (F-0010);</li>
 *   <li>a response body of at most {@value #MAX_BODY_BYTES} bytes;</li>
 *   <li>HTTP/1.1, one request per connection, no redirects;</li>
 *   <li>the TLS trust the instance chose ({@link PdpTls}), and the certificate always checked against the host the
 *       URL names: platform's transport sets HTTPS endpoint identification on every connection and has no switch
 *       that turns it off, so the JVM-wide {@code jdk.internal.httpclient.disableHostnameVerification}, which only
 *       ever governed {@code java.net.http}, has no effect on this call;</li>
 *   <li>private addresses allowed (the PDP is usually internal) and {@code http} only in development, the rule
 *       {@link PdpUrlPolicy} already applies to the URL;</li>
 *   <li>at most {@value #MAX_CONCURRENT} calls at once per processor instance ({@link InstanceBulkhead}): a call that
 *       finds every place taken waits for one until its own deadline and is then unreachable.</li>
 * </ul>
 *
 * <p>What platform throws is sorted into two classes before it leaves here, because the processor grants through
 * exactly one of them when fail-open is on: {@link #classify}.
 */
final class PdpTransport implements HttpTransport {

    /** The processor's field that turns the trust-all on, as the admin console labels it: the setting InsecureTls names. */
    static final String INSECURE_TLS_SETTING = "Skip TLS verification (dev only)";

    static final int DEFAULT_TOTAL_MILLIS = 2_500;
    static final int MIN_TOTAL_MILLIS = 1_000;
    static final int MAX_TOTAL_MILLIS = 10_000;
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(1);
    static final long MAX_BODY_BYTES = 64L * 1024L;
    static final int MAX_CONCURRENT = 32;

    private final PdpTls tls;
    private final AddressPolicy policy;
    private final Bulkhead bulkhead;
    private final Duration total;
    private TlsTrust builtFor;
    private OutboundHttp client;

    /** The transport {@code configure} builds: private networks allowed, http only when {@code allowHttp}. */
    PdpTransport(PdpTls tls, int totalMillis, boolean allowHttp) {
        this(tls, totalMillis, AddressPolicy.builder().allowHttp(allowHttp).allowPrivateNetworks(true).build(),
                new InstanceBulkhead(MAX_CONCURRENT));
    }

    /** Test seam: the address policy and the bulkhead of the test's choosing. */
    PdpTransport(PdpTls tls, int totalMillis, AddressPolicy policy, Bulkhead bulkhead) {
        this.tls = tls;
        this.total = Duration.ofMillis(totalMillisOf(totalMillis));
        this.policy = policy;
        this.bulkhead = bulkhead;
    }

    /** The field's value held to {@value #MIN_TOTAL_MILLIS}-{@value #MAX_TOTAL_MILLIS}; 0 or less is the default. */
    static int totalMillisOf(int configured) {
        if (configured <= 0) {
            return DEFAULT_TOTAL_MILLIS;
        }
        return Math.max(MIN_TOTAL_MILLIS, Math.min(MAX_TOTAL_MILLIS, configured));
    }

    Duration total() {
        return total;
    }

    PdpTls tls() {
        return tls;
    }

    /** The client for the trust in force now, rebuilt only when the trust changed (PingFederate's CAs reloaded). */
    private synchronized OutboundHttp client() throws IOException {
        TlsTrust trust = tls.current();
        if (client == null || trust != builtFor) {
            client = OutboundHttp.builder(policy)
                    .tls(trust)
                    .bulkhead(bulkhead)
                    .connectTimeout(CONNECT_TIMEOUT)
                    .headerTimeout(total)
                    .maxBodyBytes(MAX_BODY_BYTES)
                    .userAgent("pf-rar-paz-plugin")
                    .build();
            builtFor = trust;
        }
        return client;
    }

    @Override
    public Response post(String url, String body, Map<String, String> headers) throws IOException {
        Deadline deadline = Deadline.after(total);
        OutboundHttp http = client();
        OutboundRequest request;
        try {
            OutboundRequest.Builder rb = OutboundRequest.post(url);
            String contentType = PdpResponses.APPLICATION_JSON;
            if (headers != null) {
                for (Map.Entry<String, String> header : headers.entrySet()) {
                    if ("content-type".equalsIgnoreCase(header.getKey())) {
                        contentType = header.getValue();
                    } else {
                        rb.header(header.getKey(), header.getValue());
                    }
                }
            }
            request = rb.body(contentType, body == null ? "" : body).build();
        } catch (IllegalArgumentException e) {
            // A URL that is not one, or a header value that could split the message: nothing was sent.
            throw new IOException("the PDP request could not be built: " + e.getMessage(), e);
        }
        try {
            OutboundResponse response = http.send(request, deadline);
            return new Response(response.status(), response.bodyText(), response.header("Content-Type").orElse(null));
        } catch (OutboundHttpException e) {
            throw classify(e);
        }
    }

    /** The reasons that mean the PDP was not reached, or did not answer in time. */
    static final Set<OutboundHttpException.Reason> UNREACHABLE = Set.of(
            OutboundHttpException.Reason.UNRESOLVED,
            OutboundHttpException.Reason.BULKHEAD_FULL,
            OutboundHttpException.Reason.CONNECT_FAILED,
            OutboundHttpException.Reason.CONNECT_TIMEOUT,
            OutboundHttpException.Reason.HEADER_TIMEOUT,
            OutboundHttpException.Reason.DEADLINE,
            OutboundHttpException.Reason.BUDGET_EXHAUSTED);

    /**
     * Platform's failure as the plugin reads it: {@link PdpUnavailableException}, the one class fail-open grants
     * through and the circuit breaker counts, or a plain {@link IOException}, which refuses.
     *
     * <p>Unreachable: the name did not resolve, no address accepted a connection, connecting or the TLS handshake
     * ran out of time, the answer did not arrive by the deadline, or the bulkhead had no place before it
     * ({@link #UNREACHABLE}); and an I/O failure or a response cut short where the peer reset or closed the
     * connection under the request - a {@link SocketException}, {@link EOFException} or {@link ClosedChannelException}
     * in the cause chain, an I/O failure whose message starts with the JDK's "Connection reset", or HttpCore's
     * {@code NoHttpResponseException} or {@code ConnectionClosedException} (matched by simple name, because platform
     * relocates HttpCore and this plugin relocates platform). That is the set the JDK client's classifier counted
     * before 0.6.0: connect, reset, deadline.
     *
     * <p>Everything else refuses, because each means something answered or nothing was asked: a TLS failure (it
     * could not prove it was the PDP), a malformed response, a body over the cap, a URL or address the policy
     * refused, and an interrupted call.
     */
    static IOException classify(OutboundHttpException e) {
        OutboundHttpException.Reason reason = e.reason();
        boolean unreachable = UNREACHABLE.contains(reason)
                || ((reason == OutboundHttpException.Reason.IO || reason == OutboundHttpException.Reason.MALFORMED_RESPONSE)
                    && peerWentAway(e.getCause()));
        return unreachable ? new PdpUnavailableException("PDP unreachable (" + reason + "): " + e.getMessage(), e) : e;
    }

    /** Whether the chain says the connection was reset or closed under the request. Bounded: cycles are constructible. */
    static boolean peerWentAway(Throwable cause) {
        Throwable t = cause;
        for (int depth = 0; t != null && depth < 16; t = t.getCause(), depth++) {
            String name = t.getClass().getSimpleName();
            if (t instanceof SocketException || t instanceof EOFException || t instanceof ClosedChannelException
                    || "NoHttpResponseException".equals(name) || "ConnectionClosedException".equals(name)
                    || (t instanceof IOException && t.getMessage() != null
                        && t.getMessage().toLowerCase(Locale.ROOT).startsWith("connection reset"))) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        return "PdpTransport[" + tls + ", total " + total.toMillis() + " ms]";
    }

    /**
     * At most {@code max} PDP calls at once for one processor instance, whatever origin they go to (the PDP URL and the
     * batch URL share it). A call that finds every place taken waits for one until its own deadline and is then refused
     * with {@code BULKHEAD_FULL}, which {@link #classify} reads as unreachable. So a PDP that stops answering holds at
     * most {@code max} of PingFederate's request threads in this plugin at once for longer than a moment; the rest
     * wait no longer than they would have waited for the PDP.
     */
    static final class InstanceBulkhead implements Bulkhead {
        private final int max;
        private final Semaphore places;

        InstanceBulkhead(int max) {
            this.max = max;
            this.places = new Semaphore(max);
        }

        int available() {
            return places.availablePermits();
        }

        @Override
        public Permit enter(String origin, Deadline deadline) throws OutboundHttpException {
            boolean entered;
            try {
                entered = places.tryAcquire(deadline.remainingNanos(), TimeUnit.NANOSECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OutboundHttpException(OutboundHttpException.Reason.IO,
                        "interrupted while waiting for one of the " + max + " PDP call places", e);
            }
            if (!entered) {
                throw new OutboundHttpException(OutboundHttpException.Reason.BULKHEAD_FULL,
                        "all " + max + " PDP call places stayed taken until the deadline");
            }
            return places::release;
        }
    }
}
