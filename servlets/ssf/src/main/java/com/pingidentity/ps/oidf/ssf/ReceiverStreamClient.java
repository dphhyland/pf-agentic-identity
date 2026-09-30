/*
 * Client for registering this receiver with a remote SSF transmitter (stream create / subject / verify).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import com.pingidentity.ps.oidf.signals.SubjectId;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.jose4j.json.JsonUtil;

/**
 * A thin client for the transmitter-side SSF Stream Management API, from the receiver's point of view:
 * create a stream (push delivery pointing at our {@code /ssf/receiver/events}, or poll), add subjects, and
 * request a verification SET. HTTP is behind {@link HttpJson} for tests; {@link #httpTransport} is the
 * runtime implementation (bearer auth, JSON in/out).
 *
 * <p>{@link #ensure} is what the receiver runs at start-up when {@code OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL}
 * is set (plan item H-SSF-1): it reads the transmitter's configuration metadata, finds the receiver's stream at the
 * transmitter's configuration endpoint or creates it, brings its events (and a push stream's delivery) into step with
 * the receiver's settings, and returns the stream's id and, for a poll stream, the URL to poll. What it checks is
 * SSF 1.0's: §7.2.4, "The "issuer" value returned MUST be identical to the Issuer URL that was directly used to
 * retrieve the configuration information"; §8.1.1.1-§8.1.1.3, "The Receiver MUST check the response and confirm that
 * the iss value matches the Issuer from which it received the Transmitter Configuration data"; and the stream's
 * {@code aud} holds the audience the receiver's verifier expects, without which every SET on it would be refused.
 * A stream it created and then could not accept is deleted again, so a failed start leaves no half-set-up stream.
 */
public final class ReceiverStreamClient {

    /** One JSON call: method + url + body (null for GET/DELETE) → response body. */
    public interface HttpJson {
        String call(String method, String url, String bodyJson) throws Exception;
    }

    /**
     * A refusal that retrying cannot mend - the transmitter's metadata or stream is not what the receiver's settings
     * expect - so the receiver is {@code FAILED_CONFIG}, not waiting on a dependency.
     */
    public static final class Misconfigured extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        public Misconfigured(String message) {
            super(message);
        }
    }

    /** What the receiver wants of its stream: from its settings. */
    public record Plan(String configurationUrl, String expectedIssuer, String audience, List<String> events,
            String pushEndpointUrl, String pushAuthorizationToken) {
    }

    /** The receiver's stream as it stands: its id, the URL to poll (null for push) and the critical subject members. */
    public record Setup(String streamId, String pollUrl, Set<String> criticalSubjectMembers) {
    }

    private final String transmitterBase;
    private final HttpJson http;

    public ReceiverStreamClient(String transmitterBase, HttpJson http) {
        this.transmitterBase = Objects.requireNonNull(transmitterBase, "transmitterBase").replaceAll("/$", "");
        this.http = Objects.requireNonNull(http, "http");
    }

    /**
     * Create a push stream delivering to {@code receiverEndpointUrl}; returns the stream id. {@code audience}
     * is the {@code aud} this receiver expects its SETs under, or null to take whatever the transmitter
     * assigns (its client id, on this repo's transmitter).
     */
    public String createPushStream(String audience, List<String> events, String receiverEndpointUrl,
                                   String receiverEndpointBearer) throws Exception {
        LinkedHashMap<String, Object> delivery = new LinkedHashMap<>();
        delivery.put("method", DeliveryMethod.PUSH.urn());
        delivery.put("endpoint_url", receiverEndpointUrl);
        if (receiverEndpointBearer != null && !receiverEndpointBearer.isBlank()) {
            delivery.put("authorization_header", "Bearer " + receiverEndpointBearer);
        }
        return createStream(audience, events, delivery);
    }

    /** Create a poll stream; returns the stream id (poll URL is in the returned config). */
    public String createPollStream(String audience, List<String> events) throws Exception {
        return createStream(audience, events, Map.of("method", DeliveryMethod.POLL.urn()));
    }

    private String createStream(String audience, List<String> events, Map<String, Object> delivery) throws Exception {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        // aud is the transmitter's to supply (SSF §8.1.1). Naming one asks for an audience agreed out of
        // band, and a transmitter that has not agreed it refuses; null leaves the choice to the transmitter.
        if (audience != null) {
            body.put("aud", audience);
        }
        body.put("delivery", delivery);
        body.put("events_requested", events);
        Map<String, Object> resp = JsonUtil.parseJson(
                this.http.call("POST", this.transmitterBase + "/ssf/streams", JsonUtil.toJson(body)));
        Object id = resp.get("stream_id");
        if (!(id instanceof String) || ((String) id).isBlank()) {
            throw new IllegalStateException("stream create returned no stream_id: " + resp);
        }
        if (audience != null && !audience.equals(resp.get("aud"))) {
            throw new IllegalStateException("stream " + id + " was created with aud " + resp.get("aud") + ", not " + audience);
        }
        return (String) id;
    }

    /**
     * Finds or creates the receiver's stream at the transmitter {@code plan} describes, in step with it (see the class
     * comment). A push stream is the one delivering to {@code plan.pushEndpointUrl()}; a poll stream is the first poll
     * stream the transmitter lists for this receiver.
     *
     * @throws Misconfigured when the transmitter's metadata or stream does not match the receiver's settings
     * @throws Exception     when the transmitter cannot be reached or refuses a call: retried by the supervisor
     */
    public static Setup ensure(HttpJson http, Plan plan) throws Exception {
        Map<String, Object> metadata = JsonUtil.parseJson(http.call("GET", plan.configurationUrl(), null));
        if (!plan.expectedIssuer().equals(metadata.get("issuer"))) {
            throw new Misconfigured("the transmitter's configuration names issuer " + metadata.get("issuer") + ", not "
                    + plan.expectedIssuer() + " (SSF 1.0 §7.2.4)");
        }
        Object endpoint = metadata.get("configuration_endpoint");
        if (!(endpoint instanceof String)) {
            throw new Misconfigured("the transmitter's configuration has no configuration_endpoint, so it offers no"
                    + " stream management");
        }
        String configurationEndpoint = requireTls((String) endpoint, "configuration_endpoint", plan);
        boolean push = plan.pushEndpointUrl() != null;
        Map<String, Object> existing = find(streams(http.call("GET", configurationEndpoint, null)), plan);
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        if (existing != null) {
            body.put("stream_id", existing.get("stream_id"));
        }
        body.put("events_requested", plan.events());
        if (push || existing == null) {
            body.put("delivery", delivery(plan));
        }
        Map<String, Object> stream = JsonUtil.parseJson(http.call(existing == null ? "POST" : "PATCH",
                configurationEndpoint, JsonUtil.toJson(body)));
        Object id = stream.get("stream_id");
        String pollUrl;
        try {
            if (!(id instanceof String) || ((String) id).isBlank()) {
                throw new IllegalStateException("the transmitter answered with no stream_id: " + stream.keySet());
            }
            check(stream, plan);
            pollUrl = push ? null : endpointOf(stream);
            if (!push && pollUrl == null) {
                throw new Misconfigured("the transmitter's poll stream " + id + " names no endpoint_url to poll");
            }
            if (pollUrl != null) {
                requireTls(pollUrl, "the poll stream's endpoint_url", plan);
            }
        } catch (RuntimeException e) {
            if (existing == null && id instanceof String && !((String) id).isBlank()) {
                deleteQuietly(http, configurationEndpoint, (String) id, e);
            }
            throw e;
        }
        return new Setup((String) id, pollUrl, strings(metadata.get("critical_subject_members")));
    }

    /**
     * Deletes a stream this start created and could not accept, so no half-set-up stream is left; a delete that fails
     * is added to {@code cause} as suppressed, and {@code cause} is what the caller sees.
     */
    private static void deleteQuietly(HttpJson http, String configurationEndpoint, String id, RuntimeException cause) {
        try {
            http.call("DELETE", configurationEndpoint + "?stream_id=" + URLEncoder.encode(id, StandardCharsets.UTF_8),
                    null);
        } catch (Exception e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            cause.addSuppressed(e);
        }
    }

    /**
     * A URL the transmitter names, which the receiver will send its bearer token to: https, unless the configuration URL
     * the receiver was given is itself http (the development profile only; production refuses an http
     * {@code OIDF_SSF_RECEIVER_TRANSMITTER_CONFIGURATION_URL}). SSF 1.0 §7.1 on {@code configuration_endpoint}: "If
     * present, this URL MUST use HTTP over TLS [RFC9110]"; RFC 8936 §3, for the poll: "The SET delivery method described
     * in this specification is based upon HTTP over TLS [RFC2818]".
     *
     * @throws Misconfigured when {@code url} is not https and the configuration URL is
     */
    static String requireTls(String url, String what, Plan plan) {
        boolean developmentHttp = plan.configurationUrl().regionMatches(true, 0, "http://", 0, 7);
        if (!url.regionMatches(true, 0, "https://", 0, 8) && !developmentHttp) {
            throw new Misconfigured("the transmitter names " + what + " " + url + ", which is not https: the receiver's"
                    + " token is not sent there (SSF 1.0 §7.1, RFC 8936 §3)");
        }
        return url;
    }

    /** The stream's {@code iss} and {@code aud} are what the receiver verifies its SETs against. */
    private static void check(Map<String, Object> stream, Plan plan) {
        if (!plan.expectedIssuer().equals(stream.get("iss"))) {
            throw new Misconfigured("stream " + stream.get("stream_id") + " names iss " + stream.get("iss") + ", not "
                    + plan.expectedIssuer() + " (SSF 1.0 §8.1.1.1)");
        }
        Object aud = stream.get("aud");
        if (!(aud instanceof String ? aud.equals(plan.audience()) : strings(aud).contains(plan.audience()))) {
            throw new Misconfigured("stream " + stream.get("stream_id") + " has aud " + aud + ", which does not hold the"
                    + " receiver's audience " + plan.audience() + ": its SETs would all be refused");
        }
    }

    private static Map<String, Object> delivery(Plan plan) {
        LinkedHashMap<String, Object> delivery = new LinkedHashMap<>();
        if (plan.pushEndpointUrl() == null) {
            delivery.put("method", DeliveryMethod.POLL.urn());
            return delivery;
        }
        delivery.put("method", DeliveryMethod.PUSH.urn());
        delivery.put("endpoint_url", plan.pushEndpointUrl());
        delivery.put("authorization_header", "Bearer " + plan.pushAuthorizationToken());
        return delivery;
    }

    /** The receiver's stream among {@code streams}: a push stream to its endpoint, or its first poll stream. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> find(List<Map<String, Object>> streams, Plan plan) {
        String method = plan.pushEndpointUrl() == null ? DeliveryMethod.POLL.urn() : DeliveryMethod.PUSH.urn();
        for (Map<String, Object> s : streams) {
            Object d = s.get("delivery");
            if (!(d instanceof Map) || !method.equals(((Map<String, Object>) d).get("method"))) {
                continue;
            }
            if (plan.pushEndpointUrl() == null || plan.pushEndpointUrl().equals(((Map<String, Object>) d).get("endpoint_url"))) {
                return s;
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static String endpointOf(Map<String, Object> stream) {
        Object d = stream.get("delivery");
        Object url = d instanceof Map ? ((Map<String, Object>) d).get("endpoint_url") : null;
        return url instanceof String ? (String) url : null;
    }

    /**
     * The configuration endpoint's list: SSF 1.0 §8.1.1.2, "If the "stream_id" parameter is missing, then the
     * Transmitter MUST return a list of the stream configurations available to this Receiver"; one object is read as
     * a list of one.
     */
    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> streams(String body) throws Exception {
        Object parsed = JsonUtil.parseJson("{\"v\":" + body + "}").get("v");
        List<Map<String, Object>> out = new ArrayList<>();
        if (parsed instanceof Map) {
            out.add((Map<String, Object>) parsed);
        } else if (parsed instanceof List) {
            for (Object o : (List<Object>) parsed) {
                if (o instanceof Map) {
                    out.add((Map<String, Object>) o);
                }
            }
        }
        return out;
    }

    private static Set<String> strings(Object v) {
        Set<String> out = new LinkedHashSet<>();
        if (v instanceof List) {
            for (Object o : (List<?>) v) {
                if (o instanceof String) {
                    out.add((String) o);
                }
            }
        }
        return out;
    }

    public void addSubject(String streamId, SubjectId subject) throws Exception {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", streamId);
        body.put("subject", subject.toMap());
        this.http.call("POST", this.transmitterBase + "/ssf/subjects:add", JsonUtil.toJson(body));
    }

    /** Ask the transmitter to emit a verification SET with {@code state} echoed. */
    public void requestVerification(String streamId, String state) throws Exception {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("stream_id", streamId);
        if (state != null) {
            body.put("state", state);
        }
        this.http.call("POST", this.transmitterBase + "/ssf/verify", JsonUtil.toJson(body));
    }

    public void deleteStream(String streamId) throws Exception {
        this.http.call("DELETE", this.transmitterBase + "/ssf/streams?stream_id=" + streamId, null);
    }

    /**
     * The deadlines of one stream management call, which runs in the receiver's start: connecting (TLS included)
     * within 1 s, and the whole exchange within 5 s. Its body is platform's default cap, 256 KiB: a list of streams.
     */
    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(1);
    static final Duration TOTAL_TIMEOUT = Duration.ofSeconds(5);

    /**
     * Runtime transport: JSON calls with the receiver's bearer - {@code bearer}'s token, asked again once after a
     * 401 - through platform's {@link OutboundHttp} under the receiver's rules ({@link PollReceiverClient#receiverPolicy}).
     * {@code insecureTls} is the receiver's switch and trusts any certificate chain through platform's
     * {@link InsecureTls}; the host name is still checked. A call that fails - no answer by its deadline, or one
     * the transmitter refuses - throws, and the receiver's start is retried as {@code FAILED_DEPENDENCY}.
     */
    public static HttpJson httpTransport(ReceiverBearer bearer, boolean insecureTls) {
        return httpTransport(bearer, PollReceiverClient.receiverHttp(PollReceiverClient.receiverPolicy(), insecureTls,
                CONNECT_TIMEOUT, OutboundHttp.DEFAULT_MAX_BODY_BYTES), TOTAL_TIMEOUT);
    }

    /** The transport over {@code http}, each exchange within {@code total}: the test seam. */
    static HttpJson httpTransport(ReceiverBearer bearer, OutboundHttp http, Duration total) {
        return (method, url, bodyJson) -> {
            String token = bearer.token();
            OutboundResponse resp = send(http, method, url, bodyJson, token, total);
            if (resp.status() == 401) {
                bearer.rejected(token);
                resp = send(http, method, url, bodyJson, bearer.token(), total);
            }
            if (resp.status() >= 300) {
                throw new IllegalStateException(method + " " + url + " returned HTTP " + resp.status()
                        + ": " + resp.bodyText());
            }
            return resp.bodyText();
        };
    }

    private static OutboundResponse send(OutboundHttp http, String method, String url, String bodyJson, String token,
            Duration total) throws OutboundHttpException {
        OutboundRequest.Builder b = OutboundRequest.builder(OutboundRequest.Method.valueOf(method), URI.create(url))
                .header("Accept", "application/json");
        if (token != null && !token.isBlank()) {
            b.header("Authorization", "Bearer " + token);
        }
        if (bodyJson != null) {
            b.body("application/json", bodyJson);
        }
        return PollReceiverClient.withReason(http, b.build(), total);
    }
}
