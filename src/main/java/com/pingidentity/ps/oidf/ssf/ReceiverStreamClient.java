/*
 * Client for registering this receiver with a remote SSF transmitter (stream create / subject / verify).
 */
package com.pingidentity.ps.oidf.ssf;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.json.JsonUtil;

/**
 * A thin client for the transmitter-side SSF Stream Management API, from the receiver's point of view:
 * create a stream (push delivery pointing at our {@code /ssf/receiver/events}, or poll), add subjects, and
 * request a verification SET. HTTP is behind {@link HttpJson} for tests; {@link #httpTransport} is the
 * runtime implementation (bearer auth, JSON in/out).
 */
public final class ReceiverStreamClient {

    /** One JSON call: method + url + body (null for GET/DELETE) → response body. */
    public interface HttpJson {
        String call(String method, String url, String bodyJson) throws Exception;
    }

    private final String transmitterBase;
    private final HttpJson http;

    public ReceiverStreamClient(String transmitterBase, HttpJson http) {
        this.transmitterBase = Objects.requireNonNull(transmitterBase, "transmitterBase").replaceAll("/$", "");
        this.http = Objects.requireNonNull(http, "http");
    }

    /** Create a push stream delivering to {@code receiverEndpointUrl}; returns the stream id. */
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
        body.put("aud", audience);
        body.put("delivery", delivery);
        body.put("events_requested", events);
        Map<String, Object> resp = JsonUtil.parseJson(
                this.http.call("POST", this.transmitterBase + "/ssf/streams", JsonUtil.toJson(body)));
        Object id = resp.get("stream_id");
        if (!(id instanceof String) || ((String) id).isBlank()) {
            throw new IllegalStateException("stream create returned no stream_id: " + resp);
        }
        return (String) id;
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

    /** Runtime transport: JSON calls with a management bearer token. */
    public static HttpJson httpTransport(String bearerToken, boolean insecureTls) {
        HttpClient http = insecureTls ? PollReceiverClient.TrustAll.client() : HttpClient.newHttpClient();
        return (method, url, bodyJson) -> {
            HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url))
                    .header("Accept", "application/json")
                    .header("Authorization", "Bearer " + bearerToken);
            if (bodyJson != null) {
                b.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(bodyJson));
            } else {
                b.method(method, HttpRequest.BodyPublishers.noBody());
            }
            HttpResponse<String> resp = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 300) {
                throw new IllegalStateException(method + " " + url + " returned HTTP " + resp.statusCode()
                        + ": " + resp.body());
            }
            return resp.body();
        };
    }
}
