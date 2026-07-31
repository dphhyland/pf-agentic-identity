/*
 * The HTTP surface of the enrolment service.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Executors;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A small HTTP front end over {@link EnrolmentService}, on the JDK's own server.
 *
 * <p>No framework, matching the rest of this repo: the surface is five endpoints, all of the logic
 * lives in the service, and a framework would add dependencies to a component that sits on the token
 * path without earning any of them.
 *
 * <pre>
 *   POST /enrol/challenge     → a one-time challenge
 *   POST /enrol               → run the ceremony, return the first attestation
 *   POST /attestation         → re-mint (the hot path; enforces the time-box)
 *   POST /user-verification   → refresh the time-box from a fresh IdP authentication
 *   POST /compliance          → apply a device compliance signal
 *   GET  /.well-known/jwks.json → the attester's public keys, so PingFederate can verify us
 *   GET  /health
 * </pre>
 *
 * <p>Errors are the OAuth shape — {@code {"error", "error_description"}} — with the service's stable
 * code, so a client can branch on {@code user_verification_required} rather than parsing prose.
 */
public final class EnrolmentHttpServer {

    private static final Log LOGGER = LogFactory.getLog(EnrolmentHttpServer.class);
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final int WORKER_THREADS = Math.max(8, Runtime.getRuntime().availableProcessors() * 2);

    private final EnrolmentService service;
    private final JwsSigner signer;
    private final HttpServer http;

    public EnrolmentHttpServer(EnrolmentService service, JwsSigner signer, int port) throws IOException {
        this.service = Objects.requireNonNull(service, "service");
        this.signer = Objects.requireNonNull(signer, "signer");
        this.http = HttpServer.create(new InetSocketAddress(port), 0);
        // Bounded on purpose: every request does signature verification or a database round trip, so an
        // unbounded pool would convert a traffic spike into memory exhaustion rather than backpressure.
        this.http.setExecutor(Executors.newFixedThreadPool(WORKER_THREADS));

        route("/enrol/challenge", this::challenge);
        route("/enrol", this::enrol);
        route("/attestation", this::attestation);
        route("/user-verification", this::userVerification);
        route("/compliance", this::compliance);
        route("/.well-known/jwks.json", this::jwks);
        route("/health", exchange -> Map.of("status", "ok"));
    }

    public void start() {
        this.http.start();
        LOGGER.info((Object) ("device-enrolment listening on " + this.http.getAddress()));
    }

    public void stop() {
        this.http.stop(0);
    }

    /** The bound port — useful when constructed with port 0 in tests. */
    public int port() {
        return this.http.getAddress().getPort();
    }

    // ---- handlers ----------------------------------------------------------------------------

    private Map<String, Object> challenge(HttpExchange exchange) {
        EnrolmentService.Challenge issued = this.service.issueChallenge();
        return Map.of("challenge", issued.challenge(), "expires_in", issued.expiresInSeconds());
    }

    private Map<String, Object> enrol(HttpExchange exchange) throws Exception {
        JsonNode body = readJson(exchange);
        EnrolmentService.Enrolled enrolled = this.service.enrol(new EnrolmentService.EnrolmentRequest(
                binary(body, "appattest_object"),
                body.hasNonNull("appattest_key_id") ? binary(body, "appattest_key_id") : null,
                object(body, "enclave_public_jwk"),
                text(body, "challenge"),
                text(body, "user_authentication"),
                text(body, "platform"),
                text(body, "model"),
                text(body, "os_version"),
                text(body, "agent_build")));

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("instance_id", enrolled.instanceId());
        response.put("attestation", enrolled.attestation());
        response.put("expires_in", enrolled.expiresInSeconds());
        response.put("appattest_key_id", enrolled.appAttestKeyId());
        return response;
    }

    private Map<String, Object> attestation(HttpExchange exchange) throws Exception {
        JsonNode body = readJson(exchange);
        EnrolmentService.Reissued reissued = this.service.reissue(new EnrolmentService.ReissueRequest(
                text(body, "instance_id"), text(body, "key_proof")));
        return Map.of("attestation", reissued.attestation(), "expires_in", reissued.expiresInSeconds());
    }

    private Map<String, Object> userVerification(HttpExchange exchange) throws Exception {
        JsonNode body = readJson(exchange);
        this.service.refreshUserVerification(text(body, "instance_id"), text(body, "user_authentication"));
        return Map.of("status", "ok");
    }

    private Map<String, Object> compliance(HttpExchange exchange) throws Exception {
        JsonNode body = readJson(exchange);
        this.service.applyComplianceChange(text(body, "device_id"),
                ComplianceState.fromCaepValue(text(body, "current_status")), Instant.now());
        return Map.of("status", "ok");
    }

    /** The attester's public keys. PingFederate resolves these to verify the attestations we mint. */
    private Map<String, Object> jwks(HttpExchange exchange) {
        return Map.of("keys", List.of(this.signer.publicJwk()));
    }

    // ---- plumbing ----------------------------------------------------------------------------

    private interface Handler {
        Map<String, Object> handle(HttpExchange exchange) throws Exception;
    }

    private void route(String path, Handler handler) {
        this.http.createContext(path, exchange -> {
            // Nothing here is cacheable: challenges are one-time and attestations are bearer-adjacent.
            exchange.getResponseHeaders().add("Cache-Control", "no-store");
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            try {
                write(exchange, 200, handler.handle(exchange));
            } catch (EnrolmentException e) {
                if (e.status() >= 500) {
                    LOGGER.warn((Object) ("enrolment failed: " + e.error() + " — " + e.getMessage()), e);
                } else {
                    LOGGER.info((Object) ("enrolment refused: " + e.error() + " — " + e.getMessage()));
                }
                write(exchange, e.status(), error(e.error(), e.getMessage()));
            } catch (Exception e) {
                LOGGER.error((Object) "unhandled failure in the enrolment surface", e);
                write(exchange, 500, error(EnrolmentException.SERVER_ERROR, "unexpected failure"));
            } finally {
                exchange.close();
            }
        });
    }

    private static JsonNode readJson(HttpExchange exchange) throws EnrolmentException {
        try {
            return JSON.readTree(exchange.getRequestBody().readAllBytes());
        } catch (Exception e) {
            throw EnrolmentException.invalidRequest("request body is not valid JSON");
        }
    }

    private static String text(JsonNode body, String field) {
        JsonNode node = body.get(field);
        return node == null || node.isNull() ? null : node.asText();
    }

    private static byte[] binary(JsonNode body, String field) throws EnrolmentException {
        String value = text(body, field);
        if (value == null) {
            throw EnrolmentException.invalidRequest("missing '" + field + "'");
        }
        try {
            return B64URL.decode(value);
        } catch (IllegalArgumentException e) {
            throw EnrolmentException.invalidRequest("'" + field + "' is not base64url");
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(JsonNode body, String field) throws EnrolmentException {
        JsonNode node = body.get(field);
        if (node == null || !node.isObject()) {
            throw EnrolmentException.invalidRequest("'" + field + "' must be a JSON object");
        }
        return JSON.convertValue(node, Map.class);
    }

    private static Map<String, Object> error(String code, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        body.put("error_description", description);
        return body;
    }

    private static void write(HttpExchange exchange, int status, Map<String, Object> body)
            throws IOException {
        byte[] bytes = JSON.writeValueAsBytes(body);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /** Reads the whole request body as UTF-8, for the rare non-JSON case. */
    static String bodyAsString(HttpExchange exchange) throws IOException {
        return new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }
}
