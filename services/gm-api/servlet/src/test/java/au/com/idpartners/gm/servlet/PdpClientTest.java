package au.com.idpartners.gm.servlet;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The PDP call is the one part of an evaluation this server does not make local, and it is
 * where "I could not ask" must never be confused with "the answer is no" — see
 * {@link PdpClient#evaluate}. These tests run a real loopback HTTP server (no PF, no
 * mocking library on this vendored module's classpath) so the fail-closed contract is
 * pinned against real sockets, not assumptions about what {@code HttpURLConnection} does.
 */
class PdpClientTest {

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private String start(com.sun.net.httpserver.HttpHandler handler) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", handler);
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private static void respond(com.sun.net.httpserver.HttpExchange ex, int status, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = ex.getResponseBody()) {
            out.write(bytes);
        }
    }

    // ---- URL construction (no network needed) --------------------------------------------

    @Test
    void appendsTheAuthzenPathsToTheBaseUrl() {
        PdpClient client = new PdpClient("https://pdp.example.com", null, 1000);
        assertEquals("https://pdp.example.com/access/v1/evaluation", client.getEvaluationUrl());
        assertEquals("https://pdp.example.com/access/v1/search/resource", client.getResourceSearchUrl());
    }

    @Test
    void stripsATrailingSlashFromTheBaseUrl() {
        PdpClient client = new PdpClient("https://pdp.example.com/", null, 1000);
        assertEquals("https://pdp.example.com/access/v1/evaluation", client.getEvaluationUrl());
    }

    // ---- the happy path --------------------------------------------------------------------

    @Test
    void evaluateDecodesA200Response() throws Exception {
        String base = start((ex) -> {
            assertEquals("/access/v1/evaluation", ex.getRequestURI().getPath());
            respond(ex, 200, "{\"decision\":true}");
        });
        PdpClient client = new PdpClient(base, null, 2000);

        Map<String, Object> result = client.evaluate(Map.of("subject", Map.of("id", "alice")));
        assertEquals(Boolean.TRUE, result.get("decision"));
    }

    @Test
    void searchPostsToTheResourceSearchPathNotEvaluation() throws Exception {
        String base = start((ex) -> {
            assertEquals("/access/v1/search/resource", ex.getRequestURI().getPath());
            respond(ex, 200, "{\"results\":[{\"type\":\"account\",\"id\":\"111\"}]}");
        });
        PdpClient client = new PdpClient(base, null, 2000);

        Map<String, Object> result = client.search(Map.of("subject", Map.of("id", "alice")));
        assertTrue(result.get("results") instanceof java.util.List);
    }

    @Test
    void aBearerTokenIsSentWhenConfigured() throws Exception {
        AtomicReference<String> seenAuth = new AtomicReference<>();
        String base = start((ex) -> {
            seenAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            respond(ex, 200, "{\"decision\":true}");
        });
        PdpClient client = new PdpClient(base, "pdp-credential", 2000);

        client.evaluate(Map.of());
        assertEquals("Bearer pdp-credential", seenAuth.get());
    }

    @Test
    void noAuthorizationHeaderIsSentWhenNoTokenIsConfigured() throws Exception {
        AtomicReference<String> seenAuth = new AtomicReference<>();
        String base = start((ex) -> {
            seenAuth.set(ex.getRequestHeaders().getFirst("Authorization"));
            respond(ex, 200, "{\"decision\":false}");
        });
        PdpClient client = new PdpClient(base, null, 2000);

        client.evaluate(Map.of());
        assertNull(seenAuth.get(), "an unprotected PDP must not be sent a stray credential");
    }

    // ---- fail-closed: an outage must not read as an answer -----------------------------------

    @Test
    void aNon200ResponseIsAnUnavailablePdpNotADenial() throws Exception {
        String base = start((ex) -> respond(ex, 500, "{\"error\":\"internal\"}"));
        PdpClient client = new PdpClient(base, null, 2000);

        PdpClient.PdpUnavailableException e = assertThrows(PdpClient.PdpUnavailableException.class,
                () -> client.evaluate(Map.of()));
        assertTrue(e.getMessage().contains("500"), e.getMessage());
    }

    @Test
    void anUnreachableHostIsAnUnavailablePdp() throws Exception {
        // A closed local port: nothing is listening, so the connection itself fails - the
        // network-outage half of "I could not ask", distinct from a PDP that answered badly.
        int deadPort;
        try (ServerSocket s = new ServerSocket(0)) {
            deadPort = s.getLocalPort();
        }
        PdpClient client = new PdpClient("http://127.0.0.1:" + deadPort, null, 1000);

        assertThrows(PdpClient.PdpUnavailableException.class, () -> client.evaluate(Map.of()));
    }

    @Test
    void aMalformedJsonBodyIsAnUnavailablePdpNotACrash() throws Exception {
        String base = start((ex) -> respond(ex, 200, "not json at all"));
        PdpClient client = new PdpClient(base, null, 2000);

        assertThrows(PdpClient.PdpUnavailableException.class, () -> client.evaluate(Map.of()));
    }

    @Test
    void aLiteralNullBodyDecodesToNullRatherThanThrowing() throws Exception {
        // Jackson decodes the JSON literal `null` to a null Map instead of throwing; the
        // caller (GrantOperations) is the one that must turn that into an outage, not this
        // class - pinning the contract here is what makes that downstream check meaningful.
        String base = start((ex) -> respond(ex, 200, "null"));
        PdpClient client = new PdpClient(base, null, 2000);

        assertNull(client.evaluate(Map.of()));
    }
}
