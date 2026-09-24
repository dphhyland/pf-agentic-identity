package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link JdkHttpClient}: POST reports the status instead of throwing on it, keeps the response headers,
 * reads through the body cap, and is screened by the outbound policy before a connection is made.
 */
class JdkHttpClientTest {

    private HttpServer server;
    private final AtomicInteger hits = new AtomicInteger();
    private final AtomicReference<String> lastBody = new AtomicReference<>();
    private final AtomicReference<String> lastContentType = new AtomicReference<>();
    private final AtomicReference<String> lastRequestId = new AtomicReference<>();
    private volatile int status = 200;
    private volatile String responseBody = "{\"decision\":true}";

    @BeforeEach
    void start() throws Exception {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/", exchange -> {
            this.hits.incrementAndGet();
            this.lastBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            this.lastContentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            this.lastRequestId.set(exchange.getRequestHeaders().getFirst("X-Request-ID"));
            byte[] body = this.responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Request-ID", "echoed-" + this.lastRequestId.get());
            exchange.sendResponseHeaders(this.status, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    private String url() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort() + "/access/v1/evaluation";
    }

    private JdkHttpClient client() {
        return new JdkHttpClient(false, OutboundUrlPolicy.fromEnvironment().trusting(url()),
                Duration.ofSeconds(2), Duration.ofSeconds(2));
    }

    @Test
    void postsAJsonBodyWithHeadersAndReturnsTheResponse() throws Exception {
        HttpPostClient.Response response = client().post(url(), "application/json", "{\"subject\":{}}",
                Map.of("X-Request-ID", "req-1"), "application/json");

        assertEquals(200, response.status());
        assertTrue(response.isSuccess());
        assertEquals("{\"decision\":true}", response.body());
        assertEquals("{\"subject\":{}}", this.lastBody.get());
        assertEquals("application/json", this.lastContentType.get());
        assertEquals("echoed-req-1", response.header("x-request-id").orElseThrow());
        assertFalse(response.header("x-absent").isPresent());
    }

    @Test
    void aNonSuccessStatusIsReportedNotThrown() throws Exception {
        this.status = 503;
        this.responseBody = "busy";

        HttpPostClient.Response response = client().post(url(), "application/json", "{}", null, null);

        assertEquals(503, response.status());
        assertFalse(response.isSuccess());
        assertEquals("busy", response.body());
    }

    @Test
    void postsAFormInOrder() throws Exception {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("trust_mark", "a.b.c");
        form.put("note", "two words & more");
        form.put("empty", null);

        client().postForm(url(), form, null, "application/trust-mark-status-response+jwt");

        assertEquals("trust_mark=a.b.c&note=two+words+%26+more&empty=", this.lastBody.get());
        assertEquals("application/x-www-form-urlencoded", this.lastContentType.get());
        assertEquals("", HttpPostClient.formEncode(null));
    }

    @Test
    void thePolicyRefusesBeforeAnyConnection() {
        JdkHttpClient refusing = new JdkHttpClient(false, OutboundUrlPolicy.fromEnvironment());

        assertThrows(IllegalArgumentException.class, () -> refusing.post(url(), "application/json", "{}", null, null));
        assertEquals(0, this.hits.get());
    }

    @Test
    void anOverCapBodyIsRefused() {
        this.responseBody = "x".repeat(4096);
        JdkHttpClient capped = new JdkHttpClient(false, OutboundUrlPolicy.from(name ->
                OutboundUrlPolicy.MAX_BODY_ENV.equals(name) ? "1024" : null).trusting(url()));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> capped.post(url(), "application/json", "{}", null, null));
        assertTrue(e.getMessage().contains("1024"), e.getMessage());
    }

    @Test
    void getStillThrowsOnANonSuccessStatus() throws Exception {
        JdkHttpClient client = client();
        assertEquals("{\"decision\":true}", client.get(url(), "application/json"));
        this.status = 404;
        assertThrows(IllegalArgumentException.class, () -> client.get(url(), "application/json"));
        assertEquals(client.policy().maxBodyBytes(), OutboundUrlPolicy.DEFAULT_MAX_BODY_BYTES);
    }

    @Test
    void theTrustAllVariantBuilds() {
        JdkHttpClient trustAll = new JdkHttpClient(true, OutboundUrlPolicy.permissive());
        assertEquals(Long.MAX_VALUE, trustAll.policy().maxBodyBytes());
    }

    @Test
    void responseHeadersDefaultToEmpty() {
        HttpPostClient.Response response = new HttpPostClient.Response(204, "", null);
        assertEquals(Map.of(), response.headers());
        assertEquals(List.of("v"), new HttpPostClient.Response(200, "", Map.of("K", List.of("v"))).headers().get("K"));
        assertFalse(new HttpPostClient.Response(200, "", Map.of("K", List.of())).header("k").isPresent());
    }
}
