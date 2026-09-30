package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A caller's deadline (a resolution's budget, plan item S5b) bounds the whole exchange, the body included, and ends it
 * sooner than the client's own request timeout would.
 */
class JdkHttpClientDeadlineTest {
    private static final byte[] BODY = "{\"slow\":\"body\"}".getBytes(StandardCharsets.UTF_8);

    private HttpServer server;
    private ExecutorService pool;

    @BeforeEach
    void start() throws Exception {
        this.pool = Executors.newCachedThreadPool();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 50);
        this.server.setExecutor(this.pool);
        // The status and headers at once, then the body a byte every 100 ms: about 1.5 s in all.
        this.server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, BODY.length);
            try (OutputStream out = exchange.getResponseBody()) {
                for (byte b : BODY) {
                    out.write(b);
                    out.flush();
                    Thread.sleep(100);
                }
            } catch (IOException | InterruptedException gone) {
                // the client stopped reading at its deadline
            }
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
        this.pool.shutdownNow();
    }

    private String url() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort() + "/";
    }

    /** A client whose own request timeout (30 s) would wait out the whole slow body. */
    private static JdkHttpClient patient() {
        return new JdkHttpClient(false, OutboundUrlPolicy.permissive(), Duration.ofSeconds(2), Duration.ofSeconds(30));
    }

    @Test
    void aSlowBodyIsCutOffAtTheCallersDeadline() {
        long started = System.nanoTime();
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> patient().get(url(), "application/json", Deadline.after(Duration.ofMillis(400))));
        long elapsed = (System.nanoTime() - started) / 1_000_000L;

        assertEquals(OutboundHttpException.Reason.DEADLINE, e.reason(), e.getMessage());
        assertTrue(elapsed < 1200, "stopped at the caller's 400 ms, not the body's 1.5 s or the 30 s timeout: " + elapsed + " ms");
    }

    @Test
    void aPostsSlowBodyIsCutOffAtTheCallersDeadline() {
        OutboundHttpException e = assertThrows(OutboundHttpException.class, () -> patient().postForm(url(), Map.of("a", "b"), null,
                "application/json", Deadline.after(Duration.ofMillis(400))));
        assertEquals(OutboundHttpException.Reason.DEADLINE, e.reason(), e.getMessage());
    }

    @Test
    void theClientsOwnTimeoutStillHoldsUnderALaterDeadline() {
        JdkHttpClient hasty = new JdkHttpClient(false, OutboundUrlPolicy.permissive(), Duration.ofSeconds(2), Duration.ofMillis(300));
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> hasty.get(url(), "application/json", Deadline.after(Duration.ofSeconds(30))));
        assertEquals(OutboundHttpException.Reason.DEADLINE, e.reason());
    }

    @Test
    void aBodyThatArrivesInTimeIsReturned() throws Exception {
        assertEquals(new String(BODY, StandardCharsets.UTF_8),
                patient().get(url(), "application/json", Deadline.after(Duration.ofSeconds(10))));
        assertEquals(200, patient().post(url(), "text/plain", "x", null, null, Deadline.after(Duration.ofSeconds(10))).status());
        // The GET-only view passes the deadline through.
        JdkHttpGetClient view = new JdkHttpGetClient(false, OutboundUrlPolicy.permissive());
        assertEquals(new String(BODY, StandardCharsets.UTF_8), view.get(url(), "application/json", Deadline.after(Duration.ofSeconds(10))));
        OutboundHttpException e = assertThrows(OutboundHttpException.class,
                () -> view.get(url(), "application/json", Deadline.after(Duration.ofMillis(300))));
        assertEquals(OutboundHttpException.Reason.DEADLINE, e.reason());
    }

    /** A client that cannot bound a request (a test's fake) still refuses to start one after the deadline. */
    @Test
    void theDefaultsRefuseAPassedDeadlineAndOtherwiseMakeTheRequest() throws Exception {
        List<String> made = new ArrayList<>();
        HttpGetClient get = (url, accept) -> {
            made.add("GET " + url);
            return "ok";
        };
        HttpPostClient post = (url, contentType, body, headers, accept) -> {
            made.add("POST " + url + " " + body);
            return new HttpPostClient.Response(204, "", Map.of());
        };
        Deadline passed = Deadline.after(Duration.ZERO);

        assertEquals(OutboundHttpException.Reason.DEADLINE,
                assertThrows(OutboundHttpException.class, () -> get.get("https://a.example/", "x", passed)).reason());
        assertEquals(OutboundHttpException.Reason.DEADLINE, assertThrows(OutboundHttpException.class,
                () -> post.postForm("https://a.example/", Map.of("k", "v"), null, null, passed)).reason());
        assertEquals(List.of(), made);

        Deadline later = Deadline.after(Duration.ofSeconds(30));
        assertEquals("ok", get.get("https://a.example/", "x", later));
        assertEquals(204, post.postForm("https://a.example/", Map.of("k", "v"), null, null, later).status());
        assertEquals(List.of("GET https://a.example/", "POST https://a.example/ k=v"), made);
    }
}
