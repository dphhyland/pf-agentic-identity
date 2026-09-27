package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.HostBulkhead;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException.Reason;
import com.pingidentity.ps.oidf.platform.http.TlsTrust;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * JdkHttpClient on platform's OutboundHttp: the connection goes to the address the policy checked and nowhere else
 * (DNS rebinding), a per-origin bulkhead bounds concurrent requests and gives every place back, and each failure
 * reaches the caller as the kind of exception it always did.
 */
class JdkHttpClientPinningTest {

    /** A public address: what the policy is shown at the check. Nothing here should ever connect to it. */
    private static final String PUBLIC = "93.184.216.34";

    private HttpServer server;
    private ExecutorService pool;
    private final AtomicInteger hits = new AtomicInteger();
    private volatile CountDownLatch release = new CountDownLatch(0);
    private volatile CountDownLatch arrived = new CountDownLatch(0);
    private volatile int status = 200;
    private volatile String body = "{\"ok\":true}";

    @BeforeEach
    void start() throws Exception {
        this.pool = Executors.newCachedThreadPool();
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 50);
        this.server.setExecutor(this.pool);
        this.server.createContext("/", exchange -> {
            this.hits.incrementAndGet();
            this.arrived.countDown();
            try {
                this.release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] bytes = this.body.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("X-Echo", "one");
            exchange.getResponseHeaders().add("x-echo", "two");
            exchange.sendResponseHeaders(this.status, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.release.countDown();
        this.server.stop(0);
        this.pool.shutdownNow();
    }

    private int port() {
        return this.server.getAddress().getPort();
    }

    /** A resolver that answers {@code first} the first time it is asked and {@code later} after that, counting. */
    private static Function<String, InetAddress[]> rebinding(String first, String later, AtomicInteger asked) {
        return host -> {
            try {
                return new InetAddress[] {InetAddress.getByName(asked.getAndIncrement() == 0 ? first : later)};
            } catch (IOException e) {
                throw new IllegalArgumentException(e);
            }
        };
    }

    private static JdkHttpClient client(OutboundUrlPolicy policy, HostBulkhead bulkhead, Duration timeout) {
        return new JdkHttpClient(TlsTrust.jvmDefault(), bulkhead, policy, Duration.ofMillis(400), timeout);
    }

    @Test
    void aNameThatRebindsToLoopbackAfterTheCheckIsNeverFetchedFromLoopback() {
        // localhost, which the system resolver answers with loopback. The old transport checked the name through the
        // policy's resolver (public here) and let the JDK client resolve it again for the connection (loopback), and
        // the request reached this server: run against origin/main ab96458 on 2026-09-28 it returned the body with
        // one hit. Now the check's resolution is the only one, and the connection goes to the public address.
        AtomicInteger asked = new AtomicInteger();
        OutboundUrlPolicy policy = OutboundUrlPolicy.from(Map.of(OutboundUrlPolicy.ALLOW_HTTP_ENV, "true")::get)
                .withResolver(rebinding(PUBLIC, "127.0.0.1", asked));
        JdkHttpClient client = client(policy, new HostBulkhead(4), Duration.ofSeconds(2));

        Exception e = assertThrows(Exception.class,
                () -> client.get("http://localhost:" + port() + "/entity", "application/json"));

        assertEquals(0, this.hits.get(), "the connection must not have reached the loopback server");
        assertEquals(1, asked.get(), "the name is resolved once, by the check");
        OutboundHttpException transport = assertInstanceOf(OutboundHttpException.class, e,
                "a connection to the checked public address that did not answer is a failed fetch: " + e);
        assertTrue(transport.reason() == Reason.CONNECT_TIMEOUT || transport.reason() == Reason.CONNECT_FAILED
                || transport.reason() == Reason.DEADLINE, String.valueOf(transport.reason()));
    }

    @Test
    void theConnectionGoesToTheCheckedAddressWhateverTheNameSaysLater() throws Exception {
        // The mirror image: the check sees the allow-listed loopback address, and a later answer would name an
        // address nothing listens on. The request succeeds, so it went to the checked address.
        AtomicInteger asked = new AtomicInteger();
        OutboundUrlPolicy policy = OutboundUrlPolicy.from(Map.of(OutboundUrlPolicy.ALLOW_HTTP_ENV, "true",
                        OutboundUrlPolicy.HOST_ALLOWLIST_ENV, "pinned.test")::get)
                .withResolver(rebinding("127.0.0.1", PUBLIC, asked));

        assertEquals("{\"ok\":true}", client(policy, new HostBulkhead(4), Duration.ofSeconds(5))
                .get("http://pinned.test:" + port() + "/entity", "application/json"));
        assertEquals(1, this.hits.get());
        assertEquals(1, asked.get());
    }

    @Test
    void aNameThatIsPrivateAtTheCheckIsRefusedWithoutConnecting() {
        AtomicInteger asked = new AtomicInteger();
        OutboundUrlPolicy policy = OutboundUrlPolicy.from(Map.of(OutboundUrlPolicy.ALLOW_HTTP_ENV, "true")::get)
                .withResolver(rebinding("127.0.0.1", PUBLIC, asked));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> client(policy, new HostBulkhead(4),
                Duration.ofSeconds(2)).get("http://private.test:" + port() + "/entity", "application/json"));

        assertTrue(e.getMessage().contains("127.0.0.1") && e.getMessage().contains(OutboundUrlPolicy.HOST_ALLOWLIST_ENV),
                e.getMessage());
        assertEquals(0, this.hits.get());
        assertEquals(1, asked.get());
    }

    @Test
    void aFullOriginRefusesAsAFailedFetchAndEveryPlaceComesBack() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(2);
        JdkHttpClient client = client(OutboundUrlPolicy.permissive(), bulkhead, Duration.ofSeconds(5));
        JdkHttpClient impatient = client(OutboundUrlPolicy.permissive(), bulkhead, Duration.ofMillis(300));
        String url = "http://127.0.0.1:" + port() + "/entity";
        String origin = "http://127.0.0.1:" + port();
        this.release = new CountDownLatch(1);
        this.arrived = new CountDownLatch(2);
        ExecutorService callers = Executors.newFixedThreadPool(2);
        try {
            List<Future<String>> held = new ArrayList<>();
            for (int i = 0; i < 2; i++) {
                held.add(callers.submit(() -> client.get(url, "application/json")));
            }
            assertTrue(this.arrived.await(5, TimeUnit.SECONDS), "both places are taken by requests the server holds");
            assertEquals(2, bulkhead.inFlight(origin));

            Exception e = assertThrows(Exception.class, () -> impatient.get(url, "application/json"));
            OutboundHttpException full = assertInstanceOf(OutboundHttpException.class, e,
                    "a full bulkhead is a failed fetch, an IOException, never a refusal of the URL: " + e);
            assertEquals(Reason.BULKHEAD_FULL, full.reason());
            assertEquals(2, this.hits.get(), "the refused request never reached the server");

            this.release.countDown();
            for (Future<String> request : held) {
                assertEquals("{\"ok\":true}", request.get(5, TimeUnit.SECONDS));
            }
        } finally {
            callers.shutdownNow();
        }
        assertEquals(0, bulkhead.inFlight(origin));
        assertEquals("{\"ok\":true}", impatient.get(url, "application/json"), "the places are free again");
    }

    @Test
    void everyKindOfFailureGivesItsPlaceBack() throws Exception {
        HostBulkhead bulkhead = new HostBulkhead(1);
        String url = "http://127.0.0.1:" + port() + "/entity";
        String origin = "http://127.0.0.1:" + port();
        JdkHttpClient client = client(OutboundUrlPolicy.permissive(), bulkhead, Duration.ofSeconds(5));

        this.status = 500;
        assertThrows(IllegalArgumentException.class, () -> client.get(url, "application/json"), "a GET's non-2xx");
        assertEquals(0, bulkhead.inFlight(origin));

        this.status = 200;
        this.body = "x".repeat(2048);
        JdkHttpClient capped = client(OutboundUrlPolicy.from(Map.of(OutboundUrlPolicy.MAX_BODY_ENV, "1024")::get)
                .trusting(url), bulkhead, Duration.ofSeconds(5));
        IllegalArgumentException tooLarge = assertThrows(IllegalArgumentException.class, () -> capped.get(url, "application/json"));
        assertTrue(tooLarge.getMessage().contains("1024"), tooLarge.getMessage());
        assertEquals(0, bulkhead.inFlight(origin));

        this.body = "{}";
        this.release = new CountDownLatch(1);
        JdkHttpClient hasty = client(OutboundUrlPolicy.permissive(), bulkhead, Duration.ofMillis(300));
        OutboundHttpException slow = assertThrows(OutboundHttpException.class, () -> hasty.get(url, "application/json"));
        assertTrue(slow.reason() == Reason.HEADER_TIMEOUT || slow.reason() == Reason.DEADLINE, String.valueOf(slow.reason()));
        assertEquals(0, bulkhead.inFlight(origin), "a timed-out exchange gives its place back");
        this.release.countDown();

        int closedPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            closedPort = probe.getLocalPort();
        }
        OutboundHttpException refused = assertThrows(OutboundHttpException.class,
                () -> client.get("http://127.0.0.1:" + closedPort + "/", "application/json"));
        assertEquals(Reason.CONNECT_FAILED, refused.reason());
        assertEquals(0, bulkhead.inFlight("http://127.0.0.1:" + closedPort));

        assertEquals("{}", client.get(url, "application/json"), "the one place is free after all of that");
    }

    @Test
    void anUnresolvableNameIsARefusalOnlyWhereTheAddressRuleApplies() throws Exception {
        Function<String, InetAddress[]> nowhere = host -> {
            throw new IllegalArgumentException("cannot resolve " + host);
        };
        OutboundUrlPolicy strict = OutboundUrlPolicy.from(Map.<String, String>of()::get).withResolver(nowhere);
        OutboundUrlPolicy open = OutboundUrlPolicy.from(Map.of(OutboundUrlPolicy.ALLOW_PRIVATE_ENV, "true")::get).withResolver(nowhere);
        OutboundUrlPolicy trusting = strict.trusting("https://controller.internal/oidf");
        OutboundUrlPolicy allowListed = OutboundUrlPolicy.from(Map.of(OutboundUrlPolicy.HOST_ALLOWLIST_ENV, "internal")::get)
                .withResolver(nowhere);

        // As before: the strict rule cannot pass a name it cannot resolve, so that is a refusal.
        IllegalArgumentException refusal = assertThrows(IllegalArgumentException.class,
                () -> strict.check("https://gone.example/x"));
        assertTrue(refusal.getMessage().contains("gone.example"), refusal.getMessage());
        assertThrows(IllegalArgumentException.class, () -> client(strict, new HostBulkhead(1), Duration.ofSeconds(2))
                .get("https://gone.example/x", "application/json"));

        // Where the address rule does not apply, the old policy never resolved: the check passes and the fetch fails
        // as a transport failure, as the JDK client's connect did.
        for (OutboundUrlPolicy lenient : List.of(open, trusting, allowListed)) {
            String url = lenient == trusting ? "https://controller.internal/oidf/x" : "https://gone.internal/x";
            assertEquals(URI.create(url), lenient.check(url));
            OutboundHttpException e = assertThrows(OutboundHttpException.class,
                    () -> client(lenient, new HostBulkhead(1), Duration.ofSeconds(2)).get(url, "application/json"));
            assertEquals(Reason.UNRESOLVED, e.reason());
        }
    }

    @Test
    void failuresOtherThanRefusalsPassThroughUnchanged() {
        OutboundUrlPolicy policy = OutboundUrlPolicy.permissive();
        JdkHttpClient client = client(policy, new HostBulkhead(1), Duration.ofSeconds(1));
        URI uri = URI.create("https://peer.example/x");
        OutboundHttpException tls = new OutboundHttpException(Reason.TLS, "handshake");
        assertSame(tls, client.failure(tls, uri, uri.toString(), "GET"));
        assertNull(policy.refusal(tls, uri));
        Exception body = client.failure(new OutboundHttpException(Reason.BODY_TOO_LARGE, "over the 5-byte cap"), uri, uri.toString(), "POST");
        assertInstanceOf(IllegalArgumentException.class, body);
        assertTrue(body.getMessage().startsWith("POST refused: https://peer.example/x"), body.getMessage());
    }

    @Test
    void responseHeadersKeepEveryValueUnderOneName() throws Exception {
        HttpPostClient.Response response = client(OutboundUrlPolicy.permissive(), new HostBulkhead(1), Duration.ofSeconds(5))
                .post("http://127.0.0.1:" + port() + "/", "application/json", null, null, null);
        assertEquals(200, response.status());
        List<String> echoed = null;
        for (Map.Entry<String, List<String>> header : response.headers().entrySet()) {
            if (header.getKey().equalsIgnoreCase("x-echo")) {
                assertNull(echoed, "one entry for a name, however the peer spelled it");
                echoed = header.getValue();
            }
        }
        assertEquals(List.of("one", "two"), echoed);
        assertEquals("one", response.header("X-ECHO").orElseThrow());
    }

    @Test
    void headersWithoutANameOrAValueAreLeftOut() throws Exception {
        Map<String, String> headers = new java.util.HashMap<>();
        headers.put(null, "no name");
        headers.put("X-No-Value", null);
        headers.put("X-Kept", "yes");
        HttpPostClient.Response response = client(OutboundUrlPolicy.permissive(), new HostBulkhead(1), Duration.ofSeconds(5))
                .post("http://127.0.0.1:" + port() + "/", "application/json", "{}", headers, "application/json");
        assertEquals(200, response.status());
        assertEquals(1, this.hits.get());
    }

    @Test
    void theRequestItselfIsCheckedBeforeAnythingIsSent() {
        JdkHttpClient client = client(OutboundUrlPolicy.permissive(), new HostBulkhead(1), Duration.ofSeconds(5));
        String url = "http://127.0.0.1:" + port() + "/";
        assertThrows(IllegalArgumentException.class, () -> client.post(url, "application/json", "{}",
                Map.of("Connection", "keep-alive"), null), "a framing header is the transport's to write");
        assertThrows(IllegalArgumentException.class, () -> client.post(url, "application/json", "{}",
                Map.of("X-Split", "a\r\nInjected: yes"), null), "a header value that would split the request");
        assertThrows(IllegalArgumentException.class, () -> client.get("not a url", "application/json"));
        assertThrows(IllegalArgumentException.class, () -> client.get(null, "application/json"));
        assertEquals(0, this.hits.get());
        assertFalse(JdkHttpClient.BULKHEAD.maxPerOrigin() < 1);
        assertEquals(HostBulkhead.DEFAULT_MAX_PER_ORIGIN, JdkHttpClient.BULKHEAD.maxPerOrigin());
    }
}
