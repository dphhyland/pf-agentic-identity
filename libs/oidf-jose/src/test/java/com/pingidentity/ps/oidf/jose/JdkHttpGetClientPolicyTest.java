package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The policy over a real socket. The point of the first test is not the exception - it is that the
 * server's hit counter stays at zero: a refusal that still opened the connection would have already
 * done the damage an SSRF guard exists to prevent.
 */
class JdkHttpGetClientPolicyTest {

    private HttpServer server;
    private final AtomicInteger hits = new AtomicInteger();
    private volatile byte[] body = "{\"ok\":true}".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void start() throws Exception {
        this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        this.server.createContext("/", exchange -> {
            this.hits.incrementAndGet();
            exchange.sendResponseHeaders(200, this.body.length);
            exchange.getResponseBody().write(this.body);
            exchange.close();
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    private String url() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort() + "/entity";
    }

    @Test
    void aRefusedUrlNeverReachesTheNetwork() {
        JdkHttpGetClient client = new JdkHttpGetClient(false, OutboundUrlPolicy.fromEnvironment());

        assertThrows(IllegalArgumentException.class, () -> client.get(url(), "application/json"));

        assertEquals(0, this.hits.get(), "the connection must not have been made at all");
    }

    @Test
    void anOperatorTrustedHostIsFetched() throws Exception {
        JdkHttpGetClient client = new JdkHttpGetClient(false, OutboundUrlPolicy.fromEnvironment().trusting(url()));

        assertEquals("{\"ok\":true}", client.get(url(), "application/json"));
        assertEquals(1, this.hits.get());
    }

    @Test
    void anOversizedBodyIsRefused() {
        this.body = new byte[300 * 1024];
        JdkHttpGetClient client = new JdkHttpGetClient(false,
                OutboundUrlPolicy.from(java.util.Map.of(OutboundUrlPolicy.MAX_BODY_ENV, "65536")::get).trusting(url()));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> client.get(url(), "application/json"));
        assertTrue(e.getMessage().contains("65536"), e.getMessage());
    }

    @Test
    void aBodyUnderTheCapIsReturnedWhole() throws Exception {
        this.body = new byte[60 * 1024];
        java.util.Arrays.fill(this.body, (byte) 'a');
        JdkHttpGetClient client = new JdkHttpGetClient(false,
                OutboundUrlPolicy.from(java.util.Map.of(OutboundUrlPolicy.MAX_BODY_ENV, "65536")::get).trusting(url()));

        assertEquals(60 * 1024, client.get(url(), "application/json").length());
    }
}
