/*
 * The SSF receiver authenticator over platform's TokenIntrospector, against a stub introspection endpoint.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.auth.Introspection;
import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class PfIntrospectionReceiverAuthenticatorTest {
    private static final String ISSUER = "https://pf.example.com";

    private HttpServer server;
    private final AtomicReference<String> answer = new AtomicReference<>();
    private final AtomicInteger status = new AtomicInteger(200);
    private final AtomicReference<String> authorization = new AtomicReference<>();
    private final AtomicReference<String> form = new AtomicReference<>();
    private final AtomicInteger delayMillis = new AtomicInteger();

    @BeforeEach
    void start() throws Exception {
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.createContext("/as/introspect.oauth2", exchange -> {
            this.form.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            this.authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            try {
                Thread.sleep(this.delayMillis.get());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] out = String.valueOf(this.answer.get()).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(this.status.get(), out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        this.server.start();
    }

    @AfterEach
    void stop() {
        this.server.stop(0);
    }

    private String endpoint() {
        return "http://127.0.0.1:" + this.server.getAddress().getPort() + "/as/introspect.oauth2";
    }

    private ReceiverAuthenticator authenticator() {
        return PfIntrospectionReceiverAuthenticator.forEndpoint(this.endpoint(), "ssf-rs", "rs-secret", false, ISSUER);
    }

    private static long now() {
        return System.currentTimeMillis() / 1000L;
    }

    @Test
    @Requirement("RFC7662 §2.2")
    void anActiveTokenIsItsClientAndItsScopes() throws Exception {
        this.answer.set("{\"active\":true,\"client_id\":\"receiver-1\",\"scope\":\"openid ssf.manage other\",\"exp\":"
                + (now() + 300) + ",\"aud\":\"" + ISSUER + "\"}");
        AuthContext ctx = this.authenticator().authenticate("tok");
        assertTrue(ctx.isActive());
        assertEquals("receiver-1", ctx.clientId());
        assertTrue(ctx.hasScope("ssf.manage"));
        assertFalse(ctx.hasScope("missing"));
        assertTrue(this.form.get().startsWith("token=tok&token_type_hint=access_token"), this.form.get());
        assertTrue(this.authorization.get().startsWith("Basic "), "client_secret_basic");
    }

    @Test
    @Requirement("RFC7662 §2.2")
    void anInactiveTokenIsNotActive() throws Exception {
        this.answer.set("{\"active\":false}");
        AuthContext ctx = this.authenticator().authenticate("tok");
        assertFalse(ctx.isActive());
        assertFalse(ctx.hasScope("ssf.manage"));
    }

    @Test
    void noUsableAnswerIsATransportFailureTheServletsAnswer503() {
        this.answer.set("{\"scope\":\"ssf.manage\"}");
        assertThrows(ReceiverAuthException.class, () -> this.authenticator().authenticate("tok"), "no active member");
        this.answer.set("{\"active\":true,\"client_id\":\"r\",\"scope\":[\"ssf.manage\"]}");
        assertThrows(ReceiverAuthException.class, () -> this.authenticator().authenticate("tok"),
                "RFC 7662 §2.2's scope is a string; an array is not an answer");
        this.answer.set("{\"active\":true}");
        this.status.set(500);
        assertThrows(ReceiverAuthException.class, () -> this.authenticator().authenticate("tok"));
        this.status.set(200);
        this.server.stop(0);
        assertThrows(ReceiverAuthException.class, () -> this.authenticator().authenticate("tok"), "nobody answers");
    }

    @Test
    void aSlowEndpointIsCutOffAtTheDeadline() throws Exception {
        this.answer.set("{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\"}");
        this.delayMillis.set(4000);
        long started = System.nanoTime();
        assertThrows(ReceiverAuthException.class, () -> this.authenticator().authenticate("tok"));
        long tookMillis = (System.nanoTime() - started) / 1_000_000L;
        assertTrue(tookMillis < 3800, "platform's 2.5 s deadline, not the endpoint's 4 s: " + tookMillis);
        this.delayMillis.set(0);
    }

    @Test
    void anActiveAnswerIsHeldToItsLifetimeAudienceClientAndBinding() throws Exception {
        long now = now();
        String[][] refused = {
                {"{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\",\"exp\":" + (now - 1) + "}", "expired"},
                {"{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\",\"nbf\":" + (now + 600) + "}", "not yet valid"},
                {"{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\",\"aud\":[\"https://other.example\"]}", "aud"},
                {"{\"active\":true,\"scope\":\"ssf.manage\"}", "client_id"},
                {"{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\",\"token_type\":\"DPoP\",\"cnf\":{\"jkt\":\"abc\"}}", "bound"},
                {"{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\",\"cnf\":{\"x5t#S256\":\"abc\"}}", "bound"},
        };
        for (String[] c : refused) {
            this.answer.set(c[0]);
            assertFalse(this.authenticator().authenticate("tok").isActive(), c[1] + ": " + c[0]);
        }
        this.answer.set("{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\",\"aud\":[\"https://other.example\",\""
                + ISSUER + "\"]}");
        assertTrue(this.authenticator().authenticate("tok").isActive(), "aud contains the issuer");
        this.answer.set("{\"active\":true,\"client_id\":\"r\",\"scope\":\"ssf.manage\"}");
        assertTrue(this.authenticator().authenticate("tok").isActive(), "no aud, no exp: RFC 7662 makes both optional");
    }

    @Test
    void theRefusalRuleSaysWhy() {
        Introspection active = new Introspection(true, List.of("ssf.manage"), "r", null, List.of(), null, 100L, null, 50L,
                null, null, null, Map.of("active", true));
        assertNull(PfIntrospectionReceiverAuthenticator.refusal(active, ISSUER, 60));
        assertNull(PfIntrospectionReceiverAuthenticator.refusal(active, null, 60), "no audience configured, none checked");
        assertEquals("expired", PfIntrospectionReceiverAuthenticator.refusal(active, ISSUER, 100));
        assertEquals("not yet valid", PfIntrospectionReceiverAuthenticator.refusal(active, ISSUER, 49));
        assertEquals("not active", PfIntrospectionReceiverAuthenticator.refusal(Introspection.INACTIVE, ISSUER, 60));
        Introspection blankClient = new Introspection(true, List.of(), " ", null, List.of(ISSUER), null, null, null, null,
                null, null, null, Map.of("active", true));
        assertEquals("it names no client_id", PfIntrospectionReceiverAuthenticator.refusal(blankClient, ISSUER, 60));
        Introspection otherAudience = new Introspection(true, List.of(), "r", null, List.of("https://x.example"), null, null,
                null, null, null, null, null, Map.of("active", true));
        assertTrue(PfIntrospectionReceiverAuthenticator.refusal(otherAudience, ISSUER, 60).contains("aud"));
        assertNull(PfIntrospectionReceiverAuthenticator.refusal(otherAudience, null, 60));
    }
}
