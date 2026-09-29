package com.pingidentity.ps.oidf.platform.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.http.AddressPolicy;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The introspector against a stub endpoint on loopback: what it sends, how it reads the answer, what it refuses as no
 * answer, and how long it keeps one.
 */
class TokenIntrospectorTest {
    private static final OutboundHttp LOCAL = OutboundHttp.builder(
            AddressPolicy.builder().allowHttp(true).allowPrivateNetworks(true).build()).build();
    /** PingFederate 13.1.3's answer for a DPoP-bound client-credentials token, as the rig gave it on 2026-09-29. */
    private static final String PF_ACTIVE = "{\"sub\":\"s8a-dpop-cc\",\"aud\":\"https://operator.example/agentic-identity\","
            + "\"scope\":\"profile oidf.admin.read\",\"iss\":\"https://localhost:31031\",\"active\":true,"
            + "\"cnf\":{\"jkt\":\"1B9W-Wj6qDJaTXVO5N7KJt9xOU9-6izj8mBeHdiNL4c\"},\"token_type\":\"DPoP\","
            + "\"exp\":1790655144,\"client_id\":\"s8a-dpop-cc\"}";

    private HttpServer server;
    private final AtomicReference<String> answer = new AtomicReference<>(PF_ACTIVE);
    private final AtomicInteger status = new AtomicInteger(200);
    private final AtomicInteger calls = new AtomicInteger();
    private final List<Map<String, String>> requests = new ArrayList<>();
    private final AtomicReference<String> authorization = new AtomicReference<>();
    private final AtomicReference<String> contentType = new AtomicReference<>();
    private volatile long delayMillis;

    @BeforeEach
    void start() throws IOException {
        this.server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        this.server.createContext("/as/introspect.oauth2", exchange -> {
            this.calls.incrementAndGet();
            this.authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            this.contentType.set(exchange.getRequestHeaders().getFirst("Content-Type"));
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            Map<String, String> form = new LinkedHashMap<>();
            for (String pair : body.split("&")) {
                String[] kv = pair.split("=", 2);
                form.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8), URLDecoder.decode(kv[1], StandardCharsets.UTF_8));
            }
            synchronized (this.requests) {
                this.requests.add(form);
            }
            try {
                Thread.sleep(this.delayMillis);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            byte[] out = this.answer.get().getBytes(StandardCharsets.UTF_8);
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

    private URI endpoint() {
        return URI.create("http://127.0.0.1:" + this.server.getAddress().getPort() + "/as/introspect.oauth2");
    }

    private TokenIntrospector introspector() {
        return TokenIntrospector.builder(LOCAL, endpoint(),
                ClientAuthentication.clientSecretBasic("rs client", () -> "p@ss:word")).build();
    }

    @Test
    void anActiveDpopBoundAnswerIsReadWhole() throws Exception {
        Introspection i = introspector().introspect("the-token");
        assertTrue(i.active());
        assertTrue(i.bound());
        assertEquals(List.of("profile", "oidf.admin.read"), i.scopes());
        assertEquals("s8a-dpop-cc", i.clientId());
        assertEquals("s8a-dpop-cc", i.subject());
        assertEquals(List.of("https://operator.example/agentic-identity"), i.audience());
        assertEquals("https://localhost:31031", i.issuer());
        assertEquals(1790655144L, i.exp());
        assertNull(i.iat());
        assertNull(i.nbf());
        assertEquals("DPoP", i.tokenType());
        assertEquals("1B9W-Wj6qDJaTXVO5N7KJt9xOU9-6izj8mBeHdiNL4c", i.jkt());
        assertNull(i.x5tS256());
        assertEquals("DPoP", i.members().get("token_type"));
        assertThrows(UnsupportedOperationException.class, () -> i.members().put("x", "y"));
        // What went out: the token and its hint, form-encoded, and the client's credentials as RFC 6749 §2.3.1 encodes
        // them - each half form-encoded before Basic.
        assertEquals(Map.of("token", "the-token", "token_type_hint", "access_token"), this.requests.get(0));
        assertEquals("application/x-www-form-urlencoded", this.contentType.get());
        assertEquals("Basic " + Base64.getEncoder().encodeToString("rs+client:p%40ss%3Aword".getBytes(StandardCharsets.UTF_8)),
                this.authorization.get());
        assertEquals(endpoint(), introspector().endpoint());
    }

    @Test
    void membersRfc7662GivesOtherShapesAreReadAsTheirTypes() throws Exception {
        this.answer.set("{\"active\":true,\"aud\":[\"a\",\"b\"],\"iat\":1,\"nbf\":2,\"exp\":3.0E0,\"scope\":\"  one  two \","
                + "\"cnf\":{\"x5t#S256\":\"abc\"}}");
        Introspection i = introspector().introspect("t");
        assertEquals(List.of("a", "b"), i.audience());
        assertEquals(1L, i.iat());
        assertEquals(2L, i.nbf());
        assertEquals(3L, i.exp());
        assertEquals(List.of("one", "two"), i.scopes());
        assertEquals("abc", i.x5tS256());
        assertTrue(i.bound());
        this.answer.set("{\"active\":true}");
        Introspection bare = introspector().introspect("t");
        assertFalse(bare.bound());
        assertEquals(List.of(), bare.scopes());
        assertEquals(List.of(), bare.audience());
        assertNull(bare.jkt());
    }

    @Test
    void anInactiveTokenIsAnAnswerNotAFailure() throws Exception {
        this.answer.set("{\"active\":false}");
        assertSame(Introspection.INACTIVE, introspector().introspect("t"));
        assertFalse(Introspection.INACTIVE.bound());
        // No token is not asked about at all.
        assertSame(Introspection.INACTIVE, introspector().introspect(""));
        assertSame(Introspection.INACTIVE, introspector().introspect(null));
        assertEquals(1, this.calls.get());
    }

    @Test
    void anAnswerThatIsNotOneIsAnException() {
        for (String body : List.of("not json", "[]", "{}", "{\"active\":\"true\"}", "{\"active\":true,\"scope\":1}",
                "{\"active\":true,\"aud\":[1]}", "{\"active\":true,\"aud\":{}}", "{\"active\":true,\"exp\":1.5}",
                "{\"active\":true,\"exp\":\"1\"}", "{\"active\":true,\"cnf\":\"x\"}", "{\"active\":true,\"cnf\":{\"jkt\":1}}")) {
            this.answer.set(body);
            assertThrows(IntrospectionException.class, () -> introspector().introspect("t"), body);
        }
    }

    @Test
    void aStatusOtherThan200IsAnException() {
        // RFC 7662 §2.3: a client that fails authentication at the endpoint is answered 401.
        this.status.set(401);
        IntrospectionException e = assertThrows(IntrospectionException.class, () -> introspector().introspect("t"));
        assertEquals("the introspection endpoint answered HTTP 401", e.getMessage());
    }

    @Test
    void anEndpointThatCannotBeReachedIsAnException() throws Exception {
        int closed;
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            closed = socket.getLocalPort();
        }
        TokenIntrospector gone = TokenIntrospector.builder(LOCAL,
                URI.create("http://127.0.0.1:" + closed + "/as/introspect.oauth2"),
                ClientAuthentication.clientSecretBasic("c", () -> "s")).build();
        IntrospectionException e = assertThrows(IntrospectionException.class, () -> gone.introspect("t"));
        assertTrue(e.getMessage().startsWith("the introspection endpoint did not answer (CONNECT_FAILED)"), e.getMessage());
    }

    @Test
    void anAnswerSlowerThanTheDeadlineIsAnException() {
        this.delayMillis = 3000;
        long start = System.nanoTime();
        assertThrows(IntrospectionException.class, () -> introspector().introspect("t"));
        long took = Duration.ofNanos(System.nanoTime() - start).toMillis();
        assertTrue(took < 2900, "the 2.5 s deadline held: " + took + " ms");
    }

    @Test
    void aBodyOverTheCapIsAnException() {
        this.answer.set("{\"active\":true,\"pad\":\"" + "x".repeat(70 * 1024) + "\"}");
        IntrospectionException e = assertThrows(IntrospectionException.class, () -> introspector().introspect("t"));
        assertTrue(e.getMessage().contains("BODY_TOO_LARGE"), e.getMessage());
    }

    @Test
    void credentialsThatCannotBeMadeAreAnException() {
        TokenIntrospector failing = TokenIntrospector.builder(LOCAL, endpoint(), endpoint -> {
            throw new IOException("the signing key is unreachable");
        }).build();
        IntrospectionException e = assertThrows(IntrospectionException.class, () -> failing.introspect("t"));
        assertEquals("the introspection client's credentials could not be made: the signing key is unreachable",
                e.getMessage());
        TokenIntrospector nothing = TokenIntrospector.builder(LOCAL, endpoint(), endpoint -> null).build();
        assertThrows(IntrospectionException.class, () -> nothing.introspect("t"));
        assertEquals(0, this.calls.get());
    }

    /** RFC 7523 §2.2: private_key_jwt sends the assertion and its type as form parameters, signed for the endpoint. */
    @Test
    void privateKeyJwtSendsAnAssertionForTheEndpoint() throws Exception {
        List<URI> signedFor = new ArrayList<>();
        TokenIntrospector pkj = TokenIntrospector.builder(LOCAL, endpoint(), ClientAuthentication.privateKeyJwt(uri -> {
            signedFor.add(uri);
            return "eyJ.assertion.sig";
        })).build();
        pkj.introspect("t");
        assertEquals(List.of(endpoint()), signedFor);
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                this.requests.get(0).get("client_assertion_type"));
        assertEquals("eyJ.assertion.sig", this.requests.get(0).get("client_assertion"));
        assertNull(this.authorization.get());
    }

    /** RFC 7662 §2.2: an answer "MAY be cached ... but at the cost of liveness"; here at most 30 s and never past exp. */
    @Test
    void anActiveAnswerIsKeptNoLongerThanThirtySecondsOrItsExp() throws Exception {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_790_655_000L));
        TokenIntrospector cached = TokenIntrospector.builder(LOCAL, endpoint(),
                ClientAuthentication.clientSecretBasic("c", () -> "s")).cacheFor(Duration.ofSeconds(30)).clock(clock).build();
        cached.introspect("t");
        cached.introspect("t");
        assertEquals(1, this.calls.get());
        assertEquals(1, cached.cached());
        clock.advance(Duration.ofSeconds(30));
        cached.introspect("t");
        assertEquals(2, this.calls.get(), "kept for 30 s, not longer");
        // exp 1790655144 is 144 s after the start: an answer taken 130 s in is kept 14 s, not 30.
        clock.advance(Duration.ofSeconds(100));
        cached.introspect("u");
        clock.advance(Duration.ofSeconds(14));
        cached.introspect("u");
        assertEquals(4, this.calls.get(), "never past the token's exp");
        // Inactive answers and answers without exp are not kept.
        this.answer.set("{\"active\":false}");
        cached.introspect("v");
        cached.introspect("v");
        this.answer.set("{\"active\":true}");
        cached.introspect("w");
        cached.introspect("w");
        assertEquals(8, this.calls.get());
    }

    @Test
    void theCacheIsBoundedAndOffByDefault() throws Exception {
        MutableClock clock = new MutableClock(Instant.ofEpochSecond(1_790_655_000L));
        TokenIntrospector small = TokenIntrospector.builder(LOCAL, endpoint(),
                ClientAuthentication.clientSecretBasic("c", () -> "s")).cacheFor(Duration.ofSeconds(10)).clock(clock)
                .capacity(2).build();
        small.introspect("a");
        small.introspect("b");
        small.introspect("c");
        assertEquals(2, small.cached(), "full of live answers, a third is not kept");
        clock.advance(Duration.ofSeconds(11));
        small.introspect("d");
        assertEquals(1, small.cached(), "the expired were swept to make room");
        TokenIntrospector off = introspector();
        off.introspect("a");
        off.introspect("a");
        assertEquals(0, off.cached());
        assertThrows(IllegalArgumentException.class, () -> TokenIntrospector.builder(LOCAL, endpoint(),
                ClientAuthentication.clientSecretBasic("c", () -> "s")).cacheFor(Duration.ofSeconds(31)));
        assertThrows(IllegalArgumentException.class, () -> TokenIntrospector.builder(LOCAL, endpoint(),
                ClientAuthentication.clientSecretBasic("c", () -> "s")).cacheFor(Duration.ofSeconds(-1)));
    }

    @Test
    void theCacheKeyIsTheTokensDigest() {
        assertEquals("n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg", TokenIntrospector.cacheKey("test"));
        assertEquals("a=1&b=x+y%26z", TokenIntrospector.formEncode(new LinkedHashMap<>(Map.of("a", "1"))) + "&"
                + TokenIntrospector.formEncode(Map.of("b", "x y&z")));
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            this.now = this.now.plus(d);
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return this.now;
        }
    }
}
