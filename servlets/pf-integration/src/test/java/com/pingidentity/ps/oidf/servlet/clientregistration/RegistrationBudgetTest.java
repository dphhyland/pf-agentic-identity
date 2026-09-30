package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.testkit.EventCapture;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JdkHttpClient;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.AutoRegistrationSettings;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig.RegistrationSettings;
import com.pingidentity.ps.oidf.pf.testkit.FakeClientStore;
import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Every registration path spends a budget that ends by the registration's deadline (plan item S5c), over real loopback
 * HTTP: a federation whose peers answer at once and then never finish the body. Resolving the chain runs out of time,
 * and the registration is refused as a federation that could not be reached - 503 {@code temporarily_unavailable},
 * remembered for the transport backoff - rather than hanging until PingFederate's own timeout.
 */
class RegistrationBudgetTest {
    private static final String TA = "https://ta.example.com";
    private static final String INT = "https://int.example.com";
    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://op.example.com";
    /** The registration deadline these tests give the coordinator: far below the peers' stall and the client's timeout. */
    private static final Duration DEADLINE = Duration.ofMillis(600);

    private final MutableClock clock = MutableClock.startingNow();
    private final FakeClientStore store = new FakeClientStore();
    private EventCapture events;
    private Federation federation;
    private StallingPeers peers;

    @BeforeEach
    void setUp() throws IOException {
        this.events = EventCapture.install();
        Map<String, Object> rp = new HashMap<>();
        rp.put("client_registration_types", List.of("automatic", "explicit"));
        rp.put("redirect_uris", List.of(RP + "/cb"));
        this.federation = Federation.builder(this.clock).anchor(TA).intermediate(INT, TA).leaf(RP, INT)
                .metadata(RP, "openid_relying_party", rp).metadata(RP, "oauth_client", RegistrationFixtures.agentMetadata("automatic"))
                .build();
        this.peers = new StallingPeers(this.federation);
    }

    @AfterEach
    void tearDown() {
        this.peers.close();
        this.events.close();
    }

    /**
     * Serves the federation's statements over loopback HTTP: the headers at once, then the first bytes of the body,
     * then nothing for ten seconds - a peer that has answered and will not finish.
     */
    private static final class StallingPeers implements AutoCloseable {
        private final HttpServer server;
        private final ExecutorService pool = Executors.newCachedThreadPool();
        private final AtomicInteger requests = new AtomicInteger();
        private final JdkHttpClient client = new JdkHttpClient(false, OutboundUrlPolicy.permissive(), Duration.ofSeconds(2), Duration.ofSeconds(30));

        StallingPeers(Federation federation) throws IOException {
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 50);
            this.server.setExecutor(this.pool);
            this.server.createContext("/", exchange -> {
                this.requests.incrementAndGet();
                String url = java.net.URLDecoder.decode(exchange.getRequestURI().getRawQuery().substring("u=".length()), StandardCharsets.UTF_8);
                byte[] body;
                try {
                    body = federation.http().get(url, "application/entity-statement+jwt").getBytes(StandardCharsets.UTF_8);
                } catch (Exception e) {
                    exchange.sendResponseHeaders(404, -1);
                    exchange.close();
                    return;
                }
                exchange.sendResponseHeaders(200, body.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body, 0, 8);
                    out.flush();
                    Thread.sleep(10_000L);
                } catch (IOException | InterruptedException gone) {
                    // the client gave up at its deadline
                }
            });
            this.server.start();
        }

        HttpGetClient http() {
            return new HttpGetClient() {
                @Override
                public String get(String url, String accept) throws Exception {
                    return StallingPeers.this.client.get(this.local(url), accept);
                }

                @Override
                public String get(String url, String accept, Deadline deadline) throws Exception {
                    return StallingPeers.this.client.get(this.local(url), accept, deadline);
                }

                private String local(String url) {
                    return "http://127.0.0.1:" + StallingPeers.this.server.getAddress().getPort() + "/?u="
                            + URLEncoder.encode(url, StandardCharsets.UTF_8);
                }
            };
        }

        int requests() {
            return this.requests.get();
        }

        @Override
        public void close() {
            this.server.stop(0);
            this.pool.shutdownNow();
        }
    }

    private RegistrationService service() throws Exception {
        // The validator's own wall clock is the catalogue's 45 s: only the registration's budget can stop it sooner.
        ValidatorOptions options = ValidatorOptions.defaults().withClock(this.clock);
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(this.peers.http(), TA),
                TrustAnchorSet.of(this.federation.trustAnchor(TA)), Set.of(), options);
        return new RegistrationService(new RegistrationConfiguration(TA, false), validator, this.store, RegistrationFixtures.signer(),
                new RegistrationLifetime(RegistrationSettings.DEFAULTS, this.clock), new RpKeyMaterial((url, accept) -> {
                    throw new IOException("no RP key fetch expected: " + url);
                }, this.clock), new RegistrationCoordinator(8, 0L, options, DEADLINE, System::nanoTime));
    }

    /** The RP's own configuration alone: its superiors' statements have to be fetched, from the stalling peers. */
    private List<String> configurationOnly() {
        return List.of(this.federation.entityConfiguration(RP));
    }

    private static void assertBudgetRanOut(RegistrationRejectedException e, long elapsedMillis) {
        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertEquals(RegistrationRejectedException.Kind.TRANSPORT, e.kind());
        assertTrue(e.getMessage().contains("ran out of time"), e.getMessage());
        assertFalse(e.getMessage().contains(".example.com"), "the refusal names no peer: " + e.getMessage());
        assertTrue(elapsedMillis < 3_000L, "stopped at the registration's deadline, not a peer's: " + elapsedMillis + " ms");
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSlowPeerSpendsTheExplicitRegistrationsBudgetAndTheFailureIsRemembered() throws Exception {
        RegistrationService service = this.service();
        ExplicitRegistrationRequest request = new ExplicitRegistrationRequest(RP, RP, this.configurationOnly(), Map.of());

        long started = System.nanoTime();
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(request, OP));
        assertBudgetRanOut(e, (System.nanoTime() - started) / 1_000_000L);
        assertNull(this.store.get(RP));

        int asked = this.peers.requests();
        assertThrows(RegistrationRejectedException.class, () -> service.explicitRegister(request, OP));
        assertEquals(asked, this.peers.requests(), "the same chain within the transport backoff is not resolved again");
    }

    @Test
    @Requirement("OIDFED §12.2.4")
    void theServletAnswersARegistrationWhoseBudgetRanOut503WithRetryAfter() throws Exception {
        OpenIdRegistrationServlet servlet = new OpenIdRegistrationServlet(this.service(), req -> OP, 65_536);
        String body = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(this.configurationOnly());
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getServletPath()).thenReturn("/federation/register");
        when(req.getContentType()).thenReturn("application/trust-chain+json");
        when(req.getContentLengthLong()).thenReturn((long) body.length());
        ByteArrayInputStream bytes = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
        when(req.getInputStream()).thenReturn(new ServletInputStream() {
            @Override public int read() { return bytes.read(); }
            @Override public boolean isFinished() { return bytes.available() == 0; }
            @Override public boolean isReady() { return true; }
            @Override public void setReadListener(ReadListener l) { }
        });
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter written = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(written));

        servlet.doPost(req, resp);

        verify(resp).setStatus(503);
        verify(resp).setHeader("Retry-After", Long.toString(RegistrationService.TRANSPORT_FAILURE_BACKOFF_SECONDS));
        assertTrue(written.toString().contains("temporarily_unavailable"), written.toString());
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSlowPeerSpendsTheTokenEndpointsBudget() throws Exception {
        RegistrationService service = this.service();

        long started = System.nanoTime();
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, this.configurationOnly(), OP));

        assertBudgetRanOut(e, (System.nanoTime() - started) / 1_000_000L);
        assertTrue(e.isRetryable(), "the token endpoint's transport-failure outcome: 503 with Retry-After");
        assertNull(this.store.get(RP));
    }

    @Test
    @Requirement("OIDFED §18.1(3)")
    void aSlowPeerSpendsTheFrontChannelsBudget() throws Exception {
        RegistrationService service = this.service();
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("rp-1");
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("client_id", RP);
        claims.put("iss", RP);
        claims.put("aud", OP);
        claims.put("jti", "jti-1");
        claims.put("exp", this.clock.epochSecond() + 300);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(claims));
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue("rp-1");
        RequestObject proof = RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, jws.getCompactSerialization());

        long started = System.nanoTime();
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> service.admit(RP, List.of(), OP,
                service.frontChannel("authorization", RP, OP, proof, null, (client, jti, ttl) -> true, AutoRegistrationSettings.DEFAULTS)));

        assertBudgetRanOut(e, (System.nanoTime() - started) / 1_000_000L);
        assertNull(this.store.get(RP));
    }
}
