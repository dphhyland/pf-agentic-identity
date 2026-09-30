/*
 * The issuance endpoint's request path (plan item H-ATT-2, F-0060): the per-address limit, the body cap, and every
 * failure answered as a CAS section 4.6 error with no internal text.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.ChainClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.platform.pf.auth.InMemoryWindowCounter;
import com.pingidentity.ps.oidf.platform.pf.auth.RedisWindowCounter;
import com.pingidentity.ps.oidf.platform.pf.auth.WindowCounter;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

@org.junit.jupiter.api.extension.ExtendWith(InMemoryStateAccepted.class)
class IssuanceRequestPathTest {

    private static final String REDIS_URL = System.getenv("OIDF_TEST_REDIS_URL");
    private static final String INTERNAL_URL = "https://vault.internal.example:8200/v1/transit/sign/agent";

    /** A clock the test moves. */
    static final class MovableClock extends Clock {
        private Instant now = Instant.parse("2026-09-30T00:00:00Z");

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

    @AfterEach
    void clearProperties() {
        System.clearProperty("oidf.trusted.proxies");
        System.clearProperty("oidf.attester.max.body.bytes");
        System.clearProperty("oidf.attester.issuance.requests.per.minute");
    }

    /** What an answer carried. */
    record Answer(int status, Map<String, Object> body, Map<String, String> headers) {
        String description() {
            return String.valueOf(this.body.get("error_description"));
        }
    }

    /** A POST of {@code body} from {@code remote}, with {@code headers}, through the servlet's entry point. */
    static Answer post(AttestationIssuanceServlet servlet, String remote, byte[] body, Long declaredLength,
                       Map<String, String> headers) throws Exception {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRemoteAddr()).thenReturn(remote);
        when(req.getContentLengthLong()).thenReturn(declaredLength == null ? -1L : declaredLength);
        when(req.getInputStream()).thenReturn(new BytesIn(body));
        headers.forEach((name, value) -> when(req.getHeaders(name)).thenAnswer(i -> Collections.enumeration(List.of(value))));
        return answer(servlet, req);
    }

    static Answer answer(AttestationIssuanceServlet servlet, HttpServletRequest req) throws Exception {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter out = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(out));
        int[] status = {0};
        Map<String, String> headers = new HashMap<>();
        doAnswer(i -> status[0] = i.getArgument(0)).when(resp).setStatus(anyInt());
        doAnswer(i -> headers.put(i.getArgument(0), i.getArgument(1))).when(resp).setHeader(anyString(), anyString());
        servlet.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) resp);
        return new Answer(status[0], JsonUtil.parseJson(out.toString()), headers);
    }

    static Answer post(AttestationIssuanceServlet servlet, String body) throws Exception {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        return post(servlet, "192.0.2.1", bytes, (long) bytes.length, Map.of());
    }

    /** A body that passes parsing and the field checks, so issuance goes on to find the client. */
    static String wellFormed() {
        return JsonUtil.toJson(Map.of("instance_key", Map.of("kty", "EC"), "svid", "a.b.c", "proof", "p.q.r"));
    }

    /** A resolver whose client lookup fails with {@code thrown}. */
    static IssuanceClientResolver failing(RuntimeException unexpected, IssuanceException thrown) {
        return new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw thrown;
            }

            @Override
            public List<AttesterClient> attestationClients() throws IssuanceException {
                if (unexpected != null) {
                    throw unexpected;
                }
                throw thrown;
            }
        };
    }

    static final class BytesIn extends ServletInputStream {
        private final InputStream in;
        int read;

        BytesIn(byte[] bytes) {
            this.in = new ByteArrayInputStream(bytes);
        }

        @Override
        public int read() throws IOException {
            int b = this.in.read();
            if (b >= 0) {
                this.read++;
            }
            return b;
        }

        @Override
        public boolean isFinished() {
            return false;
        }

        @Override
        public boolean isReady() {
            return true;
        }

        @Override
        public void setReadListener(ReadListener listener) {
        }
    }

    // ---- the body cap ---------------------------------------------------------------------------------------------

    @Test
    @Requirement("CAS §4.6")
    void aBodyDeclaredLargerThanTheCapIsRefused413WithNothingRead() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setMaxBodyBytes(4096);
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRemoteAddr()).thenReturn("192.0.2.1");
        when(req.getContentLengthLong()).thenReturn(4097L);
        BytesIn in = new BytesIn(new byte[8192]);
        when(req.getInputStream()).thenReturn(in);
        Answer a = answer(servlet, req);
        assertEquals(413, a.status());
        assertEquals("invalid_request", a.body().get("error"));
        assertEquals(0, in.read, "nothing of the body is read");
        assertNotNull(a.headers().get(AttestationIssuanceServlet.CORRELATION_HEADER));
    }

    @Test
    void aBodyFoundLargerOnceTheCapIsReachedIsRefusedWithNoMoreRead() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setMaxBodyBytes(4096);
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getRemoteAddr()).thenReturn("192.0.2.1");
        when(req.getContentLengthLong()).thenReturn(-1L);
        BytesIn in = new BytesIn(new byte[100_000]);
        when(req.getInputStream()).thenReturn(in);
        Answer a = answer(servlet, req);
        assertEquals(413, a.status());
        assertEquals(4097, in.read, "one byte past the cap, and no more");
    }

    @Test
    void theDefaultCapIs32KiBAndABodyAtTheCapIsRead() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        String padded = "{\"pad\":\"" + "x".repeat(32 * 1024 - 10) + "\"}";
        assertEquals(32 * 1024, padded.length());
        Answer a = post(servlet, padded);
        assertEquals(400, a.status(), "read and parsed: it is refused for its fields, not its size");
        assertEquals("missing instance_key", a.description());
        assertEquals(413, post(servlet, padded + " ").status());
    }

    @Test
    void aBodyThatCannotBeReadIsAnInvalidRequest() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        when(req.getInputStream()).thenThrow(new IOException("connection reset by " + INTERNAL_URL));
        Answer a = answer(servlet, req);
        assertEquals(400, a.status());
        assertEquals("the request body could not be read", a.description());
    }

    @Test
    void aBodyThatIsNotAJsonObjectIsAnInvalidRequest() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        assertEquals("request body is not valid JSON", post(servlet, "null").description(), "jose4j refuses a null");
        assertEquals("request body is not valid JSON", post(servlet, "").description());
        assertEquals("request body is not valid JSON", post(servlet, "[1]").description());
    }

    // ---- the rate limit -------------------------------------------------------------------------------------------

    @Test
    void anAddressPastItsMinuteIsRefused429WithRetryAfterUntilTheMinuteEnds() throws Exception {
        MovableClock clock = new MovableClock();
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setRateCounter(new InMemoryWindowCounter(clock));
        servlet.setRequestsPerMinute(3);
        for (int i = 0; i < 3; i++) {
            assertEquals(400, post(servlet, "{}").status());
            clock.advance(Duration.ofSeconds(10));
        }
        Answer limited = post(servlet, "{}");
        assertEquals(429, limited.status());
        assertEquals("temporarily_unavailable", limited.body().get("error"));
        assertEquals("30", limited.headers().get("Retry-After"), "the window opened 30 s ago");
        assertTrue(limited.description().contains("3 issuance requests"), limited.description());

        byte[] other = "{}".getBytes(StandardCharsets.UTF_8);
        assertEquals(400, post(servlet, "198.51.100.7", other, 2L, Map.of()).status(), "another address has its own");

        clock.advance(Duration.ofSeconds(30));
        assertEquals(400, post(servlet, "{}").status(), "a new minute");
    }

    @Test
    void behindATrustedProxyEachClientIsCountedAndAForgedChainIsNot() throws Exception {
        System.setProperty("oidf.trusted.proxies", "10.0.0.0/8");
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setRateCounter(new InMemoryWindowCounter(new MovableClock()));
        servlet.setRequestsPerMinute(1);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        assertEquals(400, post(servlet, "10.0.0.5", body, 2L, Map.of("X-Forwarded-For", "192.0.2.1")).status());
        assertEquals(429, post(servlet, "10.0.0.5", body, 2L, Map.of("X-Forwarded-For", "192.0.2.1")).status());
        assertEquals(400, post(servlet, "10.0.0.5", body, 2L, Map.of("X-Forwarded-For", "192.0.2.2")).status());
        assertEquals(429, post(servlet, "10.0.0.5", body, 2L, Map.of("X-Forwarded-For", "203.0.113.9, 192.0.2.2")).status());
        // From a sender not listed, the header is not believed: it is counted as itself.
        assertEquals(400, post(servlet, "198.51.100.1", body, 2L, Map.of("X-Forwarded-For", "192.0.2.3")).status());
        assertEquals(429, post(servlet, "198.51.100.1", body, 2L, Map.of("X-Forwarded-For", "192.0.2.4")).status());
    }

    @Test
    void aCounterThatCannotBeWrittenRefusesTheRequest503WithNoInternalText() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setRateCounter(new WindowCounter() {
            @Override
            public WindowCount hit(String key, Duration window) throws IOException {
                throw new IOException("redis.internal.example:6379 refused the connection");
            }

            @Override
            public WindowCount peek(String key) {
                throw new UnsupportedOperationException();
            }
        });
        Answer a = post(servlet, "{}");
        assertEquals(503, a.status());
        assertEquals("temporarily_unavailable", a.body().get("error"));
        assertFalse(a.description().contains("redis"), a.description());
        assertTrue(a.description().contains(a.headers().get(AttestationIssuanceServlet.CORRELATION_HEADER)));
    }

    @Test
    void anUnattributableCallerSharesOneBucket() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setRateCounter(new InMemoryWindowCounter(new MovableClock()));
        servlet.setRequestsPerMinute(1);
        byte[] body = "{}".getBytes(StandardCharsets.UTF_8);
        assertEquals(400, post(servlet, null, body, 2L, Map.of()).status());
        assertEquals(429, post(servlet, " ", body, 2L, Map.of()).status());
    }

    @Test
    void withNoRedisTheCounterIsThisNodes() {
        assumeTrue(System.getenv("OIDF_REDIS_URL") == null && System.getenv("REDIS_URL") == null);
        assertInstanceOf(InMemoryWindowCounter.class, AttestationIssuanceServlet.defaultRateCounter());
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        assertInstanceOf(InMemoryWindowCounter.class, servlet.rateCounter());
        assertTrue(servlet.rateCounter() == servlet.rateCounter(), "made once");
    }

    @Test
    void theLimitIsSharedByNodesThroughRedis() throws Exception {
        assumeTrue(REDIS_URL != null && !REDIS_URL.isBlank(), "set OIDF_TEST_REDIS_URL to run the live Redis test");
        try (RedisClient client = new RedisClient(RedisConfig.builder(REDIS_URL).profile(DeploymentProfile.DEVELOPMENT).build())) {
            String prefix = AttestationIssuanceServlet.RATE_NAMESPACE + ":" + UUID.randomUUID();
            AttestationIssuanceServlet nodeA = new AttestationIssuanceServlet();
            AttestationIssuanceServlet nodeB = new AttestationIssuanceServlet();
            nodeA.setRateCounter(new RedisWindowCounter(client, prefix));
            nodeB.setRateCounter(new RedisWindowCounter(client, prefix));
            nodeA.setRequestsPerMinute(2);
            nodeB.setRequestsPerMinute(2);
            assertEquals(400, post(nodeA, "{}").status());
            assertEquals(400, post(nodeB, "{}").status());
            Answer third = post(nodeA, "{}");
            assertEquals(429, third.status(), "two nodes, one allowance");
            long retryAfter = Long.parseLong(third.headers().get("Retry-After"));
            assertTrue(retryAfter >= 1 && retryAfter <= 60, String.valueOf(retryAfter));
        }
    }

    @Test
    void initReadsTheLimitsStrictly() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        System.setProperty("oidf.attester.issuance.requests.per.minute", "1");
        System.setProperty("oidf.attester.max.body.bytes", "4096");
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.init(config);
        servlet.setRateCounter(new InMemoryWindowCounter(new MovableClock()));
        assertEquals(413, post(servlet, "{\"pad\":\"" + "x".repeat(5000) + "\"}").status());
        assertEquals(429, post(servlet, "{}").status());

        System.setProperty("oidf.attester.max.body.bytes", "1024");
        AttestationIssuanceServlet refused = new AttestationIssuanceServlet();
        refused.init(config);
        HttpServletResponse gated = mock(HttpServletResponse.class);
        when(gated.getOutputStream()).thenReturn(new jakarta.servlet.ServletOutputStream() {
            @Override
            public void write(int b) {
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setWriteListener(jakarta.servlet.WriteListener listener) {
            }
        });
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("POST");
        refused.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) gated);
        verify(gated).setStatus(503);
    }

    // ---- every failure a CAS §4.6 error ---------------------------------------------------------------------------

    @Test
    @Requirement("CAS §4.6")
    void aServerErrorCarriesAFixedDescriptionAndTheCorrelationIdNotTheException() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(failing(null, IssuanceException.serverError("trust bundle could not be fetched: " + INTERNAL_URL)));
        Answer a = post(servlet, wellFormed());
        assertEquals(500, a.status());
        assertEquals("server_error", a.body().get("error"));
        assertFalse(a.description().contains("internal.example"), a.description());
        String id = a.headers().get(AttestationIssuanceServlet.CORRELATION_HEADER);
        assertNotNull(id);
        assertTrue(a.description().contains(id), a.description());
    }

    @Test
    @Requirement("CAS §4.6")
    void anUnexpectedExceptionIsAServerErrorWithNoStackOrInternalText() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(failing(new IllegalStateException("PingFederate at pf-node-1.internal said no: "
                + INTERNAL_URL), null));
        Answer a = post(servlet, wellFormed());
        assertEquals(500, a.status());
        assertEquals("server_error", a.body().get("error"));
        assertFalse(a.description().contains("internal"), a.description());
        assertFalse(a.description().contains("IllegalStateException"), a.description());
        assertEquals(2, a.body().size(), "error and error_description, nothing else");
    }

    @Test
    @Requirement("CAS §4.6")
    void anInvalidClientNamesNoConfiguration() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(failing(null, IssuanceException.invalidClient(
                "attestation_signing_jwk is invalid: fetched from " + INTERNAL_URL)));
        Answer a = post(servlet, wellFormed());
        assertEquals(400, a.status());
        assertEquals("invalid_client", a.body().get("error"));
        assertFalse(a.description().contains("attestation_signing_jwk"), a.description());
    }

    @Test
    @Requirement("CAS §4.6")
    void anUnavailableStoreIsTemporarilyUnavailableWithAFixedDescription() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(failing(null, IssuanceException.temporarilyUnavailable("redis at " + INTERNAL_URL)));
        Answer a = post(servlet, wellFormed());
        assertEquals(503, a.status());
        assertTrue(a.description().startsWith("the attester cannot check this request now"), a.description());
    }

    @Test
    void aRefusalOfTheRequestSaysWhatIsWrongWithIt() throws Exception {
        Answer a = post(new AttestationIssuanceServlet(), "{\"agent_id\":\"x\"}");
        assertEquals(400, a.status());
        assertTrue(a.description().contains("agent_id"), a.description());
        assertNotNull(a.headers().get(AttestationIssuanceServlet.CORRELATION_HEADER));
    }

    @Test
    void aMethodOtherThanPostIs405WithAllow() throws Exception {
        for (String method : List.of("GET", "HEAD", "OPTIONS", "PUT")) {
            HttpServletRequest req = mock(HttpServletRequest.class);
            when(req.getMethod()).thenReturn(method);
            AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
            HttpServletResponse resp = mock(HttpServletResponse.class);
            StringWriter out = new StringWriter();
            when(resp.getWriter()).thenReturn(new PrintWriter(out));
            servlet.service((jakarta.servlet.ServletRequest) req, (jakarta.servlet.ServletResponse) resp);
            verify(resp).setStatus(405);
            verify(resp).setHeader("Allow", "POST");
            assertEquals("invalid_request", JsonUtil.parseJson(out.toString()).get("error"), method);
            verify(resp, never()).setHeader(eq("Access-Control-Allow-Origin"), anyString());
        }
    }

    @Test
    void genericDescriptionsNameTheId() {
        assertTrue(AttestationIssuanceServlet.genericDescription("server_error", "x1").endsWith("x1"));
        assertTrue(AttestationIssuanceServlet.genericDescription("invalid_client", "x2").endsWith("x2"));
        assertTrue(AttestationIssuanceServlet.genericDescription("temporarily_unavailable", "x3").contains("x3"));
    }

    // ---- the miss refresh -----------------------------------------------------------------------------------------

    @Test
    void aMissAsksEveryPluginOfAChainToReadAgain() {
        List<String> asked = new ArrayList<>();
        IssuanceClientResolver yes = refresher("yes", true, asked);
        IssuanceClientResolver no = refresher("no", false, asked);
        assertTrue(AttestationIssuanceServlet.refreshAfterMiss(new ChainClientResolver(List.of(yes, no))));
        assertEquals(List.of("yes", "no"), asked, "every plugin, even after one said yes");
        asked.clear();
        assertFalse(AttestationIssuanceServlet.refreshAfterMiss(new ChainClientResolver(List.of(no))));
        assertFalse(AttestationIssuanceServlet.refreshAfterMiss(no));
        assertTrue(AttestationIssuanceServlet.refreshAfterMiss(yes));
    }

    private static IssuanceClientResolver refresher(String name, boolean refreshes, List<String> asked) {
        return new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.invalidClient("none");
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of();
            }

            @Override
            public boolean refreshAfterMiss() {
                asked.add(name);
                return refreshes;
            }
        };
    }

    @Test
    void aMissWithNothingToReadAgainIsAnsweredAsBefore() throws Exception {
        AttestationIssuanceServlet servlet = new AttestationIssuanceServlet();
        servlet.setClientResolver(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) throws IssuanceException {
                throw IssuanceException.invalidClient("none");
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of();
            }
        });
        Answer a = post(servlet, wellFormed());
        assertEquals("invalid_client", a.body().get("error"));
    }

    @Test
    void theDefaultResolverReadsNothingAgain() {
        assertFalse(new IssuanceClientResolver() {
            @Override
            public AttestationIssuanceConfig resolve(String clientId) {
                return null;
            }

            @Override
            public List<AttesterClient> attestationClients() {
                return List.of();
            }
        }.refreshAfterMiss());
    }
}
