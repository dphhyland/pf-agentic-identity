package com.pingidentity.ps.oidf.platform.pf.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import com.pingidentity.ps.oidf.platform.redis.RedisKeyspace;
import com.pingidentity.ps.oidf.platform.redis.WindowCount;
import com.pingidentity.ps.oidf.rs.InMemoryReplayStore;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The two limits - failed authentications per client address, changes per operator - in this JVM with a clock the
 * test moves, and in Redis when {@code OIDF_TEST_REDIS_URL} names one (build.yml's java job sets it).
 */
class OperatorRateLimitTest {
    private static final String REDIS_URL = System.getenv("OIDF_TEST_REDIS_URL");

    private final OperatorFixture f;

    OperatorRateLimitTest() throws Exception {
        this.f = new OperatorFixture();
    }

    @AfterEach
    void close() {
        this.f.close();
    }

    private OperatorAuthenticator.Decision send(OperatorAuthenticator a, OperatorFixture.Request r, OperatorRoute route) {
        return a.authenticate(r.mock(), route);
    }

    @Test
    void anAddressThatFailsTenTimesInAMinuteIs429UntilTheMinuteEndsAndOthersAreNotAffected() throws Exception {
        OperatorAuthenticator a = this.f.jwt();
        for (int i = 0; i < 10; i++) {
            OperatorFixture.Request bad = OperatorFixture.bearer("not-a-token");
            assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class,
                    this.send(a, bad, OperatorFixture.READ)).status());
            this.f.clock.advance(Duration.ofSeconds(1));
        }
        // The eleventh request is refused before its token is looked at - a good token included.
        OperatorFixture.Request good = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
        OperatorAuthenticator.Refused limited = assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(a, good, OperatorFixture.READ));
        assertEquals(429, limited.status());
        assertEquals("too_many_failures", limited.reason());
        assertEquals(List.of(), limited.challenges());
        assertEquals(50L, limited.retryAfter(), "the window opened at the first failure, ten seconds ago");
        assertEquals("429", this.f.last().fields().get("status"));

        OperatorFixture.Request elsewhere = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
        elsewhere.address = "198.51.100.7";
        assertInstanceOf(OperatorAuthenticator.Authorised.class, this.send(a, elsewhere, OperatorFixture.READ));

        this.f.clock.advance(Duration.ofSeconds(51));
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.send(a, this.f.dpop(this.f.token("oidf.admin.read"), "GET"), OperatorFixture.READ));
    }

    @Test
    void theForwardedForHeaderIsNeverTheAddressCounted() throws Exception {
        OperatorAuthenticator a = this.f.jwt();
        for (int i = 0; i < 10; i++) {
            OperatorFixture.Request bad = OperatorFixture.bearer("not-a-token");
            this.send(a, bad, OperatorFixture.READ);
        }
        OperatorFixture.Request r = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
        // X-Forwarded-For is not read: the mock would answer null for it, and the container's address is the same.
        assertEquals(429, assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(a, r, OperatorFixture.READ)).status());
    }

    @Test
    void theFailureLimitIsASetting() throws Exception {
        Map<String, String> env = this.f.jwtSettings();
        env.put(OperatorAuthConfig.AUTH_FAILURES_PER_MINUTE, "2");
        OperatorAuthenticator a = this.f.authenticator(env, DeploymentProfile.PRODUCTION);
        this.send(a, new OperatorFixture.Request(), OperatorFixture.READ);
        this.send(a, new OperatorFixture.Request(), OperatorFixture.READ);
        assertEquals(429, assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(a, new OperatorFixture.Request(), OperatorFixture.READ)).status());
    }

    @Test
    void authoriseAnswersA429WithRetryAfterAndNoChallenge() throws Exception {
        Map<String, String> env = this.f.jwtSettings();
        env.put(OperatorAuthConfig.AUTH_FAILURES_PER_MINUTE, "1");
        OperatorAuthenticator a = this.f.authenticator(env, DeploymentProfile.PRODUCTION);
        a.authorise(new OperatorFixture.Request().mock(), mock(HttpServletResponse.class), OperatorFixture.READ);
        HttpServletResponse response = mock(HttpServletResponse.class);
        assertFalse(a.authorise(new OperatorFixture.Request().mock(), response, OperatorFixture.READ));
        verify(response).setStatus(429);
        verify(response).setHeader("Retry-After", "60");
        verify(response, never()).addHeader(eq("WWW-Authenticate"), anyString());
    }

    @Test
    void anOperatorThatMakesSixtyChangesInAMinuteIs429ForTheNextAndReadsAreNotCounted() throws Exception {
        OperatorAuthenticator a = this.f.jwt();
        String token = this.f.token("oidf.admin.read oidf.admin.entities");
        for (int i = 0; i < 60; i++) {
            assertInstanceOf(OperatorAuthenticator.Authorised.class,
                    this.send(a, this.f.dpop(token, "POST"), OperatorFixture.UPDATE), "change " + (i + 1));
        }
        for (int i = 0; i < 5; i++) {
            assertInstanceOf(OperatorAuthenticator.Authorised.class,
                    this.send(a, this.f.dpop(token, "GET"), OperatorFixture.READ));
        }
        OperatorAuthenticator.Refused r = assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(a, this.f.dpop(token, "POST"), OperatorFixture.UPDATE));
        assertEquals(429, r.status());
        assertEquals("too_many_changes", r.reason());
        assertEquals(60L, r.retryAfter());
        assertEquals(OperatorFixture.CLIENT, this.f.last().fields().get("actor"));
        this.f.clock.advance(Duration.ofSeconds(60));
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.send(a, this.f.dpop(token, "POST"), OperatorFixture.UPDATE));
    }

    /** A counter that cannot be read or written refuses as unavailable: no limit is ever skipped. */
    @Test
    void aCounterThatFailsIs503() throws Exception {
        WindowCounter failing = new WindowCounter() {
            @Override
            public WindowCount hit(String key, Duration window) throws IOException {
                throw new IOException("Redis is down");
            }

            @Override
            public WindowCount peek(String key) throws IOException {
                throw new IOException("Redis is down");
            }
        };
        WindowCounter fine = new InMemoryWindowCounter(this.f.clock);
        OperatorAuthConfig config = OperatorFixture.config(this.f.jwtSettings(), DeploymentProfile.DEVELOPMENT);
        OperatorAuthenticator reference = this.f.authenticator(this.f.jwtSettings(), DeploymentProfile.DEVELOPMENT);
        assertTrue(reference != null);
        String token = this.f.token("oidf.admin.read oidf.admin.entities");

        OperatorAuthenticator peekFails = new OperatorAuthenticator(config,
                new com.pingidentity.ps.oidf.rs.RemoteJwks(com.pingidentity.ps.oidf.platform.http.OutboundHttp.builder(
                        com.pingidentity.ps.oidf.platform.http.AddressPolicy.builder()
                                .trusting(this.f.origin() + "/pf/JWKS").build()).build(), this.f.origin() + "/pf/JWKS"),
                null, new InMemoryReplayStore(), failing, fine, request -> OperatorFixture.ISSUER);
        OperatorAuthenticator.Refused r = assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(peekFails, this.f.dpop(token, "GET"), OperatorFixture.READ));
        assertEquals(503, r.status());
        assertEquals("rate_limit_unavailable", r.reason());

        WindowCounter peeksOnly = new WindowCounter() {
            @Override
            public WindowCount hit(String key, Duration window) throws IOException {
                throw new IOException("Redis is read-only");
            }

            @Override
            public WindowCount peek(String key) {
                return new WindowCount(0, Duration.ZERO);
            }
        };
        OperatorAuthenticator hitFails = new OperatorAuthenticator(config,
                new com.pingidentity.ps.oidf.rs.RemoteJwks(com.pingidentity.ps.oidf.platform.http.OutboundHttp.builder(
                        com.pingidentity.ps.oidf.platform.http.AddressPolicy.builder()
                                .trusting(this.f.origin() + "/pf/JWKS").build()).build(), this.f.origin() + "/pf/JWKS"),
                null, new InMemoryReplayStore(), peeksOnly, failing, request -> OperatorFixture.ISSUER);
        assertEquals("rate_limit_unavailable", assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(hitFails, new OperatorFixture.Request(), OperatorFixture.READ)).reason());
        OperatorAuthenticator.Refused change = assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(hitFails, this.f.dpop(token, "POST"), OperatorFixture.UPDATE));
        assertEquals(503, change.status());
        assertEquals(OperatorFixture.CLIENT, this.f.last().fields().get("actor"));
    }

    // ---- the counters -----------------------------------------------------------------------------------------------

    @Test
    void theInMemoryCounterCountsInAWindowFromTheFirstHitAndDropsItsOldestKeys() {
        InMemoryWindowCounter c = new InMemoryWindowCounter(this.f.clock, 2);
        assertEquals(new WindowCount(0, Duration.ZERO), c.peek("a"));
        assertEquals(new WindowCount(1, Duration.ofSeconds(60)), c.hit("a", Duration.ofSeconds(60)));
        this.f.clock.advance(Duration.ofSeconds(20));
        assertEquals(new WindowCount(2, Duration.ofSeconds(40)), c.hit("a", Duration.ofSeconds(60)));
        assertEquals(new WindowCount(2, Duration.ofSeconds(40)), c.peek("a"));
        this.f.clock.advance(Duration.ofSeconds(40));
        assertEquals(new WindowCount(0, Duration.ZERO), c.peek("a"));
        assertEquals(new WindowCount(1, Duration.ofSeconds(60)), c.hit("a", Duration.ofSeconds(60)));
        c.hit("b", Duration.ofSeconds(60));
        c.hit("c", Duration.ofSeconds(60));
        assertEquals(2, c.size());
        assertEquals(0, c.peek("a").count(), "the oldest key went first");
        assertThrows(IllegalArgumentException.class, () -> new InMemoryWindowCounter(this.f.clock, 0));
    }

    @Test
    void theRedisCounterPeeksWithoutCountingAndRefusesAReplyItCannotRead() throws Exception {
        RedisClient client = mock(RedisClient.class);
        RedisKeyspace keyspace = mock(RedisKeyspace.class);
        when(client.keyspace(any())).thenReturn(keyspace);
        when(keyspace.prefix()).thenReturn("oidf:admin:limit:auth");
        when(keyspace.key("k")).thenReturn("oidf:admin:limit:auth:k");
        when(keyspace.countInWindow("k", Duration.ofMinutes(1))).thenReturn(new WindowCount(3, Duration.ofSeconds(9)));
        RedisWindowCounter c = new RedisWindowCounter(client, "oidf:admin:limit:auth");
        assertEquals(new WindowCount(3, Duration.ofSeconds(9)), c.hit("k", Duration.ofMinutes(1)));
        when(client.eval(any(), anyList(), anyList())).thenReturn(List.of(3L, 9000L));
        assertEquals(new WindowCount(3, Duration.ofSeconds(9)), c.peek("k"));
        for (Object reply : new Object[] {null, "OK", List.of(1L), List.of("1", 2L), List.of(1L, "2")}) {
            when(client.eval(any(), anyList(), anyList())).thenReturn(reply);
            assertThrows(IOException.class, () -> c.peek("k"), String.valueOf(reply));
        }
    }

    /**
     * The assembly puts the DPoP replay store and both limits in Redis when a Redis client is given - the production
     * replay guarantee across nodes - and in this JVM when none is.
     */
    @Test
    void theAssemblyPutsTheReplayStoreAndBothLimitsInRedisWhenOneIsGiven() throws Exception {
        RedisClient client = mock(RedisClient.class);
        for (String prefix : List.of(OperatorAuthenticator.DPOP_NAMESPACE, OperatorAuthenticator.FAILURES_NAMESPACE,
                OperatorAuthenticator.MUTATIONS_NAMESPACE)) {
            RedisKeyspace keyspace = mock(RedisKeyspace.class);
            when(keyspace.prefix()).thenReturn(prefix);
            when(keyspace.key(anyString())).thenAnswer(call -> prefix + ":" + call.getArgument(0));
            when(keyspace.countInWindow(anyString(), any())).thenReturn(new WindowCount(1, Duration.ofMinutes(1)));
            when(client.keyspace(prefix)).thenReturn(keyspace);
        }
        when(client.eval(any(), anyList(), anyList())).thenReturn(List.of(0L, 0L));
        OperatorAuthConfig config = OperatorAuthConfig.from(OperatorFixture.settings(this.f.jwtSettings()),
                DeploymentProfile.PRODUCTION, com.pingidentity.ps.oidf.platform.profile.AcceptedRisks.none(), true);
        OperatorAuthenticator a = OperatorAuthenticator.from(config, client, request -> OperatorFixture.ISSUER,
                this.f.clock);
        verify(client).keyspace(OperatorAuthenticator.DPOP_NAMESPACE);
        verify(client).keyspace(OperatorAuthenticator.FAILURES_NAMESPACE);
        verify(client).keyspace(OperatorAuthenticator.MUTATIONS_NAMESPACE);
        assertEquals(401, assertInstanceOf(OperatorAuthenticator.Refused.class,
                this.send(a, OperatorFixture.bearer("not-a-token"), OperatorFixture.READ)).status());
        verify(client).eval(any(), anyList(), anyList());
        verify(client.keyspace(OperatorAuthenticator.FAILURES_NAMESPACE)).countInWindow(anyString(), any());
    }

    /** Each way the assembly can go on its token source and its TLS: a usable or an unusable configuration. */
    @Test
    void theAssemblyBuildsTheTokenSourceOnlyForAUsableConfiguration() throws Exception {
        Map<String, String> jwtNoKeys = this.f.jwtSettings();
        jwtNoKeys.remove(OperatorAuthConfig.JWKS_URL);
        Map<String, String> introspectionNoAudience = this.f.introspectionSettings();
        introspectionNoAudience.remove(OperatorAuthConfig.AUDIENCE);
        Map<String, String> insecureInProduction = this.f.jwtSettings();
        insecureInProduction.put(OperatorAuthConfig.INSECURE_TLS, "true");
        for (Map<String, String> env : List.of(jwtNoKeys, introspectionNoAudience, insecureInProduction)) {
            OperatorAuthConfig config = OperatorFixture.config(env, DeploymentProfile.PRODUCTION);
            assertFalse(config.usable());
            OperatorAuthenticator a = OperatorAuthenticator.from(config, null, request -> OperatorFixture.ISSUER,
                    this.f.clock);
            OperatorAuthenticator.Refused r = assertInstanceOf(OperatorAuthenticator.Refused.class,
                    this.send(a, this.f.dpop(this.f.token("oidf.admin.read"), "GET"), OperatorFixture.READ));
            assertEquals(503, r.status(), env.toString());
            assertEquals("not_configured", r.reason());
        }
        Map<String, String> insecureInDevelopment = this.f.jwtSettings();
        insecureInDevelopment.put(OperatorAuthConfig.INSECURE_TLS, "true");
        OperatorAuthConfig config = OperatorFixture.config(insecureInDevelopment, DeploymentProfile.DEVELOPMENT);
        assertTrue(config.usable(), String.valueOf(config.problem()));
        OperatorAuthenticator a = OperatorAuthenticator.from(config, null, request -> OperatorFixture.ISSUER,
                this.f.clock);
        assertInstanceOf(OperatorAuthenticator.Authorised.class,
                this.send(a, this.f.dpop(this.f.token("oidf.admin.read"), "GET"), OperatorFixture.READ));
    }

    /** Two authenticators on one Redis stand in for two nodes: the limits and the proofs are shared. */
    @Test
    void inRedisTheLimitsAndTheProofsAreSharedByEveryNode() throws Exception {
        assumeTrue(REDIS_URL != null && !REDIS_URL.isBlank(), "set OIDF_TEST_REDIS_URL to run the live Redis test");
        try (RedisClient client = new RedisClient(RedisConfig.builder(REDIS_URL)
                .profile(DeploymentProfile.DEVELOPMENT).build())) {
            Map<String, String> env = this.f.jwtSettings();
            OperatorAuthConfig config = OperatorAuthConfig.from(OperatorFixture.settings(env),
                    DeploymentProfile.PRODUCTION, com.pingidentity.ps.oidf.platform.profile.AcceptedRisks.none(), true);
            assertTrue(config.usable(), String.valueOf(config.problem()));
            OperatorAuthenticator nodeA = OperatorAuthenticator.from(config, client, request -> OperatorFixture.ISSUER,
                    this.f.clock);
            OperatorAuthenticator nodeB = OperatorAuthenticator.from(config, client, request -> OperatorFixture.ISSUER,
                    this.f.clock);
            OperatorFixture.Request r = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
            assertInstanceOf(OperatorAuthenticator.Authorised.class, nodeA.authenticate(r.mock(), OperatorFixture.READ));
            assertEquals("invalid_dpop_proof", assertInstanceOf(OperatorAuthenticator.Refused.class,
                    nodeB.authenticate(r.mock(), OperatorFixture.READ)).reason(), "a proof node A saw is a replay on B");

            String address = "203.0.113." + (1 + (int) (Math.random() * 250)) + "-" + UUID.randomUUID();
            for (int i = 0; i < 10; i++) {
                OperatorFixture.Request bad = OperatorFixture.bearer("not-a-token");
                bad.address = address;
                (i % 2 == 0 ? nodeA : nodeB).authenticate(bad.mock(), OperatorFixture.READ);
            }
            OperatorFixture.Request good = this.f.dpop(this.f.token("oidf.admin.read"), "GET");
            good.address = address;
            OperatorAuthenticator.Refused limited = assertInstanceOf(OperatorAuthenticator.Refused.class,
                    nodeB.authenticate(good.mock(), OperatorFixture.READ));
            assertEquals(429, limited.status());
            assertTrue(limited.retryAfter() >= 1 && limited.retryAfter() <= 60, String.valueOf(limited.retryAfter()));

            RedisWindowCounter counter = new RedisWindowCounter(client, "oidf:admin:limit:test:" + UUID.randomUUID());
            assertEquals(0, counter.peek("nobody").count());
            counter.hit("somebody", Duration.ofSeconds(30));
            assertEquals(1, counter.peek("somebody").count());
            assertTrue(counter.peek("somebody").remaining().toMillis() > 0);
        }
    }
}
