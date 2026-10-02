package com.pingidentity.ps.oidf.platform.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The client against a real Redis, which the fake cannot stand in for: the commands as Redis parses them, the
 * scripts as Redis runs them (the fake only emulates them by digest), and the TLS handshake with a real server.
 * Skipped, with the reason, unless the environment names a server - the variables client-attestation's
 * {@code RedisLiveTest} reads, which build.yml's java job sets for the whole reactor:
 *
 * <ul>
 *   <li>{@code OIDF_TEST_REDIS_URL} - a plaintext {@code redis://} URL, password included;</li>
 *   <li>{@code OIDF_TEST_REDIS_TLS_URL} and {@code OIDF_TEST_REDIS_CA_FILE} - a {@code rediss://} URL whose host the
 *       server's certificate names, and the CA that issued it ({@code tools/ci/start-tls-redis.sh});</li>
 *   <li>{@code OIDF_TEST_REDIS_SENTINELS}, {@code OIDF_TEST_REDIS_SENTINEL_MASTER} and
 *       {@code OIDF_TEST_REDIS_SENTINEL_URL} - a Sentinel set up by hand (CI does not start one; the README of
 *       libs/platform has the commands), the master's name, and a {@code redis://} URL with the master's password;
 *       with {@code OIDF_TEST_REDIS_SENTINEL_FAILOVER=true} as well, the test asks the first sentinel for a failover
 *       and follows the master to its new address.</li>
 * </ul>
 */
class RedisLiveTest {
    private static final String PLAIN = System.getenv("OIDF_TEST_REDIS_URL");
    private static final String TLS = System.getenv("OIDF_TEST_REDIS_TLS_URL");
    private static final String CA = System.getenv("OIDF_TEST_REDIS_CA_FILE");
    private static final String SENTINELS = System.getenv("OIDF_TEST_REDIS_SENTINELS");
    private static final String SENTINEL_MASTER = System.getenv("OIDF_TEST_REDIS_SENTINEL_MASTER");
    private static final String SENTINEL_URL = System.getenv("OIDF_TEST_REDIS_SENTINEL_URL");
    private static final boolean FAILOVER = "true".equals(System.getenv("OIDF_TEST_REDIS_SENTINEL_FAILOVER"));

    private static boolean set(String value) {
        return value != null && !value.isBlank();
    }

    private static RedisClient plain() {
        assumeTrue(set(PLAIN), "set OIDF_TEST_REDIS_URL to run the live Redis tests");
        return new RedisClient(RedisConfig.builder(PLAIN).profile(DeploymentProfile.DEVELOPMENT).build());
    }

    private static void needTls() {
        assumeTrue(set(TLS) && set(CA), "set OIDF_TEST_REDIS_TLS_URL and OIDF_TEST_REDIS_CA_FILE to run the live TLS Redis tests");
    }

    private static String unique(String name) {
        return "oidf:platform-test:" + name + ":" + UUID.randomUUID();
    }

    @Test
    void theCommandsAsRedisParsesThem() throws IOException {
        try (RedisClient client = plain()) {
            String key = unique("k");
            assertTrue(client.setIfAbsent(key, "a", Duration.ofSeconds(30)));
            assertFalse(client.setIfAbsent(key, "b", Duration.ofSeconds(30)));
            assertEquals("a", client.get(key));
            long ttl = (Long) client.call("PTTL", key);
            assertTrue(ttl > 0L && ttl <= 30_000L, "PX is milliseconds: " + ttl);
            assertTrue(client.set(key, "b", Duration.ofSeconds(30)));
            assertTrue(client.pexpire(key, Duration.ofSeconds(5)));
            assertTrue((Long) client.call("PTTL", key) <= 5_000L);
            assertEquals(1L, client.del(key));
            assertNull(client.get(key));
            String counter = unique("n");
            assertEquals(1L, client.incr(counter));
            assertEquals(2L, client.incr(counter));
            assertEquals(-1L, client.call("PTTL", counter), "INCR alone leaves no TTL");
            assertEquals(1L, client.del(counter));
            assertThrows(RedisErrorReply.class, () -> client.call("NOSUCHCOMMAND"));
        }
    }

    @Test
    void theLeaseScriptsAsRedisRunsThemIncludingAfterAScriptFlush() throws IOException {
        try (RedisClient client = plain()) {
            RedisKeyspace leases = client.keyspace("oidf:platform-test:lease");
            String key = UUID.randomUUID().toString();
            assertTrue(leases.setIfAbsent(key, "holder-1", Duration.ofSeconds(30)));
            assertFalse(leases.setIfAbsent(key, "holder-2", Duration.ofSeconds(30)));
            client.call("SCRIPT", "FLUSH");
            assertFalse(leases.compareAndExtend(key, "holder-2", Duration.ofSeconds(60)), "EVALSHA met NOSCRIPT, EVAL ran it");
            assertEquals(List.of(1L), client.call("SCRIPT", "EXISTS", RedisScript.COMPARE_AND_EXTEND.sha1()), "and loaded it");
            assertTrue(leases.compareAndExtend(key, "holder-1", Duration.ofSeconds(60)));
            assertTrue((Long) client.call("PTTL", leases.key(key)) > 30_000L, "the holder's renewal took");
            assertFalse(leases.compareAndDelete(key, "holder-2"));
            assertEquals("holder-1", leases.get(key));
            assertTrue(leases.compareAndDelete(key, "holder-1"));
            assertNull(leases.get(key));
            assertFalse(leases.compareAndExtend(key, "holder-1", Duration.ofSeconds(60)));
        }
    }

    @Test
    void theFixedWindowCounterAlwaysExpires() throws IOException {
        try (RedisClient client = plain()) {
            String key = unique("rate");
            WindowCount first = client.countInWindow(key, Duration.ofSeconds(10));
            assertEquals(1L, first.count());
            assertTrue(first.remaining().toMillis() > 9_000L && first.remaining().toMillis() <= 10_000L, first.toString());
            assertEquals(2L, client.countInWindow(key, Duration.ofSeconds(10)).count());
            client.call("SET", key, "41");
            WindowCount orphan = client.countInWindow(key, Duration.ofSeconds(5));
            assertEquals(42L, orphan.count());
            assertEquals(Duration.ofSeconds(5), orphan.remaining(), "a counter left without a TTL gets one");
            client.del(key);
        }
    }

    @Test
    void zeroFourZerosKeysAreFoundThroughAKeyspace() throws IOException {
        try (RedisClient client = plain()) {
            String challenge = UUID.randomUUID().toString();
            client.call("SET", "oidf:as:challenge:" + challenge, "1", "EX", "30");
            RedisKeyspace as = client.keyspace("oidf:as");
            assertEquals("1", as.get("challenge:" + challenge));
            assertEquals(1L, as.del("challenge:" + challenge));
        }
    }

    @Test
    void overTlsTheClientAuthenticatesAfterVerifyingTheServer() throws IOException {
        needTls();
        try (RedisClient client = new RedisClient(RedisConfig.builder(TLS).caFile(Path.of(CA)).build())) {
            assertTrue(client.tls());
            assertTrue(client.ping());
            String key = unique("tls");
            assertTrue(client.setIfAbsent(key, "v", Duration.ofSeconds(30)));
            assertEquals(1L, client.del(key));
        }
    }

    @Test
    void overTlsAServerWhoseCertificateDoesNotNameTheHostOrWhoseCaIsNotGivenIsRefused() {
        needTls();
        URI tls = URI.create(TLS);
        assumeTrue(!RedisTls.isIpLiteral(tls.getHost()), "the TLS URL must use the certificate's name, so an address can be the mismatch");
        try (RedisClient byAddress = new RedisClient(RedisConfig.builder(TLS.replace(tls.getHost(), "127.0.0.1"))
                .caFile(Path.of(CA)).build());
             RedisClient noCa = new RedisClient(RedisConfig.builder(TLS).build())) {
            assertThrows(IOException.class, byAddress::ping);
            assertThrows(IOException.class, noCa::ping, "the JVM's CAs did not issue the test certificate");
        }
    }

    @Test
    void plaintextIsRefusedUnderProductionEvenWhenTheServerIsThere() {
        assumeTrue(set(PLAIN), "set OIDF_TEST_REDIS_URL to run the live Redis tests");
        assertThrows(IllegalArgumentException.class, () -> new RedisClient(RedisConfig.builder(PLAIN).build()));
    }

    @Test
    void throughARealSentinelAndAfterAFailover() throws Exception {
        assumeTrue(set(SENTINELS) && set(SENTINEL_MASTER) && set(SENTINEL_URL),
                "set OIDF_TEST_REDIS_SENTINELS, OIDF_TEST_REDIS_SENTINEL_MASTER and OIDF_TEST_REDIS_SENTINEL_URL to run against Sentinel");
        List<String> sentinels = List.of(SENTINELS.split("[\\s,]+"));
        try (RedisClient client = new RedisClient(RedisConfig.builder(SENTINEL_URL).profile(DeploymentProfile.DEVELOPMENT)
                .sentinel(SENTINEL_MASTER, sentinels, null).build())) {
            assertTrue(client.sentinel());
            String key = unique("sentinel");
            assertTrue(client.set(key, "v", Duration.ofSeconds(60)));
            assertEquals("v", client.get(key));
            if (!FAILOVER) {
                return;
            }
            Object before = client.call("CONFIG", "GET", "port");
            RedisConfig.HostPort first = RedisConfig.HostPort.parse(sentinels.get(0));
            try (RedisClient sentinel = new RedisClient(RedisConfig.builder("redis://" + first).profile(DeploymentProfile.DEVELOPMENT).build())) {
                assertEquals("OK", sentinel.call("SENTINEL", "FAILOVER", SENTINEL_MASTER));
            }
            // During the switch a command may fail; within the window one lands on the new master.
            long until = System.nanoTime() + Duration.ofSeconds(30).toNanos();
            Exception last = null;
            while (System.nanoTime() < until) {
                try {
                    if (client.set(key, "w", Duration.ofSeconds(60)) && !before.equals(client.call("CONFIG", "GET", "port"))) {
                        last = null;
                        break;
                    }
                } catch (IOException | RedisErrorReply e) {
                    last = e;
                }
                Thread.sleep(250L);
            }
            Exception failure = last;
            assertNull(failure, () -> "never reached the new master: " + failure);
            assertFalse(before.equals(client.call("CONFIG", "GET", "port")), "the client follows the master to its new port");
            assertEquals("w", client.get(key), "and writes there");
            client.del(key);
        }
    }
}
