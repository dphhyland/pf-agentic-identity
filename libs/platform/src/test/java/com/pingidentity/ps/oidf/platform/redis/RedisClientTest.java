package com.pingidentity.ps.oidf.platform.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The client against an in-process RESP server: the commands, the key prefixes (0.4.0's keys found where 0.4.0 wrote
 * them), the scripts with their NOSCRIPT fallback, the bounded pool, the command deadline, the one retry, and RESP
 * replies it must refuse. {@link RedisLiveTest} runs the commands and scripts against a real Redis.
 */
class RedisClientTest {
    private FakeRedis redis;
    private RedisClient client;

    @BeforeEach
    void start() throws IOException {
        this.redis = new FakeRedis("s3cr3t", FakeRedis.Role.MASTER);
        this.client = client(this.redis.url("redis", "127.0.0.1") + "/2", 2, 2000L);
    }

    @AfterEach
    void stop() throws IOException {
        this.client.close();
        this.redis.close();
    }

    private static RedisClient client(String url, int pool, long commandMillis) {
        return new RedisClient(RedisConfig.builder(url).profile(DeploymentProfile.DEVELOPMENT).poolSize(pool)
                .borrowTimeout(Duration.ofMillis(200)).commandTimeout(Duration.ofMillis(commandMillis)).build());
    }

    @Test
    void aConnectionAuthenticatesSelectsItsDatabaseAndIsReused() throws IOException {
        assertTrue(this.client.ping());
        assertTrue(this.client.ping());
        assertEquals(List.of("AUTH default s3cr3t", "SELECT 2", "PING", "PING"), this.redis.commands());
        assertEquals(1, this.redis.accepted(), "the second command reused the first connection");

        try (FakeRedis open = new FakeRedis(null, FakeRedis.Role.MASTER);
             RedisClient bare = client("redis://127.0.0.1:" + open.port(), 1, 2000L);
             RedisClient passwordOnly = client("redis://pw@127.0.0.1:" + open.port(), 1, 2000L)) {
            assertTrue(bare.ping());
            assertEquals(List.of("PING"), open.commands(), "no password, no AUTH; database 0, no SELECT");
            open.clearCommands();
            assertThrows(RedisErrorReply.class, passwordOnly::ping, "a server with no password refuses AUTH");
            assertEquals(List.of("AUTH pw"), open.commands(), "a bare userinfo is sent as the password alone");
        }
    }

    @Test
    void theCommandsLeasesAndRateLimitsNeed() throws IOException {
        Duration minute = Duration.ofMinutes(1);
        assertTrue(this.client.setIfAbsent("k", "a", minute));
        assertFalse(this.client.setIfAbsent("k", "b", minute), "NX: the first writer wins");
        assertEquals("a", this.client.get("k"));
        assertTrue(this.client.set("k", "b", minute), "SET without NX always sets");
        assertEquals("b", this.client.get("k"));
        assertNull(this.client.get("absent"));
        assertTrue(this.client.pexpire("k", Duration.ofMillis(1)));
        assertFalse(this.client.pexpire("absent", minute));
        assertEquals(1L, this.client.incr("n"));
        assertEquals(2L, this.client.incr("n"));
        assertEquals(1L, this.client.del("n", "absent"));
        assertEquals(0L, this.client.del("n"));
        assertTrue(this.redis.commands().contains("SET k a NX PX 60000"), this.redis.commands().toString());

        assertTrue(this.client.setIfAbsent("lease", "holder-1", minute));
        assertFalse(this.client.compareAndExtend("lease", "holder-2", minute), "only the holder renews");
        assertTrue(this.client.compareAndExtend("lease", "holder-1", minute));
        assertFalse(this.client.compareAndDelete("lease", "holder-2"), "only the holder releases");
        assertEquals("holder-1", this.client.get("lease"));
        assertTrue(this.client.compareAndDelete("lease", "holder-1"));
        assertNull(this.client.get("lease"));
        assertFalse(this.client.compareAndExtend("lease", "holder-1", minute), "nothing to renew once released");

        WindowCount first = this.client.countInWindow("rate", Duration.ofSeconds(10));
        assertEquals(1L, first.count());
        assertTrue(first.remaining().compareTo(Duration.ofSeconds(10)) <= 0 && !first.remaining().isNegative(), first.toString());
        assertEquals(2L, this.client.countInWindow("rate", Duration.ofSeconds(10)).count());

        assertThrows(IllegalArgumentException.class, () -> this.client.set("k", "v", Duration.ZERO));
        assertThrows(NullPointerException.class, () -> this.client.set("k", "v", null));
        assertThrows(IllegalArgumentException.class, () -> this.client.call());
    }

    @Test
    void aCounterSomethingLeftWithoutATtlGetsOne() throws IOException {
        this.redis.put("rate", "41");
        WindowCount count = this.client.countInWindow("rate", Duration.ofSeconds(5));
        assertEquals(42L, count.count());
        assertEquals(Duration.ofSeconds(5), count.remaining());
    }

    @Test
    void aScriptRedisDoesNotHoldIsSentInFullOnceAndByDigestAfter() throws IOException {
        this.client.compareAndDelete("k", "v");
        this.client.compareAndDelete("k", "v");
        String sha = RedisScript.COMPARE_AND_DELETE.sha1();
        assertEquals(List.of("EVALSHA " + sha + " 1 k v", "EVAL " + RedisScript.COMPARE_AND_DELETE.source() + " 1 k v",
                "EVALSHA " + sha + " 1 k v"), this.redis.commands().subList(2, 5));
        this.redis.forgetScripts();
        this.client.compareAndDelete("k", "v");
        assertTrue(this.redis.commands().get(6).startsWith("EVAL "), "after SCRIPT FLUSH the source goes again");

        RedisScript unknown = new RedisScript("return 1");
        assertThrows(RedisErrorReply.class, () -> this.client.eval(unknown, List.of(), List.of()));
        List<String> sent = this.redis.commands();
        assertEquals(List.of("EVALSHA " + unknown.sha1() + " 0", "EVAL return 1 0"), sent.subList(sent.size() - 2, sent.size()),
                "NOSCRIPT: the source went next");
        this.redis.rawNextReply("-ERR something else\r\n");
        assertEquals("ERR", assertThrows(RedisErrorReply.class, () -> this.client.compareAndDelete("k", "v")).code());
        assertEquals(40, RedisScript.FIXED_WINDOW.sha1().length());
        assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", RedisScript.sha1(""));
        assertEquals(List.of("EVAL", "s", "2", "k1", "k2", "a"), List.of(RedisClient.scriptCommand("EVAL", "s", List.of("k1", "k2"), List.of("a"))));
    }

    @Test
    void aKeyspacePrefixesEveryKeyAndFindsZeroFourZerosKeys() throws IOException {
        // 0.4.0's RedisAttestationStore wrote oidf:as:challenge:<value> with SET ... EX; a view over oidf:as finds it.
        this.client.call("SET", "oidf:as:challenge:abc", "1", "EX", "60");
        RedisKeyspace as = this.client.keyspace("oidf:as");
        assertEquals("oidf:as", as.prefix());
        assertEquals("oidf:as:challenge:abc", as.key("challenge:abc"));
        assertEquals("1", as.get("challenge:abc"));
        assertEquals(1L, as.del("challenge:abc"));
        assertNull(this.redis.value("oidf:as:challenge:abc"));

        RedisKeyspace fed = this.client.keyspace("oidf:fed:endpoint");
        assertTrue(fed.setIfAbsent("jti:c j", "1", Duration.ofMinutes(1)));
        assertEquals("1", this.redis.value("oidf:fed:endpoint:jti:c j"));
        assertTrue(fed.set("x", "2", Duration.ofMinutes(1)));
        assertEquals(1L, fed.incr("n"));
        assertTrue(fed.pexpire("n", Duration.ofMinutes(1)));
        assertEquals(2L, fed.countInWindow("n", Duration.ofMinutes(1)).count());
        assertTrue(fed.setIfAbsent("lease", "me", Duration.ofMinutes(1)));
        assertTrue(fed.compareAndExtend("lease", "me", Duration.ofMinutes(1)));
        assertTrue(fed.compareAndDelete("lease", "me"));

        for (String bad : new String[]{null, "", "oidf:", ":oidf", "oidf::as", "oidf as", "oidf:*"}) {
            assertThrows(IllegalArgumentException.class, () -> this.client.keyspace(bad), String.valueOf(bad));
        }
    }

    @Test
    void anErrorReplyKeepsTheConnectionAndNamesItsCode() throws IOException {
        RedisErrorReply e = assertThrows(RedisErrorReply.class, () -> this.client.call("NOSUCH"));
        assertEquals("ERR", e.code());
        assertEquals("Redis error reply: ERR unknown command 'NOSUCH'", e.getMessage());
        assertEquals("ERR unknown command 'NOSUCH'", e.line());
        assertTrue(this.client.ping());
        assertEquals(1, this.redis.accepted(), "an error reply leaves the connection aligned and pooled");
        assertEquals("OK", new RedisErrorReply("OK").code());

        // Inside an array an error is a value, not a throw, so the rest of the array is still read.
        this.redis.rawNextReply("*2\r\n-ERR inner\r\n:7\r\n");
        List<?> mixed = (List<?>) this.client.call("ANY");
        assertInstanceOf(RedisErrorReply.class, mixed.get(0));
        assertEquals(7L, mixed.get(1));
        assertTrue(this.client.ping());
    }

    @Test
    void repliesOfEveryShapeAndTheOnesThatAreRefused() throws IOException {
        assertTrue(this.client.ping());
        this.redis.rawNextReply("*-1\r\n");
        assertNull(this.client.call("X"));
        this.redis.rawNextReply("$0\r\n\r\n");
        assertEquals("", this.client.call("X"));
        this.redis.rawNextReply("*2\r\n$3\r\nh\u00e9\r\n+ok\r\n");
        assertEquals(List.of("h\u00e9", "ok"), this.client.call("X"));

        // Each on a fresh connection to a server with no password, so the reply is the command's and nothing
        // reused is retried.
        try (FakeRedis open = new FakeRedis(null, FakeRedis.Role.MASTER)) {
            for (String bad : new String[]{"?what\r\n", ":twelve\r\n", "$99999999999\r\n", "$-2\r\n", "*2000000\r\n",
                    "$1\r\nab\r\n", "$1\r\na\rx", "+ok\rx", "$5\r\nab|", "+ok|", "*2\r\n:1\r\n|", "",
                    "+" + "a".repeat(RedisConnection.MAX_LINE + 1) + "\r\n"}) {
                try (RedisClient fresh = client("redis://127.0.0.1:" + open.port(), 1, 2000L)) {
                    if (bad.isEmpty()) {
                        open.dropNextCommand();
                    } else if (bad.endsWith("|")) {
                        open.rawNextReplyThenClose(bad.substring(0, bad.length() - 1));
                    } else {
                        open.rawNextReply(bad);
                    }
                    assertThrows(IOException.class, () -> fresh.call("X"), bad.length() > 40 ? "a line past the cap" : bad);
                }
                open.closeConnections();
            }
        }
        assertThrows(IOException.class, () -> RedisConnection.number("5", 6, 7));
        assertThrows(IOException.class, () -> RedisConnection.number("8", 6, 7));
        assertEquals(6L, RedisConnection.number("6", 6, 7));
    }

    @Test
    void aStaleConnectionIsRetriedOnceOnAFreshOne() throws Exception {
        assertTrue(this.client.ping());
        this.redis.closeConnections();
        assertTrue(this.client.ping(), "the pooled connection had gone; the retry opened another");
        assertEquals(2, this.redis.accepted());

        this.redis.dropNextCommand();
        assertTrue(this.client.ping(), "dropped mid-command on a reused connection: retried");
        assertEquals(3, this.redis.accepted());
    }

    @Test
    void aFreshConnectionThatFailsIsNotRetried() throws Exception {
        this.redis.dropNextCommand();
        assertThrows(IOException.class, () -> this.client.ping(), "nothing reused, so nothing stale to blame");
        assertEquals(1, this.redis.accepted());

        int port;
        try (ServerSocket closed = new ServerSocket(0)) {
            port = closed.getLocalPort();
        }
        try (RedisClient nowhere = client("redis://127.0.0.1:" + port, 1, 2000L)) {
            assertThrows(IOException.class, nowhere::ping);
        }
    }

    @Test
    void theRetryItselfFailingIsTheFailure() throws Exception {
        assertTrue(this.client.ping());
        this.redis.closeConnections();
        this.redis.close();
        assertThrows(IOException.class, () -> this.client.ping());
    }

    @Test
    void everyCommandIsUnderItsDeadline() throws Exception {
        try (RedisClient quick = client(this.redis.url("redis", "127.0.0.1"), 1, 300L)) {
            assertTrue(quick.ping());
            this.redis.silent(true);
            long start = System.nanoTime();
            assertThrows(SocketTimeoutException.class, quick::ping);
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue(took >= 250L && took < 2000L, "took " + took + " ms, the retry included");
            this.redis.silent(false);
        }
        assertThrows(SocketTimeoutException.class, () -> RedisConnection.remainingMillis(System.nanoTime() - 1L));
        assertEquals(1, RedisConnection.remainingMillis(System.nanoTime() + 10_000L));
    }

    @Test
    void thePoolHoldsAtMostItsSizeAndABorrowerWaitsOnlyItsDeadline() throws Exception {
        ExecutorService threads = Executors.newFixedThreadPool(3);
        try (RedisClient one = client(this.redis.url("redis", "127.0.0.1"), 1, 3000L)) {
            this.redis.delay(600L);
            CountDownLatch started = new CountDownLatch(1);
            Future<Boolean> holder = threads.submit(() -> {
                started.countDown();
                return one.ping();
            });
            started.await();
            Thread.sleep(100L);
            IOException e = assertThrows(IOException.class, one::ping);
            assertTrue(e.getMessage().contains("OIDF_REDIS_POOL_SIZE is 1"), e.getMessage());
            assertTrue(holder.get(5, TimeUnit.SECONDS));
            this.redis.delay(0L);
            assertTrue(one.ping(), "the permit came back");
            assertEquals(1, this.redis.accepted(), "one connection, never two");

            Thread.currentThread().interrupt();
            assertThrows(InterruptedIOException.class, one::ping);
            assertTrue(Thread.interrupted(), "the interrupt is kept");
        } finally {
            threads.shutdownNow();
        }
    }

    @Test
    void aClosedClientRefusesCommandsAndClosesWhatItGetsBack() throws Exception {
        assertTrue(this.client.ping());
        this.client.close();
        IOException e = assertThrows(IOException.class, () -> this.client.ping());
        assertTrue(e.getMessage().contains("closed"), e.getMessage());

        this.redis.delay(300L);
        RedisClient racing = client(this.redis.url("redis", "127.0.0.1"), 1, 3000L);
        Thread closer = new Thread(() -> {
            try {
                Thread.sleep(100L);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            racing.close();
        });
        closer.start();
        assertTrue(racing.ping(), "a command in flight when the client closes still finishes");
        closer.join();
        assertThrows(IOException.class, racing::ping);
    }

    @Test
    void theDecisions() {
        assertTrue(RedisClient.retries(true, false));
        assertTrue(RedisClient.retries(false, true));
        assertFalse(RedisClient.retries(false, false));
        RedisErrorReply readOnly = new RedisErrorReply("READONLY You can't write against a read only replica.");
        assertTrue(RedisClient.failsOver(readOnly, true, 0));
        assertFalse(RedisClient.failsOver(readOnly, true, 1));
        assertFalse(RedisClient.failsOver(readOnly, false, 0));
        assertFalse(RedisClient.failsOver(new RedisErrorReply("ERR x"), true, 0));
    }

    @Test
    void aWindowCountIsTwoIntegers() throws IOException {
        assertEquals(new WindowCount(3L, Duration.ofMillis(5)), WindowCount.of(List.of(3L, 5L)));
        for (Object bad : new Object[]{null, "x", List.of(3L), List.of("3", 5L), List.of(3L, "5")}) {
            assertThrows(IOException.class, () -> WindowCount.of(bad), String.valueOf(bad));
        }
    }
}
