package com.pingidentity.ps.oidf.platform.redis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Sentinel against in-process fakes: the master found with {@code SENTINEL get-master-addr-by-name}, checked with
 * {@code ROLE}, and found again after a failover - a {@code READONLY} reply from the old master, now a replica, or
 * a connection lost to it. The sentinels are asked in order until one names the master.
 */
class RedisSentinelTest {
    private static final String MASTER = "mymaster";

    private FakeRedis sentinel;
    private FakeRedis first;
    private FakeRedis second;

    @BeforeEach
    void start() throws IOException {
        this.sentinel = new FakeRedis("sentinel-pw", FakeRedis.Role.SENTINEL);
        this.first = new FakeRedis("pw", FakeRedis.Role.MASTER);
        this.second = new FakeRedis("pw", FakeRedis.Role.REPLICA);
        this.sentinel.master(MASTER, "127.0.0.1", this.first.port());
    }

    @AfterEach
    void stop() throws IOException {
        this.sentinel.close();
        this.first.close();
        this.second.close();
    }

    private RedisClient client(List<String> sentinels, String sentinelPassword) {
        return new RedisClient(RedisConfig.builder("redis://:pw@redis.example:6379").profile(DeploymentProfile.DEVELOPMENT)
                .poolSize(2).commandTimeout(Duration.ofSeconds(3)).sentinel(MASTER, sentinels, sentinelPassword).build());
    }

    private String at(FakeRedis server) {
        return "127.0.0.1:" + server.port();
    }

    /** The sentinel moves the master to {@code second}, and {@code first} becomes its replica. */
    private void failover() {
        this.first.role(FakeRedis.Role.REPLICA);
        this.second.role(FakeRedis.Role.MASTER);
        this.sentinel.master(MASTER, "127.0.0.1", this.second.port());
    }

    @Test
    void theMasterIsWhereTheSentinelSaysAndSaysItIsTheMaster() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.sentinel());
            assertTrue(client.setIfAbsent("k", "v", Duration.ofMinutes(1)));
            assertEquals("v", this.first.value("k"));
            assertEquals(List.of("AUTH sentinel-pw", "SENTINEL get-master-addr-by-name " + MASTER), this.sentinel.commands());
            assertEquals(List.of("AUTH pw", "ROLE", "SET k v NX PX 60000"), this.first.commands());
            assertTrue(client.ping());
            assertEquals(1, this.sentinel.accepted(), "the answer is remembered while the master holds");
        }
    }

    @Test
    void aReadOnlyReplyIsAFailoverAndTheCommandGoesToTheNewMaster() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.ping());
            this.failover();
            assertTrue(client.set("k", "v", Duration.ofMinutes(1)), "READONLY from the old master; retried on the new one");
            assertEquals("v", this.second.value("k"));
            assertEquals(2, this.sentinel.accepted(), "the sentinel was asked again");
            assertTrue(client.set("k", "w", Duration.ofMinutes(1)));
            assertEquals(1, this.second.accepted(), "and the new master's connection is pooled");
        }
    }

    @Test
    void aLostConnectionIsAFailoverToo() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.ping());
            this.failover();
            this.first.close();
            assertTrue(client.ping(), "the old master is gone; the sentinel named the new one");
            assertTrue(this.second.commands().contains("ROLE"));
        }
    }

    @Test
    void theFirstConnectionFailingIsRetriedWhereTheSentinelNowPoints() throws IOException {
        int dead;
        try (ServerSocket gone = new ServerSocket(0)) {
            dead = gone.getLocalPort();
        }
        this.sentinel.master(MASTER, "127.0.0.1", dead);
        this.second.role(FakeRedis.Role.MASTER);
        this.sentinel.master(MASTER, "127.0.0.1", this.second.port());
        this.sentinel.masterOnce(MASTER, "127.0.0.1", dead);
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.ping(), "the sentinel's first answer was a master that had died; the retry asked again");
            assertEquals(2, this.sentinel.accepted());
            this.sentinel.masterOnce(MASTER, "127.0.0.1", dead);
            this.second.close();
            assertThrows(IOException.class, client::ping, "both masters gone: the retry fails too");
        }
    }

    @Test
    void aServerThatIsNotTheMasterIsRefused() throws IOException {
        this.sentinel.master(MASTER, "127.0.0.1", this.second.port());
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            IOException e = assertThrows(IOException.class, client::ping);
            assertTrue(e.getMessage().contains("ROLE says slave"), e.getMessage());
            assertFalse(this.second.commands().contains("PING"), "nothing was sent to a replica");
        }
        IOException odd = assertThrows(IOException.class, () -> RedisClient.requireMaster("master"));
        assertTrue(odd.getMessage().contains("ROLE says master"), odd.getMessage());
        assertThrows(IOException.class, () -> RedisClient.requireMaster(List.of()));
        RedisClient.requireMaster(List.of("master", 0L, List.of()));
    }

    @Test
    void theSentinelsAreAskedInOrderUntilOneNamesTheMaster() throws IOException {
        int dead;
        try (ServerSocket gone = new ServerSocket(0)) {
            dead = gone.getLocalPort();
        }
        try (FakeRedis ignorant = new FakeRedis("sentinel-pw", FakeRedis.Role.SENTINEL);
             RedisClient client = this.client(List.of("127.0.0.1:" + dead, this.at(ignorant), this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.ping(), "the first is down, the second knows no such master, the third answers");
            assertEquals(1, ignorant.accepted());
        }
    }

    @Test
    void aSentinelThatNeverAnswersCostsOnlyItsShareOfTheDeadline() throws IOException {
        try (FakeRedis hung = new FakeRedis(null, FakeRedis.Role.SENTINEL);
             RedisClient client = this.client(List.of(this.at(hung), this.at(this.sentinel)), "sentinel-pw")) {
            hung.silent(true);
            long start = System.nanoTime();
            assertTrue(client.ping(), "the first sentinel accepts and says nothing; the second names the master");
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue(took >= 1000L && took < 2500L, "half of the 3000 ms deadline went to the first, took " + took + " ms");
            assertEquals(1, hung.accepted());

            client.locator.lost(client.locator.generation());
            start = System.nanoTime();
            assertTrue(client.ping());
            assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 1000L, "the sentinel that answered is asked first");
            assertEquals(1, hung.accepted(), "and the silent one is not asked again");
            assertEquals(2, this.sentinel.accepted());
        }
        assertEquals(1_500L, MasterLocator.Sentinel.share(0L, 3_000L, 2));
        assertEquals(3_000L, MasterLocator.Sentinel.share(0L, 3_000L, 1));
        assertEquals(1_100L, MasterLocator.Sentinel.share(100L, 3_100L, 3));
    }

    @Test
    void theSentinelsAllSilentIsAnOutageWithinTheDeadline() throws IOException {
        try (FakeRedis hung = new FakeRedis(null, FakeRedis.Role.SENTINEL);
             RedisClient client = new RedisClient(RedisConfig.builder("redis://:pw@redis.example:6379")
                     .profile(DeploymentProfile.DEVELOPMENT).commandTimeout(Duration.ofMillis(600))
                     .sentinel(MASTER, List.of(this.at(hung), this.at(hung)), null).build())) {
            hung.silent(true);
            long start = System.nanoTime();
            IOException e = assertThrows(IOException.class, client::ping);
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue(took >= 500L && took < 2000L, "took " + took + " ms");
            assertTrue(e.getMessage().contains("no sentinel named the master " + MASTER), e.getMessage());
        }
    }

    @Test
    void aCommandWaitingOnAnotherThreadsLookupWaitsOnlyItsOwnDeadline() throws Exception {
        try (FakeRedis hung = new FakeRedis(null, FakeRedis.Role.SENTINEL)) {
            hung.silent(true);
            RedisConfig config = RedisConfig.builder("redis://redis.example").profile(DeploymentProfile.DEVELOPMENT)
                    .sentinel(MASTER, List.of(this.at(hung)), null).build();
            MasterLocator located = MasterLocator.sentinel(RedisUrl.parse("redis://redis.example"), config, null);
            Thread asking = new Thread(() -> {
                try {
                    located.master(System.nanoTime() + 3_000_000_000L);
                } catch (IOException expected) {
                    // the silent sentinel's deadline passes
                }
            });
            asking.start();
            Thread.sleep(200L);
            long start = System.nanoTime();
            IOException e = assertThrows(IOException.class, () -> located.master(System.nanoTime() + 300_000_000L));
            long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
            assertTrue(took >= 250L && took < 1500L, "took " + took + " ms");
            assertTrue(e.getMessage().contains("while the sentinels were being asked"), e.getMessage());
            hung.silent(false);
            asking.join(5000L);
        }

        // A waiter with time enough takes the answer the other thread found, and asks no sentinel itself.
        this.sentinel.delay(300L);
        MasterLocator located = MasterLocator.sentinel(RedisUrl.parse("redis://redis.example"), RedisConfig
                .builder("redis://redis.example").profile(DeploymentProfile.DEVELOPMENT)
                .sentinel(MASTER, List.of(this.at(this.sentinel)), "sentinel-pw").build(), null);
        MasterLocator.Endpoint[] found = new MasterLocator.Endpoint[1];
        Thread asking = new Thread(() -> {
            try {
                found[0] = located.master(System.nanoTime() + 3_000_000_000L);
            } catch (IOException e) {
                throw new IllegalStateException(e);
            }
        });
        asking.start();
        Thread.sleep(100L);
        MasterLocator.Endpoint waited = located.master(System.nanoTime() + 3_000_000_000L);
        asking.join(5000L);
        assertEquals(found[0], waited);
        assertEquals(1, this.sentinel.accepted(), "one lookup for both");
        this.sentinel.delay(0L);

        // A deadline already gone asks no sentinel.
        located.lost(located.generation());
        SocketTimeoutException gone = assertThrows(SocketTimeoutException.class, () -> located.master(System.nanoTime() - 1L));
        assertTrue(gone.getMessage().contains("before a sentinel could be asked"), gone.getMessage());
        assertEquals(1, this.sentinel.accepted());

        // Interrupted while waiting: the command fails as interrupted, and the flag stays set.
        located.lost(located.generation());
        Thread.currentThread().interrupt();
        try {
            assertThrows(InterruptedIOException.class, () -> located.master(System.nanoTime() + 3_000_000_000L));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void anIdleConnectionToALostMasterIsNotReused() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.ping());
            assertEquals(1, this.first.accepted());
            client.locator.lost(0L);
            assertTrue(client.ping(), "a loss another command reported, with a connection to the old master idle");
            assertEquals(2, this.first.accepted(), "the idle connection of the old generation was closed, not reused");
            assertEquals(2, this.sentinel.accepted());
        }
    }

    @Test
    void aFreshConnectionLostAfterTheCommandWasSentIsNotRetried() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            this.first.dropNextCommandNamed("INCR");
            assertThrows(IOException.class, () -> client.incr("n"), "the INCR may have run: an outage, not a second INCR");
            assertEquals(1L, this.first.commands().stream().filter("INCR n"::equals).count());
            assertEquals(1L, client.incr("n"), "the next command finds the master again");
            assertEquals(2, this.sentinel.accepted());
        }
    }

    @Test
    void noSentinelNamingTheMasterIsAnOutageThatSaysWhy() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "wrong")) {
            IOException e = assertThrows(IOException.class, client::ping);
            assertTrue(e.getMessage().contains("no sentinel named the master " + MASTER) && e.getMessage().contains("WRONGPASS"),
                    e.getMessage());
            assertFalse(e.getMessage().contains("wrong"), "the password is not in the message: " + e.getMessage());
        }
        this.sentinel.master(MASTER, null, 0);
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            IOException e = assertThrows(IOException.class, client::ping);
            assertTrue(e.getMessage().contains("does not know a master named " + MASTER), e.getMessage());
        }
        for (List<String> odd : List.of(List.of("127.0.0.1"), List.of("127.0.0.1", "port"), List.of("127.0.0.1", "0"))) {
            this.sentinel.masterReply(MASTER, odd);
            try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
                assertThrows(IOException.class, client::ping, odd.toString());
            }
        }
    }

    @Test
    void aSentinelWithNoPasswordIsSentNoAuth() throws IOException {
        try (FakeRedis open = new FakeRedis(null, FakeRedis.Role.SENTINEL)) {
            open.master(MASTER, "127.0.0.1", this.first.port());
            try (RedisClient client = this.client(List.of(this.at(open)), null)) {
                assertTrue(client.ping());
                assertEquals(List.of("SENTINEL get-master-addr-by-name " + MASTER), open.commands());
            }
        }
    }

    @Test
    void aConnectionInUseDuringAFailoverIsClosedWhenItComesBack() throws Exception {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertTrue(client.ping());
            this.first.delay(500L);
            Thread holder = new Thread(() -> {
                try {
                    client.ping();
                } catch (IOException e) {
                    throw new IllegalStateException(e);
                }
            });
            holder.start();
            Thread.sleep(150L);
            this.first.delay(0L);
            this.failover();
            assertTrue(client.set("k", "v", Duration.ofMinutes(1)), "the new connection met a replica, and the retry the master");
            holder.join(5000L);
            int before = this.second.accepted();
            assertTrue(client.ping());
            assertTrue(client.ping());
            assertEquals(before, this.second.accepted(), "the new master's connection is the one pooled");
            assertFalse(this.first.commands().subList(this.first.commands().size() - 1, this.first.commands().size()).contains("SET k v PX 60000"));
        }
    }

    @Test
    void aSentinelAnsweringNothingLikeAnAddressIsNotBelieved() throws IOException {
        try (FakeRedis open = new FakeRedis(null, FakeRedis.Role.SENTINEL)) {
            open.rawReplies("+nonsense\r\n", 2);
            try (RedisClient client = this.client(List.of(this.at(open)), null)) {
                IOException e = assertThrows(IOException.class, client::ping);
                assertTrue(e.getMessage().contains("something other than a host and a port"), e.getMessage());
            }
        }
    }

    @Test
    void anErrorReplyThatIsNotReadOnlyIsNotAFailover() throws IOException {
        try (RedisClient client = this.client(List.of(this.at(this.sentinel)), "sentinel-pw")) {
            assertThrows(RedisErrorReply.class, () -> client.call("NOSUCH"));
            assertTrue(client.ping());
            assertEquals(1, this.sentinel.accepted());
            this.failover();
            this.second.role(FakeRedis.Role.REPLICA);
            IOException twice = assertThrows(IOException.class, () -> client.set("k", "v", Duration.ofMinutes(1)));
            assertTrue(twice.getMessage().contains("ROLE says slave"), "the retry met a replica too, and wrote nothing to it");
        }
    }

    @Test
    void theLocatorsGenerations() throws IOException {
        MasterLocator direct = MasterLocator.direct(RedisUrl.parse("redis://h:1"));
        assertEquals(new MasterLocator.Endpoint("h", 1, "h", 0L), direct.master(0L));
        direct.lost(0L);
        assertEquals(0L, direct.generation());
        assertFalse(direct.sentinel());

        RedisConfig config = RedisConfig.builder("redis://redis.example").profile(DeploymentProfile.DEVELOPMENT)
                .sentinel(MASTER, List.of(this.at(this.sentinel)), "sentinel-pw").build();
        MasterLocator located = MasterLocator.sentinel(RedisUrl.parse("redis://redis.example"), config, null);
        long deadline = System.nanoTime() + 3_000_000_000L;
        MasterLocator.Endpoint master = located.master(deadline);
        assertEquals("redis.example", master.tlsName(), "an address is verified against the URL's host");
        assertEquals(0L, master.generation());
        located.lost(5L);
        assertEquals(master, located.master(deadline), "a loss reported for another generation changes nothing");
        this.sentinel.master(MASTER, "localhost", this.first.port());
        located.lost(0L);
        assertEquals(1L, located.generation(), "the loss starts a new generation at once");
        MasterLocator.Endpoint named = located.master(deadline);
        assertEquals("localhost", named.tlsName(), "a name is verified as itself");
        assertEquals(1L, named.generation());
        located.lost(1L);
        located.lost(1L);
        assertEquals(2L, located.generation(), "a second report of the same loss is the same loss");
    }
}
