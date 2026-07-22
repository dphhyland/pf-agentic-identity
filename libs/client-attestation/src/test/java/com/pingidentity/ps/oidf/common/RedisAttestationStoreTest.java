package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class RedisAttestationStoreTest {

    private FakeRedisServer redis;
    private RedisAttestationStore store;

    @BeforeEach
    void start() throws Exception {
        redis = new FakeRedisServer("s3cr3t");
        store = new RedisAttestationStore(redis.url(), 300L);
    }

    @AfterEach
    void stop() throws Exception {
        store.close();
        redis.close();
    }

    @Test
    void issuedChallengeCanBeConsumedOnce() {
        String challenge = store.issue();
        assertNotNull(challenge);
        assertTrue(store.consume(challenge));
        assertFalse(store.consume(challenge), "challenge must be single-use");
    }

    @Test
    void unknownChallengeRejected() {
        assertFalse(store.consume("not-a-real-challenge"));
        assertFalse(store.consume(null));
        assertFalse(store.consume(""));
    }

    @Test
    void challengesAreUnique() {
        assertNotEquals(store.issue(), store.issue());
    }

    @Test
    void expiredChallengeRejected() throws Exception {
        try (RedisAttestationStore shortTtl = new RedisAttestationStore(redis.url(), 1L)) {
            String challenge = shortTtl.issue();
            Thread.sleep(1100L);
            assertFalse(shortTtl.consume(challenge), "challenge must expire after its TTL");
        }
    }

    @Test
    void secondStoreSeesChallengesFromFirst() throws Exception {
        // Two store instances (≈ two cluster nodes / two classloaders) sharing one Redis.
        try (RedisAttestationStore other = new RedisAttestationStore(redis.url(), 300L)) {
            String challenge = store.issue();
            assertTrue(other.consume(challenge), "challenge must be visible across store instances");
            assertFalse(store.consume(challenge), "consumption must be visible across store instances");
        }
    }

    @Test
    void firstUseAcceptedReplayRejected() {
        assertTrue(store.firstSeen("client-a", "jti-1", 300L));
        assertFalse(store.firstSeen("client-a", "jti-1", 300L));
    }

    @Test
    void differentJtiAndClientAreIndependent() {
        assertTrue(store.firstSeen("client-a", "jti-1", 300L));
        assertTrue(store.firstSeen("client-a", "jti-2", 300L));
        assertTrue(store.firstSeen("client-b", "jti-1", 300L));
    }

    @Test
    void blankJtiRejected() {
        assertThrows(IllegalArgumentException.class, () -> store.firstSeen("client-a", "  ", 300L));
    }

    @Test
    void wrongPasswordFailsClosed() throws Exception {
        try (RedisAttestationStore bad = new RedisAttestationStore(
                "redis://default:wrong@127.0.0.1:" + redis.port(), 300L)) {
            assertThrows(IllegalStateException.class, bad::issue);
            assertFalse(bad.consume("anything"), "auth failure must fail closed");
            assertFalse(bad.firstSeen("client-a", "jti-1", 300L), "auth failure must fail closed");
        }
    }

    @Test
    void redisDownFailsClosed() throws Exception {
        String challenge = store.issue();
        redis.close();
        assertFalse(store.consume(challenge), "Redis outage must fail closed, not open");
        assertFalse(store.firstSeen("client-a", "jti-9", 300L), "Redis outage must fail closed, not open");
        assertThrows(IllegalStateException.class, store::issue);
    }

    @Test
    void survivesStaleConnections() throws Exception {
        // Consume on a fresh connection, then use the (pooled, possibly stale) connection again.
        String c1 = store.issue();
        assertTrue(store.consume(c1));
        String c2 = store.issue();
        assertTrue(store.consume(c2));
    }
}
