package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * The statement cache directly: what a read evicts (too close to expiry, too old since issue), how the
 * size bound evicts, and the staged writes a chain walk commits only when the whole chain validated.
 */
class SubordinateStatementCacheTest {
    private static final String ISS = "https://ta.example";
    private static final String SUB = "https://leaf.example";

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    @Test
    void aFreshEntryIsServed() {
        SubordinateStatementCache cache = new SubordinateStatementCache();
        cache.put(ISS, SUB, "jwt-1", now() + 3600);

        assertEquals("jwt-1", cache.get(ISS, SUB, 300));
        assertEquals(1, cache.size());
        assertNull(cache.get(ISS, "https://other.example", 300));
    }

    @Test
    void anEntryInsideTheExpiryBufferIsEvictedOnRead() {
        SubordinateStatementCache cache = new SubordinateStatementCache();
        cache.put(ISS, SUB, "jwt-1", now() + 200);

        assertNull(cache.get(ISS, SUB, 300), "200 s left is inside a 300 s buffer");
        assertEquals(0, cache.size(), "the read evicts it");
    }

    @Test
    void anEntryOlderThanTheMaxAgeIsEvictedOnRead() {
        SubordinateStatementCache cache = new SubordinateStatementCache();
        cache.put(ISS, SUB, "jwt-1", now() + 3600, now() - 120);

        assertEquals("jwt-1", cache.get(ISS, SUB, 300, 600), "120 s old is within a 600 s bound");
        assertEquals("jwt-1", cache.get(ISS, SUB, 300, -1), "no bound");
        assertNull(cache.get(ISS, SUB, 300, 60), "120 s old is past a 60 s bound");
        assertEquals(0, cache.size());

        cache.put(ISS, SUB, "jwt-2", now() + 3600, 0L);
        assertEquals("jwt-2", cache.get(ISS, SUB, 300, 1), "an entry with no iat cannot be judged by age");
    }

    /** Age and expiry are judged by the cache's own clock, so a test (or a caller) can move time without waiting. */
    @Test
    void entriesAgeAgainstTheCachesClock() {
        com.pingidentity.ps.oidf.federation.testkit.MutableClock clock = com.pingidentity.ps.oidf.federation.testkit.MutableClock.startingNow();
        SubordinateStatementCache cache = new SubordinateStatementCache(8, clock);
        cache.put(ISS, SUB, "jwt-1", clock.epochSecond() + 3600, clock.epochSecond());

        assertEquals("jwt-1", cache.get(ISS, SUB, 300, 600));
        clock.advance(java.time.Duration.ofSeconds(601));
        assertNull(cache.get(ISS, SUB, 300, 600), "601 s later it is past the 600 s bound");

        cache.put(ISS, SUB, "jwt-2", clock.epochSecond() + 400, clock.epochSecond());
        clock.advance(java.time.Duration.ofSeconds(101));
        assertNull(cache.get(ISS, SUB, 300), "299 s left is inside the 300 s buffer");
        assertThrows(NullPointerException.class, () -> new SubordinateStatementCache(8, null));
    }

    @Test
    void theSizeBoundEvictsTheLeastRecentlyUsed() {
        SubordinateStatementCache cache = new SubordinateStatementCache(2);
        cache.put(ISS, "https://a.example", "a", now() + 3600);
        cache.put(ISS, "https://b.example", "b", now() + 3600);
        cache.get(ISS, "https://a.example", 300);
        cache.put(ISS, "https://c.example", "c", now() + 3600);

        assertEquals(2, cache.size());
        assertEquals("a", cache.get(ISS, "https://a.example", 300));
        assertNull(cache.get(ISS, "https://b.example", 300), "b was least recently used");

        SubordinateStatementCache unbounded = new SubordinateStatementCache(SubordinateStatementCache.UNBOUNDED);
        for (int i = 0; i < 300; i++) {
            unbounded.put(ISS, "https://e" + i + ".example", "x", now() + 3600);
        }
        assertEquals(300, unbounded.size());
        assertThrows(IllegalArgumentException.class, () -> new SubordinateStatementCache(0));
    }

    @Test
    void anExplicitEvictionRemovesOnlyThatEntry() {
        SubordinateStatementCache cache = new SubordinateStatementCache();
        cache.put(ISS, SUB, "jwt-1", now() + 3600);
        cache.evict(ISS, "https://absent.example");
        assertEquals(1, cache.size());
        cache.evict(ISS, SUB);
        assertEquals(0, cache.size());
    }

    @Test
    void stagedWritesAreVisibleToTheWalkButReachTheCacheOnlyOnCommit() {
        SubordinateStatementCache cache = new SubordinateStatementCache();
        SubordinateStatementCache.PendingWrites pending = cache.newPendingWrites();
        pending.stagePut(ISS, SUB, "older", now() + 3600, now());
        pending.stagePut(ISS, SUB, "newer", now() + 3600, now());

        assertEquals("newer", pending.find(ISS, SUB), "the newest staged copy wins");
        assertNull(pending.find(ISS, "https://other.example"));
        assertEquals(2, pending.stagedCount());
        assertNull(cache.get(ISS, SUB, 300), "nothing is shared before commit");

        pending.commit();
        assertEquals("newer", cache.get(ISS, SUB, 300));
        assertEquals(0, pending.stagedCount());
        pending.commit();
    }

    @Test
    void discardedWritesNeverReachTheCache() {
        SubordinateStatementCache cache = new SubordinateStatementCache();
        SubordinateStatementCache.PendingWrites pending = cache.newPendingWrites();
        pending.stagePut(ISS, SUB, "jwt", now() + 3600, now());
        pending.discard();
        pending.commit();
        assertEquals(0, cache.size());
        pending.discard();
    }

    @Test
    void disabledPendingWritesStageNothing() {
        SubordinateStatementCache.PendingWrites disabled = SubordinateStatementCache.disabledPendingWrites();
        disabled.stagePut(ISS, SUB, "jwt", now() + 3600, now());
        assertEquals(0, disabled.stagedCount());
        assertNull(disabled.find(ISS, SUB));
        disabled.commit();
        assertThrows(NullPointerException.class, () -> new SubordinateStatementCache().newPendingWrites().stagePut(null, SUB, "j", 1, 1));
        assertThrows(NullPointerException.class, () -> new SubordinateStatementCache().put(null, SUB, "j", 1));
    }
}
