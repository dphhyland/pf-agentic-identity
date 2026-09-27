package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.EvidenceBindingStore.Binding;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

/** The per-node binding store: the same outcomes as Redis's SET NX then GET, under one lock. */
class InMemoryEvidenceBindingStoreTest {
    private static final Instant T0 = Instant.parse("2026-09-27T00:00:00Z");

    private static InMemoryEvidenceBindingStore at(Instant now) {
        return new InMemoryEvidenceBindingStore(8, Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    void theFirstPresenterWinsAndMayReturn() {
        InMemoryEvidenceBindingStore store = at(T0);
        long exp = T0.plusSeconds(600).getEpochSecond();
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", exp));
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", exp));
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-2", "c", exp));
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-1", "other", exp));
        assertEquals(Binding.BOUND, store.bind("sha-2", "jkt-2", "c", exp), "other evidence is its own binding");
        assertEquals(2, store.size());
    }

    @Test
    void aBindingExpiresWithItsEvidence() {
        MutableClock clock = new MutableClock(T0);
        InMemoryEvidenceBindingStore store = new InMemoryEvidenceBindingStore(8, clock);
        long exp = T0.plusSeconds(60).getEpochSecond();
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", exp));
        clock.now = T0.plusSeconds(59);
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-2", "c", exp));
        clock.now = T0.plusSeconds(60);
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-2", "c", exp + 600),
                "at the evidence's exp the binding is gone with it");
    }

    @Test
    void alreadyExpiredEvidenceIsHeldForASecondNotForever() {
        MutableClock clock = new MutableClock(T0);
        InMemoryEvidenceBindingStore store = new InMemoryEvidenceBindingStore(8, clock);
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-1", "c", T0.minusSeconds(5).getEpochSecond()));
        assertEquals(Binding.CONFLICT, store.bind("sha-1", "jkt-2", "c", T0.plusSeconds(600).getEpochSecond()));
        clock.now = T0.plusSeconds(1);
        assertEquals(Binding.BOUND, store.bind("sha-1", "jkt-2", "c", T0.plusSeconds(600).getEpochSecond()));
    }

    @Test
    void theStoreIsBounded() {
        InMemoryEvidenceBindingStore store = new InMemoryEvidenceBindingStore(2, Clock.fixed(T0, ZoneOffset.UTC));
        long exp = T0.plusSeconds(600).getEpochSecond();
        store.bind("a", "k", "c", exp);
        store.bind("b", "k", "c", exp);
        store.bind("c", "k", "c", exp);
        assertTrue(store.size() <= 2);
        assertThrows(IllegalArgumentException.class, () -> new InMemoryEvidenceBindingStore(0, Clock.systemUTC()));
        assertEquals(EvidenceBindingStore.DEFAULT_MAX_ENTRIES, 8192);
        assertEquals(0, new InMemoryEvidenceBindingStore().size());
    }

    @Test
    void aDigestAndAKeyAreRequiredAndANullClientIsTheEmptyClient() {
        InMemoryEvidenceBindingStore store = at(T0);
        long exp = T0.plusSeconds(600).getEpochSecond();
        assertThrows(IllegalArgumentException.class, () -> store.bind(null, "k", "c", exp));
        assertThrows(IllegalArgumentException.class, () -> store.bind(" ", "k", "c", exp));
        assertThrows(IllegalArgumentException.class, () -> store.bind("sha", null, "c", exp));
        assertThrows(IllegalArgumentException.class, () -> store.bind("sha", " ", "c", exp));
        assertEquals(Binding.BOUND, store.bind("sha", "k", null, exp));
        assertEquals(Binding.BOUND, store.bind("sha", "k", null, exp));
        assertEquals(Binding.CONFLICT, store.bind("sha", "k", "c", exp));
    }

    private static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneOffset getZone() {
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

        @Override
        public long millis() {
            return this.now.toEpochMilli();
        }
    }
}
