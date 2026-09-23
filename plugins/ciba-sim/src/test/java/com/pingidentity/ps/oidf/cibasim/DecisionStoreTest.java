/*
 * What a recorded decision reads back as, and when it stops.
 */
package com.pingidentity.ps.oidf.cibasim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.cibasim.DecisionStore.Decision;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DecisionStoreTest {

    private static final Instant T0 = Instant.parse("2026-09-24T00:00:00Z");

    private static final class SteppingClock extends Clock {
        Instant now = T0;

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
    }

    @Test
    void theTransactionIdIsTheHashOfTheAuthReqIdAndNeverTheIdItself() {
        String tx = DecisionStore.txIdFor("urn:auth-req:abc");
        assertTrue(tx.matches("[0-9a-f]{64}"));
        assertEquals(tx, DecisionStore.txIdFor("  urn:auth-req:abc "), "trimmed, so both sides derive the same id");
        assertFalse(tx.contains("abc"));
        assertThrows(IllegalArgumentException.class, () -> DecisionStore.txIdFor(" "));
        assertThrows(IllegalArgumentException.class, () -> DecisionStore.txIdFor(null));
    }

    @Test
    void absentAllowDenyAndOverwrite(@TempDir Path dir) throws Exception {
        DecisionStore store = new DecisionStore(dir.resolve("decisions"), Duration.ofMinutes(15), new SteppingClock());
        String tx = DecisionStore.txIdFor("req-1");

        assertEquals(Optional.empty(), store.lookup(tx), "nothing recorded");
        assertEquals(tx, store.record("req-1", Decision.ALLOW));
        assertEquals(Optional.of(Decision.ALLOW), store.lookup(tx));
        store.record("req-1", Decision.DENY);
        assertEquals(Optional.of(Decision.DENY), store.lookup(tx), "a later decision replaces the earlier");
        store.forget(tx);
        assertEquals(Optional.empty(), store.lookup(tx));
        assertFalse(Files.list(dir.resolve("decisions")).anyMatch(p -> p.getFileName().toString().endsWith(".tmp")),
                "the write is renamed into place, no temp file is left");
    }

    @Test
    void aDecisionOlderThanTheTtlReadsAsAbsentAndIsRemoved(@TempDir Path dir) throws Exception {
        SteppingClock clock = new SteppingClock();
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), clock);
        String tx = store.record("req-2", Decision.ALLOW);

        clock.now = T0.plus(Duration.ofMinutes(15));
        assertEquals(Optional.of(Decision.ALLOW), store.lookup(tx), "exactly the TTL is still inside it");
        clock.now = T0.plus(Duration.ofMinutes(15)).plusSeconds(1);
        assertEquals(Optional.empty(), store.lookup(tx));
        assertFalse(Files.exists(dir.resolve(tx)), "removed, not just hidden");
    }

    @Test
    void anUnreadableOrForeignFileIsAbsentNotAnError(@TempDir Path dir) throws Exception {
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), new SteppingClock());
        String tx = DecisionStore.txIdFor("req-3");
        Files.writeString(dir.resolve(tx), "maybe 12\n");
        assertEquals(Optional.empty(), store.lookup(tx), "an unknown verdict is no verdict");
        assertFalse(Files.exists(dir.resolve(tx)));

        Files.writeString(dir.resolve(tx), "allow notanumber\n");
        assertEquals(Optional.empty(), store.lookup(tx), "no readable timestamp = as old as the epoch = expired");
        Files.writeString(dir.resolve(tx), "allow\n");
        assertEquals(Optional.empty(), store.lookup(tx));
        assertFalse(Files.exists(dir.resolve(tx)));

        assertEquals(Optional.empty(), store.lookup("../../etc/passwd"), "only a hex transaction id names a file");
        assertEquals(Optional.empty(), store.lookup(null));
        assertEquals(Optional.empty(), store.lookup("  "));
        store.forget("../../etc/passwd");
        store.forget(null);
    }

    @Test
    void directoryComesFromTheEnvironmentOrTheTempDir() {
        assertEquals(Path.of("/var/x"), DecisionStore.fromEnvironment(k -> "/var/x ").dir());
        assertEquals(Path.of(System.getProperty("java.io.tmpdir"), "oidf-ciba-sim"), DecisionStore.fromEnvironment(k -> null).dir());
        assertEquals(Path.of(System.getProperty("java.io.tmpdir"), "oidf-ciba-sim"), DecisionStore.fromEnvironment(k -> " ").dir());
    }

    @Test
    void recordRefusesANullDecision(@TempDir Path dir) {
        DecisionStore store = new DecisionStore(dir, Duration.ofMinutes(15), new SteppingClock());
        assertThrows(IllegalArgumentException.class, () -> store.record("req", null));
    }

    @Test
    void actionsParseLooselyButOnlyToTheTwoWords() {
        assertEquals(Decision.ALLOW, Decision.parse(" Allow "));
        assertEquals(Decision.DENY, Decision.parse("deny"));
        assertNull(Decision.parse("approve"));
        assertNull(Decision.parse(null));
    }
}
