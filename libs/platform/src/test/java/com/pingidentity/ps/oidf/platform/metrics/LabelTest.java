/*
 * A label is a name and a bound; a metric keeps its values within it.
 */
package com.pingidentity.ps.oidf.platform.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class LabelTest {

    @Test
    void aDeclaredLabelKeepsItsValuesAndOther() {
        Label l = Label.oneOf("outcome", "refused", "accepted", "accepted");
        assertTrue(l.isDeclared());
        assertEquals(Set.of("accepted", "refused"), l.declared());
        assertEquals(0, l.cap());
        assertEquals(3, l.maxValues(), "two values and other");
        assertEquals("outcome [accepted, refused]", l.toString());
        Family.Slot slot = new Family.Slot(l);
        assertEquals("refused", slot.admit("refused"));
        assertEquals("other", slot.admit("other"));
        assertNull(slot.admit("maybe"));
    }

    @Test
    void aCappedLabelKeepsTheFirstValuesAndFoldsTheRest() {
        Label l = Label.capped("client", 2);
        assertFalse(l.isDeclared());
        assertEquals(Set.of(), l.declared());
        assertEquals(2, l.cap());
        assertEquals(3, l.maxValues());
        assertEquals("client (capped at 2)", l.toString());
        Family.Slot slot = new Family.Slot(l);
        assertEquals("a", slot.admit("a"));
        assertEquals("a", slot.admit("a"), "a kept value stays kept");
        assertEquals("b", slot.admit("b"));
        assertNull(slot.admit("c"), "past the cap");
        assertNull(slot.admit("d"), "and every new value after it");
        assertEquals("b", slot.admit("b"));
        assertEquals("other", slot.admit("other"), "other takes no place and is always kept");
    }

    @Test
    void valuesNoLabelKeepsAreFolded() {
        Family.Slot slot = new Family.Slot(Label.capped("host", 10));
        assertNull(slot.admit(null));
        assertNull(slot.admit(""));
        assertNull(slot.admit("x".repeat(Label.MAX_VALUE_LENGTH + 1)));
        assertEquals("x".repeat(Label.MAX_VALUE_LENGTH), slot.admit("x".repeat(Label.MAX_VALUE_LENGTH)));
        assertNull(slot.admit("line\nbreak"));
        assertNull(slot.admit("tab\t"));
        assertEquals("café \"quoted\" \\", slot.admit("café \"quoted\" \\"), "quotes and backslashes are escaped when rendered, not refused");
    }

    @Test
    void theCapHoldsWhenManyThreadsAdmitAtOnce() throws Exception {
        Family.Slot slot = new Family.Slot(Label.capped("client", 50));
        List<Thread> threads = new java.util.ArrayList<>();
        java.util.Set<String> kept = java.util.concurrent.ConcurrentHashMap.newKeySet();
        for (int t = 0; t < 8; t++) {
            int base = t;
            threads.add(new Thread(() -> {
                for (int i = 0; i < 1000; i++) {
                    String v = slot.admit("c" + (base * 1000 + i));
                    if (v != null) {
                        kept.add(v);
                    }
                }
            }));
        }
        threads.forEach(Thread::start);
        for (Thread t : threads) {
            t.join();
        }
        assertEquals(50, kept.size());
    }

    /** Another thread admits the same new value while this one waits for the lock: it is kept, not folded. */
    @Test
    void aValueAdmittedWhileWaitingForTheLockIsKept() throws Exception {
        Family.Slot slot = new Family.Slot(Label.capped("client", 1));
        String[] got = new String[1];
        Thread waiter = new Thread(() -> got[0] = slot.admit("x"));
        synchronized (slot) {
            waiter.start();
            while (waiter.getState() != Thread.State.BLOCKED) {
                Thread.onSpinWait();
            }
            slot.seen.add("x");
        }
        waiter.join();
        assertEquals("x", got[0]);
        assertNull(slot.admit("y"), "and the cap of one is spent");
    }

    @Test
    void badLabelsAreRefused() {
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf(null, "a"));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("Outcome", "a"));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("1st", "a"));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("le", "a"), "a timer's bucket label");
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("quantile", "a"));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("a".repeat(65), "a"));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("outcome"));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("outcome", List.of()));
        assertThrows(NullPointerException.class, () -> Label.oneOf("outcome", (String[]) null));
        assertThrows(NullPointerException.class, () -> Label.oneOf("outcome", (List<String>) null));
        List<String> many = new java.util.ArrayList<>();
        for (int i = 0; i <= Label.MAX_VALUES; i++) {
            many.add("v" + i);
        }
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("outcome", many));
        assertEquals(Label.MAX_VALUES, Label.oneOf("outcome", many.subList(0, Label.MAX_VALUES)).declared().size());
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("outcome", "ok", null));
        assertThrows(IllegalArgumentException.class, () -> Label.oneOf("outcome", "ok", "bad\n"));
        assertThrows(IllegalArgumentException.class, () -> Label.capped("client", 0));
        assertThrows(IllegalArgumentException.class, () -> Label.capped("client", Label.MAX_VALUES + 1));
        assertThrows(IllegalArgumentException.class, () -> Label.capped("Client", 1));
        assertEquals(Label.MAX_VALUES, Label.capped("client", Label.MAX_VALUES).cap());
    }

    @Test
    void labelsAreEqualWhenTheirNameAndBoundAre() {
        assertEquals(Label.oneOf("o", "a", "b"), Label.oneOf("o", "b", "a"));
        assertEquals(Label.oneOf("o", "a", "b").hashCode(), Label.oneOf("o", "b", "a").hashCode());
        assertEquals(Label.capped("c", 3), Label.capped("c", 3));
        assertNotEquals(Label.capped("c", 3), Label.capped("c", 4));
        assertNotEquals(Label.capped("c", 3), Label.capped("d", 3));
        assertNotEquals(Label.oneOf("o", "a"), Label.oneOf("o", "b"));
        assertNotEquals(Label.oneOf("o", "a"), Label.capped("o", 1));
        assertNotEquals(Label.oneOf("o", "a"), "o");
    }
}
