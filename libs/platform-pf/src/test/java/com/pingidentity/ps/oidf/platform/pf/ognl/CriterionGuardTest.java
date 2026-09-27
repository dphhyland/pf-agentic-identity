/*
 * An OGNL criterion behind the guard answers true or false, and nothing it throws escapes.
 */
package com.pingidentity.ps.oidf.platform.pf.ognl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CriterionGuardTest {

    @Test
    void theBodysAnswerPassesThrough() {
        assertTrue(CriterionGuard.evaluate("permits", () -> true));
        assertFalse(CriterionGuard.evaluate("denies", () -> false));
    }

    @Test
    void anExceptionDenies() {
        assertFalse(CriterionGuard.evaluate("throws", () -> {
            throw new IllegalStateException("expected in this test");
        }));
    }

    /** A missing staged jar surfaces as a NoClassDefFoundError inside the body; it denies instead of escaping to OGNL. */
    @Test
    void anErrorDeniesToo() {
        assertFalse(CriterionGuard.evaluate("links", () -> {
            throw new NoClassDefFoundError("com/pingidentity/ps/oidf/platform/Missing (expected in this test)");
        }));
        assertFalse(CriterionGuard.evaluate("asserts", () -> {
            throw new AssertionError("expected in this test");
        }));
    }

    @Test
    void noBodyDeniesAndNoNameIsStillLogged() {
        assertFalse(CriterionGuard.evaluate("empty", null));
        assertFalse(CriterionGuard.evaluate(null, null));
        assertTrue(CriterionGuard.evaluate(null, () -> true));
    }

    /** An exception message can carry request-derived text; the log line gets it as one cleaned, bounded line. */
    @Test
    void theLoggedMessageIsOneCleanLine() {
        assertEquals("java.lang.IllegalStateException: bad client_id x??injected? line",
                CriterionGuard.describe(new IllegalStateException("bad client_id x\r\ninjected\u202e line")));
        assertEquals("java.lang.NullPointerException", CriterionGuard.describe(new NullPointerException()));
        assertEquals("a?b?c", CriterionGuard.oneLine("a\u2028b\u2029c"), "line and paragraph separators");
        assertEquals("x".repeat(CriterionGuard.MAX_TEXT), CriterionGuard.oneLine("x".repeat(1000)));
        String pairAtTheCut = "x".repeat(CriterionGuard.MAX_TEXT - 1) + "\ud83d\ude00";
        assertEquals("x".repeat(CriterionGuard.MAX_TEXT - 1), CriterionGuard.oneLine(pairAtTheCut), "never half a pair");
        String pairInside = "x".repeat(CriterionGuard.MAX_TEXT - 2) + "\ud83d\ude00";
        assertEquals(pairInside, CriterionGuard.oneLine(pairInside));
        assertFalse(CriterionGuard.evaluate("crlf\r\nname", () -> {
            throw new IllegalArgumentException("expected in this test\n2026-09-28 INFO forged line");
        }));
    }
}
