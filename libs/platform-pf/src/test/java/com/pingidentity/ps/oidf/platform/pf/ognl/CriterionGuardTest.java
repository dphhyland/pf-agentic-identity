/*
 * An OGNL criterion behind the guard answers true or false, and nothing it throws escapes.
 */
package com.pingidentity.ps.oidf.platform.pf.ognl;

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
}
