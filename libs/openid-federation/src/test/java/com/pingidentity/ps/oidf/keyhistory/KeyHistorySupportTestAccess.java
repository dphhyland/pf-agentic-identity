/*
 * KeyHistorySupport's test hook, for tests outside its package - published in this module's test-jar.
 */
package com.pingidentity.ps.oidf.keyhistory;

/**
 * {@link KeyHistorySupport#resetForTests()} for tests in other packages and modules (pf-integration's), which reach it through
 * this module's test-jar. The hook itself is package-private, so production code cannot forget the key-history store (plan item
 * H-FED-10).
 */
public final class KeyHistorySupportTestAccess {

    private KeyHistorySupportTestAccess() {
    }

    /** Forgets the store. */
    public static void reset() {
        KeyHistorySupport.resetForTests();
    }
}
