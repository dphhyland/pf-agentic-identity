/*
 * TrustMarkSupport's test hook, for tests outside its package - published in this module's test-jar.
 */
package com.pingidentity.ps.oidf.trustmark;

/**
 * {@link TrustMarkSupport#resetForTests()} for tests in other packages and modules (pf-integration's), which reach it through
 * this module's test-jar. The hook itself is package-private, so production code cannot forget the trust-mark registry (plan item
 * H-FED-10).
 */
public final class TrustMarkSupportTestAccess {

    private TrustMarkSupportTestAccess() {
    }

    /** Forgets the registry. */
    public static void reset() {
        TrustMarkSupport.resetForTests();
    }
}
