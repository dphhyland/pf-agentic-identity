/*
 * AuthoritySupport's test hook, for tests outside its package - published in this module's test-jar.
 */
package com.pingidentity.ps.oidf.authority;

/**
 * {@link AuthoritySupport#resetForTests()} for tests in other packages and modules (pf-integration's), which reach it through
 * this module's test-jar. The hook itself is package-private, so production code cannot forget the hosted-entity authority (plan item
 * H-FED-10).
 */
public final class AuthoritySupportTestAccess {

    private AuthoritySupportTestAccess() {
    }

    /** Forgets every configuration, so a test can see the unconfigured state. */
    public static void reset() {
        AuthoritySupport.resetForTests();
    }
}
