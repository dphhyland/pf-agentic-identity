/*
 * The SSF shared state's test hook, for tests outside its package.
 */
package com.pingidentity.ps.oidf.ssf;

/** {@link SsfSupport#resetForTests()} for the servlet layer's tests, which live in another package. */
public final class SsfSupportTestAccess {

    private SsfSupportTestAccess() {
    }

    /** Stops the loops and forgets the published state. */
    public static void reset() {
        SsfSupport.resetForTests();
    }
}
