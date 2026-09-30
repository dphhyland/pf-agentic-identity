/*
 * FederationPolicySupport's test hook, for tests outside its package - published in this module's test-jar.
 */
package com.pingidentity.ps.oidf.pf;

/**
 * {@link FederationPolicySupport#resetForTests()} for tests in other packages and modules (attestation-issuer's), which reach it
 * through this module's test-jar. The hook itself is package-private, so production code cannot forget the federation decision points
 * (plan item H-FED-10).
 */
public final class FederationPolicySupportTestAccess {

    private FederationPolicySupportTestAccess() {
    }

    /** Forgets the decision points built, so the next caller builds again. */
    public static void reset() {
        FederationPolicySupport.resetForTests();
    }
}
