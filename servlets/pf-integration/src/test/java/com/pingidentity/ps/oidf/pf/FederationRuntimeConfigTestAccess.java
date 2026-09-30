/*
 * FederationRuntimeConfig's test hook, for tests outside its package - published in this module's test-jar.
 */
package com.pingidentity.ps.oidf.pf;

/**
 * {@link FederationRuntimeConfig#resetForTests()} for tests in other packages and modules (attestation-issuer's), which reach it
 * through this module's test-jar. The hook itself is package-private, so production code cannot forget the process-wide federation configuration
 * (plan item H-FED-10).
 */
public final class FederationRuntimeConfigTestAccess {

    private FederationRuntimeConfigTestAccess() {
    }

    /** Forgets the resolved configuration, so the next {@link FederationRuntimeConfig#get()} resolves again. */
    public static void reset() {
        FederationRuntimeConfig.resetForTests();
    }
}
