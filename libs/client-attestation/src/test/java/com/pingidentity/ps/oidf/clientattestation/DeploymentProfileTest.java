package com.pingidentity.ps.oidf.clientattestation;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/** Everything but {@code development} is production - unset, a typo, and {@code production} itself. */
class DeploymentProfileTest {

    @Test
    void unsetIsProduction() {
        assertTrue(DeploymentProfile.isProduction(k -> null));
        assertTrue(DeploymentProfile.isProduction(k -> ""));
    }

    @Test
    void onlyDevelopmentIsNotProduction() {
        assertFalse(DeploymentProfile.isProduction(k -> "development"));
        assertFalse(DeploymentProfile.isProduction(k -> " Development "));
        assertTrue(DeploymentProfile.isProduction(k -> "production"));
        assertTrue(DeploymentProfile.isProduction(k -> "dev"));
        assertTrue(DeploymentProfile.isProduction(k -> "developement"));
    }
}
