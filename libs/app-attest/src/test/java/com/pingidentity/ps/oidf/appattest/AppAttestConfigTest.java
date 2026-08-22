package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.EnumSet;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * The construction-time validation on {@link AppAttestConfig} — blank identifiers, an empty accepted
 * set — and the production/development split that is this module's central security control.
 */
class AppAttestConfigTest {

    @Test
    void productionAcceptsOnlyProduction() {
        AppAttestConfig config = AppAttestConfig.production("TEAMID1234", "com.example.app");
        assertTrue(config.accepts(AppAttestEnvironment.PRODUCTION));
        assertFalse(config.accepts(AppAttestEnvironment.DEVELOPMENT));
        assertEquals(Set.of(AppAttestEnvironment.PRODUCTION), config.acceptedEnvironments());
    }

    @Test
    void allowingDevelopmentAcceptsBothEnvironments() {
        AppAttestConfig config = AppAttestConfig.allowingDevelopment("TEAMID1234", "com.example.app");
        assertTrue(config.accepts(AppAttestEnvironment.PRODUCTION));
        assertTrue(config.accepts(AppAttestEnvironment.DEVELOPMENT));
    }

    @Test
    void appIdIsTeamIdDotBundleId() {
        AppAttestConfig config = AppAttestConfig.production("TEAMID1234", "com.example.app");
        assertEquals("TEAMID1234.com.example.app", config.appId());
        assertEquals("TEAMID1234", config.teamId());
        assertEquals("com.example.app", config.bundleId());
    }

    @Test
    void acceptsReturnsFalseForNull() {
        AppAttestConfig config = AppAttestConfig.production("TEAMID1234", "com.example.app");
        assertFalse(config.accepts(null));
    }

    @Test
    void rejectsABlankTeamId() {
        assertThrows(IllegalArgumentException.class, () -> AppAttestConfig.production("  ", "com.example.app"));
        assertThrows(IllegalArgumentException.class, () -> AppAttestConfig.production(null, "com.example.app"));
    }

    @Test
    void rejectsABlankBundleId() {
        assertThrows(IllegalArgumentException.class, () -> AppAttestConfig.production("TEAMID1234", " "));
        assertThrows(IllegalArgumentException.class, () -> AppAttestConfig.production("TEAMID1234", null));
    }

    @Test
    void rejectsAnEmptyAcceptedEnvironmentSet() {
        assertThrows(IllegalArgumentException.class, () -> AppAttestConfig.withTrustRoot(
                "TEAMID1234", "com.example.app", EnumSet.noneOf(AppAttestEnvironment.class),
                AppAttestConfig.appleRootCa()));
    }

    @Test
    void rejectsANullAcceptedEnvironmentSet() {
        assertThrows(IllegalArgumentException.class, () -> AppAttestConfig.withTrustRoot(
                "TEAMID1234", "com.example.app", null, AppAttestConfig.appleRootCa()));
    }

    @Test
    void rejectsANullTrustRoot() {
        assertThrows(NullPointerException.class, () -> AppAttestConfig.withTrustRoot(
                "TEAMID1234", "com.example.app", EnumSet.of(AppAttestEnvironment.PRODUCTION), null));
    }

    @Test
    void bundledAppleRootCaLoadsAndIsSelfIssued() {
        var root = AppAttestConfig.appleRootCa();
        assertEquals(root.getIssuerX500Principal(), root.getSubjectX500Principal());
        assertTrue(root.getSubjectX500Principal().getName().contains("Apple"));
    }
}
