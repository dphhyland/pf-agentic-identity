/*
 * The one profile rule: development for "development", production for everything else.
 */
package com.pingidentity.ps.oidf.platform.profile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

class DeploymentProfileTest {

    private static Function<String, String> env(String value) {
        return k -> DeploymentProfile.SETTING.equals(k) ? value : null;
    }

    @Test
    void developmentIsTheOneValueTrimmedInAnyCase() {
        for (String value : new String[] {"development", "Development", "DEVELOPMENT", " development ", "\tdevelopment\n"}) {
            assertSame(DeploymentProfile.DEVELOPMENT, DeploymentProfile.parse(value), value);
            assertTrue(DeploymentProfile.of(env(value)).isDevelopment(), value);
            assertFalse(DeploymentProfile.of(env(value)).isProduction(), value);
        }
    }

    @Test
    void everythingElseIsProductionAnUnsetVariableIncluded() {
        for (String value : new String[] {null, "", " ", "production", "staging", "dev", "developement", "development1",
                "develop ment", "\"development\""}) {
            assertSame(DeploymentProfile.PRODUCTION, DeploymentProfile.parse(value), String.valueOf(value));
            assertTrue(DeploymentProfile.of(env(value)).isProduction(), String.valueOf(value));
            assertFalse(DeploymentProfile.of(env(value)).isDevelopment(), String.valueOf(value));
        }
    }

    @Test
    void theProfileIsReadFromTheOneVariableAndTheProcessEnvironment() {
        assertSame(DeploymentProfile.PRODUCTION, DeploymentProfile.of(Map.of("OIDF_PROFILE", "development")::get));
        assertEquals("OIDF_DEPLOYMENT_PROFILE", DeploymentProfile.SETTING);
        // The build sets no profile, so the process is production, as an unset variable is.
        assertSame(DeploymentProfile.parse(System.getenv(DeploymentProfile.SETTING)), DeploymentProfile.current());
        assertEquals("development", DeploymentProfile.DEVELOPMENT.value());
        assertEquals("production", DeploymentProfile.PRODUCTION.value());
    }

    @Test
    void rarModelsReadingIsExactlyDevelopmentLowerCase() {
        assertTrue(DeploymentProfile.isExactlyDevelopment(env("development")));
        assertTrue(DeploymentProfile.isExactlyDevelopment(env(" development ")));
        assertFalse(DeploymentProfile.isExactlyDevelopment(env("Development")), "stricter than the profile rule (F-0160)");
        assertFalse(DeploymentProfile.isExactlyDevelopment(env("production")));
        assertFalse(DeploymentProfile.isExactlyDevelopment(env(null)));
    }

    @Test
    void describeSaysWhatTheVariableHoldsAndWhatItCountsAs() {
        assertEquals("OIDF_DEPLOYMENT_PROFILE is unset, which is production", DeploymentProfile.describe(env(null)));
        assertEquals("OIDF_DEPLOYMENT_PROFILE is 'staging', which counts as production", DeploymentProfile.describe(env("staging")));
        assertEquals("OIDF_DEPLOYMENT_PROFILE is '', which counts as production", DeploymentProfile.describe(env("")));
        assertEquals("OIDF_DEPLOYMENT_PROFILE is 'Development'", DeploymentProfile.describe(env("Development")));
    }
}
