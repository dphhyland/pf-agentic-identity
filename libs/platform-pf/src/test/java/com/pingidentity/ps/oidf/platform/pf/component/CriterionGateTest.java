/*
 * S-9's rule for the OGNL criteria: false while their component is not serving, decided in the engine's copy without
 * the webapp's registry.
 */
package com.pingidentity.ps.oidf.platform.pf.component;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.ComponentStatus;
import com.pingidentity.ps.oidf.platform.component.ComponentSwitches;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class CriterionGateTest {

    @AfterEach
    void reset() {
        CriterionGate.useForTests(null, null);
        ProfileRefusals.resetForTests();
        System.clearProperty("oidf.attestation.require.bridge.key");
    }

    private static void switches(Map<String, String> env) {
        CriterionGate.useForTests(() -> ComponentSwitches.of(env::get, name -> null), component -> Optional.empty());
    }

    private static ComponentStatus status(ComponentState state, String reason) {
        return new ComponentStatus("ATTESTATION_AUTH", true, state, reason, Instant.EPOCH);
    }

    @Test
    void theEngineCopyAnswersFromTheSwitch() {
        switches(Map.of("OIDF_ATTESTATION_AUTH_ENABLED", "false", "OIDF_FEDERATION_ENABLED", "maybe", "OIDF_DEPLOYMENT_PROFILE",
                "development"));
        assertFalse(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
        assertFalse(CriterionGate.answer("ATTESTATION_AUTH").serving());
        assertTrue(CriterionGate.answer("ATTESTATION_AUTH").why().startsWith("is DISABLED"), CriterionGate.answer("ATTESTATION_AUTH").why());
        // A switch that is not true or false is FAILED_CONFIG: no criterion of that component passes.
        assertFalse(CriterionGate.serves("FEDERATION", "validateTrustChain"));
        assertTrue(CriterionGate.answer("FEDERATION").why().startsWith("is FAILED_CONFIG"));
        // Refused again, logged at DEBUG this time; the answer is the one kept.
        assertFalse(CriterionGate.serves("FEDERATION", "federationPolicy"));
    }

    @Test
    void anEnabledOrInferredComponentServesAndItsCriterionDecides() {
        switches(Map.of("OIDF_ATTESTATION_AUTH_ENABLED", "true", "OIDF_DEPLOYMENT_PROFILE", "development"));
        assertTrue(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
        assertTrue(CriterionGate.serves("FEDERATION", "validateTrustChain"), "inferred");
    }

    @Test
    void unsetInProductionBesideItsSettingsIsFailedConfig() {
        switches(Map.of("OIDF_FEDERATION_TRUST_ANCHORS", "https://ta.example"));
        assertFalse(CriterionGate.serves("FEDERATION", "validateTrustChain"));
    }

    @Test
    void aComponentTheProfileRefusesAnswersFalse() {
        switches(Map.of("OIDF_FEDERATION_ENABLED", "true"));
        // A refusal in code under production (the test's profile: nothing names development) refuses the component here too.
        assertThrows(ProfileRefused.class, () -> ProfileRefusals.refuse("FEDERATION", "a test refusal"));
        assertFalse(CriterionGate.serves("FEDERATION", "validateTrustChain"));
        assertTrue(CriterionGate.answer("FEDERATION").why().startsWith("is REFUSED"));
    }

    @Test
    void thisLoadersRegistryAnswersWhenItHasTheComponent() {
        CriterionGate.useForTests(() -> {
            throw new AssertionError("the switches are not asked when the registry answers");
        }, component -> Optional.of(status(ComponentState.DEGRADED, "static attesters only")));
        assertTrue(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
        CriterionGate.useForTests(null, component -> Optional.of(status(ComponentState.FAILED_DEPENDENCY, "")));
        assertFalse(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
        assertEquals("is FAILED_DEPENDENCY", CriterionGate.answer("ATTESTATION_AUTH").why());
        CriterionGate.useForTests(null, component -> Optional.of(status(ComponentState.READY, "")));
        assertTrue(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
    }

    @Test
    void whatCannotBeReadIsNotServingAndNeverThrows() {
        CriterionGate.useForTests(() -> {
            throw new IllegalStateException("the catalogue is missing");
        }, component -> Optional.empty());
        assertFalse(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
        CriterionGate.useForTests(null, component -> {
            throw new NoClassDefFoundError("platform");
        });
        assertFalse(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"));
    }

    /**
     * The engine's copy is another loader's: its registry is its own and empty, so it cannot see the webapp's READY and
     * answers from the switch. Here the webapp's copy (this test's loader) has ATTESTATION_AUTH READY, and the process
     * switches it off through the superseded system property; the copy loaded apart answers false, this one true.
     */
    @Test
    void theEngineCopyInAnotherLoaderDecidesWithoutTheWebappsRegistry() throws Exception {
        Components.register("ATTESTATION_AUTH", true).ready("");
        System.setProperty("oidf.attestation.require.bridge.key", "false");
        assertTrue(CriterionGate.serves("ATTESTATION_AUTH", "validateClientAttestation"), "the webapp's copy reads its registry");

        List<URL> urls = new ArrayList<>();
        for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
            urls.add(new File(entry).toURI().toURL());
        }
        try (URLClassLoader engine = new URLClassLoader(urls.toArray(new URL[0]), ClassLoader.getPlatformClassLoader())) {
            Class<?> copy = engine.loadClass(CriterionGate.class.getName());
            assertNotSame(CriterionGate.class, copy);
            Object serves = copy.getMethod("serves", String.class, String.class).invoke(null, "ATTESTATION_AUTH", "validateClientAttestation");
            assertEquals(Boolean.FALSE, serves, "the engine's copy answers from the switch, not from the webapp's READY");
        }
    }
}
