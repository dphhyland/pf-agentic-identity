/*
 * The registration servlet's and filters' init-params, read through S5C's registration catalogue (plan item ST-5).
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * An init-param may name the trust controller only to agree with the deployment's; the accepted algorithms are a list
 * of words, and the subordinate cache's bound is at least 1 or -1.
 */
class RegistrationConfigurationSettingsTest {

    @Test
    void aTrustControllerInitParamMayOnlyAgree() {
        assertDoesNotThrow(() -> RegistrationConfiguration.requireAgreement(RegistrationConfiguration.settings(name -> null),
                RegistrationConfiguration.TRUST_CONTROLLER_HOST_PARAM, "https://ta.example"));
        assertDoesNotThrow(() -> RegistrationConfiguration.requireAgreement(RegistrationConfiguration.settings(
                Map.of("trustControllerHost", " https://ta.example ")::get), RegistrationConfiguration.TRUST_CONTROLLER_HOST_PARAM,
                "https://ta.example"));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> RegistrationConfiguration.requireAgreement(
                RegistrationConfiguration.settings(Map.of("trustControllerBaseUrl", "https://other.example")::get),
                RegistrationConfiguration.TRUST_CONTROLLER_BASE_URL_PARAM, "https://ta.example"));
        assertTrue(e.getMessage().contains("trustControllerBaseUrl"), e.getMessage());
    }

    @Test
    void theAcceptedAlgorithmsAreWordsAndTheCacheBoundIsNeverZero() {
        assertEquals(Set.of(), RegistrationConfiguration.acceptedSigningAlgorithms(RegistrationConfiguration.settings(name -> null)));
        assertEquals(Set.of("ES256", "PS256"), RegistrationConfiguration.acceptedSigningAlgorithms(RegistrationConfiguration.settings(
                Map.of("acceptedSigningAlgorithms", "ES256 PS256")::get)));
        assertEquals(256, RegistrationConfiguration.cacheMaxEntries(RegistrationConfiguration.settings(name -> null)));
        assertEquals(-1, RegistrationConfiguration.cacheMaxEntries(RegistrationConfiguration.settings(
                Map.of("subordinateStatementCacheMaxEntries", "-1")::get)));
        SettingRefused zero = assertThrows(SettingRefused.class, () -> RegistrationConfiguration.cacheMaxEntries(
                RegistrationConfiguration.settings(Map.of("subordinateStatementCacheMaxEntries", "0")::get)));
        assertEquals("subordinateStatementCacheMaxEntries", zero.setting());
    }
}
