/*
 * Automatic registration and attestation authentication register their parts at init, as today's configuration
 * decides, without changing whether init throws.
 */
package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import com.pingidentity.ps.oidf.pf.BridgeSigners;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ComponentStatesTest {

    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String ANCHOR_JWKS_PROP = "oidf.federation.trust.anchor.jwks";
    private static final String FRONT_CHANNEL_PROP = "oidf.auto.registration.front.channel";
    private static final String REQUIRE_PROP = "oidf.attestation.require.bridge.key";
    private static final String BACKING_PROP = "oidf.bridge.signer.backing";
    private static final String KEYS_PROP = "oidf.bridge.signing.keys";

    @BeforeEach
    @AfterEach
    void reset() throws Exception {
        for (String p : new String[] {HOST_PROP, ANCHOR_JWKS_PROP, FRONT_CHANNEL_PROP, REQUIRE_PROP, BACKING_PROP, KEYS_PROP}) {
            System.clearProperty(p);
        }
        FederationRuntimeConfig.resetForTests();
        java.lang.reflect.Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    private static void pinAnchor() throws Exception {
        EllipticCurveJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        System.setProperty(HOST_PROP, "https://anchor.example");
        System.setProperty(ANCHOR_JWKS_PROP, "{\"keys\":[" + anchor.toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "]}");
        FederationRuntimeConfig.resetForTests();
    }

    // ---- AUTO_REGISTRATION ---------------------------------------------------------------------------

    @Test
    void theFrontChannelFilterSwitchedOffIsADisabledPart() throws Exception {
        System.setProperty(FRONT_CHANNEL_PROP, "false");
        new FrontChannelAutoRegistrationFilter().init(mock(FilterConfig.class));
        assertEquals(ComponentState.DISABLED, part("FrontChannelAutoRegistrationFilter").state());
        assertEquals(Startup.AUTO_REGISTRATION, part("FrontChannelAutoRegistrationFilter").component());
    }

    @Test
    void withoutPinnedAnchorKeysBothFiltersKeepServingButAutomaticRegistrationIsFailed() throws Exception {
        System.setProperty(HOST_PROP, "https://anchor.example");
        assertDoesNotThrow(() -> new FrontChannelAutoRegistrationFilter().init(mock(FilterConfig.class)));
        assertDoesNotThrow(() -> new TokenEndpointAutoRegistrationFilter().init(mock(FilterConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, part("FrontChannelAutoRegistrationFilter").state());
        assertEquals(ComponentState.FAILED_CONFIG, part("TokenEndpointAutoRegistrationFilter").state());
        assertTrue(part("TokenEndpointAutoRegistrationFilter").reason().startsWith(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV),
                part("TokenEndpointAutoRegistrationFilter").reason());
        assertEquals(ComponentState.FAILED_CONFIG, Components.status(Startup.AUTO_REGISTRATION).orElseThrow().state());
    }

    @Test
    void withThePinnedAnchorTheFrontChannelFilterIsReady() throws Exception {
        // The token endpoint's filter is not started here: its init starts the registration sweeper.
        pinAnchor();
        new FrontChannelAutoRegistrationFilter().init(mock(FilterConfig.class));
        assertEquals(ComponentState.READY, part("FrontChannelAutoRegistrationFilter").state());
    }

    @Test
    void anInitThatThrowsStillThrowsAndIsRecorded() {
        // No trust controller at all: the token endpoint's filter refuses to start, as before.
        ServletException e = assertThrows(ServletException.class,
                () -> new TokenEndpointAutoRegistrationFilter().init(mock(FilterConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, part("TokenEndpointAutoRegistrationFilter").state());
        assertTrue(part("TokenEndpointAutoRegistrationFilter").reason().startsWith(e.getMessage().substring(0, 40)),
                part("TokenEndpointAutoRegistrationFilter").reason());
    }

    // ---- ATTESTATION_AUTH ----------------------------------------------------------------------------

    @Test
    void attestationAuthenticationOptedOutIsDisabled() throws Exception {
        System.setProperty(REQUIRE_PROP, "false");
        new ClientAttestationAuthFilter().init(null);
        assertEquals(ComponentState.DISABLED, part("ClientAttestationAuthFilter").state());
        assertEquals(Startup.ATTESTATION_AUTH, part("ClientAttestationAuthFilter").component());
    }

    @Test
    void attestationAuthenticationRequiredAndUnconfiguredIsAFailedConfiguration() {
        assertThrows(ServletException.class, () -> new ClientAttestationAuthFilter().init(null));
        assertEquals(ComponentState.FAILED_CONFIG, part("ClientAttestationAuthFilter").state());
        assertTrue(part("ClientAttestationAuthFilter").reason().contains("no bridge signing configured"),
                part("ClientAttestationAuthFilter").reason());
    }

    @Test
    void attestationAuthenticationWithoutPinnedAnchorKeysIsDegradedAndCountsAsReady(@TempDir Path dir) throws Exception {
        configureKeys(dir);
        System.setProperty(HOST_PROP, "https://anchor.example");
        FederationRuntimeConfig.resetForTests();
        new ClientAttestationAuthFilter().init(null);
        assertEquals(ComponentState.DEGRADED, part("ClientAttestationAuthFilter").state());
        assertTrue(part("ClientAttestationAuthFilter").reason().contains("statically trusted attesters are unaffected"));
    }

    @Test
    void attestationAuthenticationConfiguredIsReady(@TempDir Path dir) throws Exception {
        configureKeys(dir);
        new ClientAttestationAuthFilter().init(null);
        assertEquals(ComponentState.READY, part("ClientAttestationAuthFilter").state());
    }

    private static void configureKeys(Path dir) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("k0");
        Path file = dir.resolve("bridge-keys.json");
        Files.writeString(file, "{\"https://rp.example.com/agent-1\":{\"jwk\":" + key.toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE)
                + ",\"attesters\":[\"https://attester.example.com\"]}}");
        System.setProperty(BACKING_PROP, "config");
        System.setProperty(KEYS_PROP, file.toString());
        java.lang.reflect.Method bridge = BridgeSigners.class.getDeclaredMethod("resetForTest");
        bridge.setAccessible(true);
        bridge.invoke(null);
    }
}
