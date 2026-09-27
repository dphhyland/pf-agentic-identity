/*
 * The SSF transmitter's and receiver's states follow what the bootstrap did, and never change it.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.component.ComponentRegistry;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import jakarta.servlet.ServletConfig;
import java.time.Clock;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfComponentsTest {

    private ComponentParts parts;

    @BeforeEach
    void fresh() {
        System.clearProperty("oidf.ssf.issuer");
        this.parts = new ComponentParts(new ComponentRegistry(), Clock.systemUTC());
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((k, v) -> when(config.getInitParameter(k)).thenReturn(v));
        return config;
    }

    private static final Map<String, String> TRANSMITTER = Map.of("issuer", "https://op.example.com");
    private static final Map<String, String> RECEIVER = Map.of("issuer", "https://op.example.com",
            "receiverExpectedIssuer", "https://transmitter.example.com", "receiverAudience", "https://op.example.com",
            "receiverEndpointAuthToken", "t0ken");

    private static boolean transmitterConfigured() {
        return configured();
    }

    private static boolean configured() {
        try {
            SsfSupport.configuration();
            return true;
        } catch (IllegalStateException e) {
            return false;
        }
    }

    @Test
    void aStartedTransmitterIsReady() {
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        SsfComponents.transmitter(part, true, config(TRANSMITTER));
        assertEquals(ComponentState.READY, part.status().state());
    }

    @Test
    void noIssuerIsADisabledTransmitter() {
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        SsfComponents.transmitter(part, false, config(Map.of()));
        assertEquals(ComponentState.DISABLED, part.status().state());
    }

    @Test
    void settingsThatDoNotParseAreReadAsDisabledAsTheBootstrapReadsThem() {
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        SsfComponents.transmitter(part, false, config(Map.of("issuer", "https://op.example.com", "pushRetryMaxAttempts", "lots")));
        assertEquals(ComponentState.DISABLED, part.status().state(), "finding F-0191");
    }

    @Test
    void aConfiguredTransmitterThatDidNotStartFailedOnADependencyUntilTheRetryConfiguresIt() {
        ComponentParts.Part part = this.parts.begin(Startup.SSF, "SsfConfigurationServlet");
        SsfComponents.transmitter(part, false, config(TRANSMITTER));
        assertEquals(ComponentState.FAILED_DEPENDENCY, part.status().state());
        assertEquals(SsfComponents.NOT_STARTED, part.status().reason());
        this.parts.refresh();
        assertEquals(transmitterConfigured() ? ComponentState.READY : ComponentState.FAILED_DEPENDENCY, part.status().state(),
                "the probe is SsfSupport.configuration()");
    }

    @Test
    void theReceiverIsDisabledWhenSsfOrTheReceiverIsNotConfigured() {
        ComponentParts.Part none = this.parts.begin(Startup.SSF_RECEIVER, "A");
        SsfComponents.receiver(none, false, config(Map.of()));
        assertEquals(ComponentState.DISABLED, none.status().state());
        ComponentParts.Part noReceiver = this.parts.begin(Startup.SSF_RECEIVER, "B");
        SsfComponents.receiver(noReceiver, true, config(TRANSMITTER));
        assertEquals(ComponentState.DISABLED, noReceiver.status().state());
    }

    @Test
    void aReceiverMissingItsAudienceOrTokenIsAFailedConfiguration() {
        ComponentParts.Part part = this.parts.begin(Startup.SSF_RECEIVER, "SsfReceiverServlet");
        SsfComponents.receiver(part, true, config(Map.of("issuer", "https://op.example.com",
                "receiverExpectedIssuer", "https://transmitter.example.com")));
        assertEquals(ComponentState.FAILED_CONFIG, part.status().state());
        assertEquals("the SSF receiver is not started: [receiverAudience, receiverEndpointAuthToken] must be set", part.status().reason());
    }

    @Test
    void aConfiguredReceiverIsReadyWhenTheTransmitterStartedAndFailedOnADependencyWhenItDidNot() {
        ComponentParts.Part started = this.parts.begin(Startup.SSF_RECEIVER, "A");
        SsfComponents.receiver(started, true, config(RECEIVER));
        assertEquals(ComponentState.READY, started.status().state());
        ComponentParts.Part notStarted = this.parts.begin(Startup.SSF_RECEIVER, "B");
        SsfComponents.receiver(notStarted, false, config(RECEIVER));
        assertEquals(ComponentState.FAILED_DEPENDENCY, notStarted.status().state());
        assertEquals(SsfComponents.NOT_STARTED, notStarted.status().reason());
    }
}
