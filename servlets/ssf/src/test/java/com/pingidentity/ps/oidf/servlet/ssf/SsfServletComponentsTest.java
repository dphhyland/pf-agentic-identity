/*
 * The SSF servlets register their parts at init through SsfComponents, from what the bootstrap did.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.ServletConfig;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SsfServletComponentsTest {

    @BeforeEach
    void noAmbientIssuer() {
        System.clearProperty("oidf.ssf.issuer");
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    private static ServletConfig config(Map<String, String> params) {
        ServletConfig config = mock(ServletConfig.class);
        params.forEach((k, v) -> when(config.getInitParameter(k)).thenReturn(v));
        return config;
    }

    @Test
    void withNoIssuerTheTransmitterIsDisabled() throws Exception {
        new SsfConfigurationServlet().init(config(Map.of()));
        assertEquals(ComponentState.DISABLED, part("SsfConfigurationServlet").state());
        assertEquals(Startup.SSF, part("SsfConfigurationServlet").component());
    }

    @Test
    void withNoIssuerTheReceiverIsDisabled() throws Exception {
        new SsfReceiverServlet().init(config(Map.of()));
        assertEquals(ComponentState.DISABLED, part("SsfReceiverServlet").state());
        assertEquals(Startup.SSF_RECEIVER, part("SsfReceiverServlet").component());
    }

    @Test
    void aReceiverMissingItsAudienceAndTokenIsAFailedConfiguration() throws Exception {
        new SsfReceiverServlet().init(config(Map.of("issuer", "https://op.example.com",
                "receiverExpectedIssuer", "https://transmitter.example.com")));
        assertEquals(ComponentState.FAILED_CONFIG, part("SsfReceiverServlet").state());
    }
}
