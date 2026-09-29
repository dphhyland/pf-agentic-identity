/*
 * Hosting registers its part at init: with no authority configured it is disabled, and init returns.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.ServletConfig;
import org.junit.jupiter.api.Test;

class HostingComponentTest {

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void noAuthorityMeansHostingIsDisabledNotFailed() {
        // A PingFederate that hosts nothing must not look failed, and so not ready; its init returns (S-9), at deploy.
        assertDoesNotThrow(() -> new HostedEntityServlet().init(mock(ServletConfig.class)));
        assertEquals(ComponentState.DISABLED, part("HostedEntityServlet").state());
        assertEquals(Startup.HOSTING, part("HostedEntityServlet").component());
    }
}
