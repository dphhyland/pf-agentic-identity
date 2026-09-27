/*
 * Hosting registers its part at init: with no authority configured it is disabled, and init still refuses to start.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;

class HostingComponentTest {

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    @Test
    void noAuthorityMeansHostingIsDisabledNotFailedAndInitStillRefuses() {
        // The servlet starts lazily, on its path's first request: a caller reaching /federation/agents/* on a
        // PingFederate that hosts nothing must not be able to make it look failed, and so not ready.
        assertThrows(ServletException.class, () -> new HostedEntityServlet().init(mock(ServletConfig.class)));
        assertEquals(ComponentState.DISABLED, part("HostedEntityServlet").state());
        assertEquals(Startup.HOSTING, part("HostedEntityServlet").component());
    }
}
