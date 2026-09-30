/*
 * The operator API and the federation entity register their parts at init: the operator API is disabled without an
 * admin token and ready with one, and a federation init that fails returns and is recorded as failed.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import jakarta.servlet.ServletConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FederationComponentTest {

    private static final String TOKEN_PROP = "oidf.authority.admin_token";

    @BeforeEach
    @AfterEach
    void reset() {
        System.clearProperty(TOKEN_PROP);
        FederationRuntimeConfig.resetForTests();
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    // ---- OPERATOR_API --------------------------------------------------------------------------------

    @Test
    void theOperatorApiWithoutAnAdminTokenIsDisabled() throws Exception {
        new FederationAdminServlet().init(mock(ServletConfig.class));
        assertEquals(ComponentState.DISABLED, part("FederationAdminServlet").state());
        assertEquals(Startup.OPERATOR_API, part("FederationAdminServlet").component());
    }

    @Test
    void theOperatorApiWithAnAdminTokenIsReady() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("adminToken")).thenReturn("an-admin-token");
        new FederationAdminServlet().init(config);
        assertEquals(ComponentState.READY, part("FederationAdminServlet").state());
        assertEquals(ComponentState.READY, Components.status(Startup.OPERATOR_API).orElseThrow().state());
    }

    // ---- FEDERATION ----------------------------------------------------------------------------------

    @Test
    void aFederationInitThatFailsReturnsAndIsAFailedConfiguration() {
        // No trust anchor issuer configured: the servlet does not start, and its init returns (S-9).
        assertDoesNotThrow(() -> new OpenIdFederationServlet().init(mock(ServletConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, part("OpenIdFederationServlet").state());
        assertEquals(Startup.FEDERATION, part("OpenIdFederationServlet").component());
        assertTrue(part("OpenIdFederationServlet").reason().startsWith("Failed to initialize OpenID Federation servlet"),
                part("OpenIdFederationServlet").reason());
        assertEquals(ComponentState.FAILED_CONFIG, Components.status(Startup.FEDERATION).orElseThrow().state());
    }
}
