/*
 * The operator API and the federation entity register their parts at init: the operator API is disabled with no operator
 * authentication, refused while production has a static bearer, failed when its settings cannot authenticate anyone,
 * and a federation init that fails returns and is recorded as failed.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfigTestAccess;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.platform.component.Components;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.PartStatus;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthConfig;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorTestKit;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.util.Map;
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
        FederationRuntimeConfigTestAccess.reset();
    }

    private static PartStatus part(String name) {
        return Startup.parts().parts().stream().filter(p -> p.part().equals(name)).findFirst().orElseThrow();
    }

    // ---- OPERATOR_API --------------------------------------------------------------------------------

    @Test
    void theOperatorApiWithNoOperatorAuthenticationIsDisabled() throws Exception {
        new FederationAdminServlet().init(mock(ServletConfig.class));
        assertEquals(ComponentState.DISABLED, part("FederationAdminServlet").state());
        assertEquals(Startup.OPERATOR_API, part("FederationAdminServlet").component());
    }

    /** Phase 3 decision 20: a static bearer set in production refuses the operator API, with a reason that says to remove it. */
    @Test
    void theOperatorApiWithAStaticBearerInProductionIsRefused() throws Exception {
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("adminToken")).thenReturn("an-admin-token");
        new FederationAdminServlet().init(config);
        assertEquals(ComponentState.REFUSED, part("FederationAdminServlet").state(), "this JVM runs the production profile");
        assertTrue(part("FederationAdminServlet").reason().startsWith("OIDF_AUTHORITY_ADMIN_TOKEN is set, and production"
                + " never accepts the static bearer: remove it"), part("FederationAdminServlet").reason());
        assertEquals(ComponentState.REFUSED, Components.status(Startup.OPERATOR_API).orElseThrow().state());
    }

    @Test
    void whatTheOperatorApisInitMakesOfItsAuthenticator() throws Exception {
        ComponentParts.Part ready = Startup.begin("S8B_OPERATOR_TEST", "OperatorConfiguredReady");
        assertTrue(FederationAdminServlet.operatorConfigured(ready,
                OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer("t")), "development's static bearer");
        assertTrue(FederationAdminServlet.operatorConfigured(ready, new OperatorTestKit().authenticator(DeploymentProfile.PRODUCTION)));

        ComponentParts.Part broken = Startup.begin("S8B_OPERATOR_TEST", "OperatorConfiguredBroken");
        assertFalse(FederationAdminServlet.operatorConfigured(broken,
                OperatorTestKit.of(Map.of(OperatorAuthConfig.AUDIENCE, "https://pf.example.com/agentic-identity"),
                        DeploymentProfile.PRODUCTION)));
        assertEquals(ComponentState.FAILED_CONFIG, broken.status().state());
        assertTrue(broken.status().reason().contains(OperatorAuthConfig.BASE_URL), broken.status().reason());

        ComponentParts.Part off = Startup.begin("S8B_OPERATOR_TEST", "OperatorConfiguredOff");
        assertFalse(FederationAdminServlet.operatorConfigured(off, OperatorTestKit.unconfigured(DeploymentProfile.PRODUCTION)));
        assertEquals(ComponentState.DISABLED, off.status().state());
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
