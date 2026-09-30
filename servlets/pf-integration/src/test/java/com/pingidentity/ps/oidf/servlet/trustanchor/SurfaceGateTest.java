/*
 * S-9's floor on the federation, hosting and operator surfaces: an init that fails returns and records its reason,
 * and the servlet answers 503 (a component that did not start) or 404 (one that is off) without running.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.AuthoritySupportTestAccess;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfigTestAccess;
import com.pingidentity.ps.oidf.platform.component.ComponentState;
import com.pingidentity.ps.oidf.servlet.GateTesting;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupportTestAccess;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SurfaceGateTest {

    private static final String POLICY_PROP = "oidf.authority.metadata.policy";
    private static final String TOKEN_PROP = "oidf.authority.admin_token";

    private final HttpServletRequest request = mock(HttpServletRequest.class);
    private final HttpServletResponse response = mock(HttpServletResponse.class);

    @BeforeEach
    @AfterEach
    void reset() {
        System.clearProperty(POLICY_PROP);
        System.clearProperty(TOKEN_PROP);
        FederationRuntimeConfigTestAccess.reset();
        // A refusal in code another test made (an in-memory store under production) must not refuse these parts.
        com.pingidentity.ps.oidf.platform.profile.ProfileRefusals.resetForTests();
    }

    @Test
    void aFederationEntityThatDidNotStartAnswers503AndNeverRuns() throws Exception {
        OpenIdFederationServlet servlet = new OpenIdFederationServlet();
        assertDoesNotThrow(() -> servlet.init(mock(ServletConfig.class)));
        assertEquals(ComponentState.FAILED_CONFIG, GateTesting.part("OpenIdFederationServlet").state());

        ByteArrayOutputStream answer = GateTesting.body(this.response);
        servlet.service(this.request, this.response);
        verify(this.response).setStatus(503);
        assertTrue(GateTesting.text(answer).startsWith("{\"error\":\"temporarily_unavailable\""), GateTesting.text(answer));
        verify(this.request, never()).getMethod();
    }

    @Test
    void hostingWhoseConfigurationFailsPublishesNoHalfAuthorityAndAnswers503() throws Exception {
        boolean hostingBefore = AuthoritySupport.isHostingConfigured();
        // Development: under production the registry in memory would refuse HOSTING first (PR-2).
        com.pingidentity.ps.oidf.platform.profile.ProfileRefusals.publish(new com.pingidentity.ps.oidf.platform.settings.ProfileAudit.Result(
                com.pingidentity.ps.oidf.platform.profile.DeploymentProfile.DEVELOPMENT, java.util.List.of(), java.util.List.of()));
        // An authority is named, and its domain metadata policy is not one: the start fails before signing is published.
        System.setProperty(POLICY_PROP, "{\"openid_relying_party\":5}");
        FederationRuntimeConfigTestAccess.reset();
        ServletConfig config = mock(ServletConfig.class);
        when(config.getInitParameter("authorityEntityId")).thenReturn("https://authority.example");
        HostedEntityServlet servlet = new HostedEntityServlet();
        assertDoesNotThrow(() -> servlet.init(config));
        assertEquals(ComponentState.FAILED_CONFIG, GateTesting.part("HostedEntityServlet").state());
        assertEquals(hostingBefore, AuthoritySupport.isHostingConfigured(), "a failed start publishes no signing");

        ByteArrayOutputStream answer = GateTesting.body(this.response);
        servlet.service(this.request, this.response);
        verify(this.response).setStatus(503);
        assertTrue(GateTesting.text(answer).contains("HOSTING is not available"), GateTesting.text(answer));
        verify(this.request, never()).getMethod();
    }

    @Test
    void aStoreIsNotPublishedWhenALaterStepOfTheAuthorityFails() {
        // configureAuthority resolves the store, the policy and the signer before it publishes anything, so a policy that
        // is not one leaves no registry behind - with the registry configured first, the store would stay published.
        AuthoritySupportTestAccess.reset();
        TrustMarkSupportTestAccess.reset();
        try {
            System.setProperty(POLICY_PROP, "{\"openid_relying_party\":5}");
            FederationRuntimeConfigTestAccess.reset();
            // Development: under production the direct URL would be refused before the policy is read (PR-2).
            com.pingidentity.ps.oidf.platform.profile.ProfileRefusals.publish(new com.pingidentity.ps.oidf.platform.settings.ProfileAudit.Result(
                    com.pingidentity.ps.oidf.platform.profile.DeploymentProfile.DEVELOPMENT, java.util.List.of(), java.util.List.of()));
            Map<String, String> params = Map.of("authorityEntityId", "https://authority.example",
                    "jdbcUrl", "jdbc:example:a-store-no-one-connects-to");
            IllegalStateException notAPolicy = assertThrows(IllegalStateException.class, () -> HostedEntityServlet.configureAuthorityFrom(com.pingidentity.ps.oidf.platform.settings.Sources
                    .of(Map.of("OIDF_DEPLOYMENT_PROFILE", "development")::get, System::getProperty, params::get)));
            assertTrue(notAPolicy.getMessage().contains("OIDF_AUTHORITY_METADATA_POLICY"), notAPolicy.getMessage());
            assertTrue(AuthoritySupport.registryIfConfigured().isEmpty(), "a failed configuration publishes no registry");
            assertFalse(AuthoritySupport.isHostingConfigured(), "a failed configuration publishes no signing");
            assertFalse(TrustMarkSupport.isConfigured(), "a failed configuration publishes no Trust Mark store");
        } finally {
            AuthoritySupportTestAccess.reset();
            TrustMarkSupportTestAccess.reset();
        }
    }

    @Test
    void hostingThatIsOffAnswers404() throws Exception {
        HostedEntityServlet servlet = new HostedEntityServlet();
        servlet.init(mock(ServletConfig.class));
        assertEquals(ComponentState.DISABLED, GateTesting.part("HostedEntityServlet").state());

        ByteArrayOutputStream answer = GateTesting.body(this.response);
        servlet.service(this.request, this.response);
        verify(this.response).setStatus(404);
        assertTrue(GateTesting.text(answer).startsWith("{\"error\":\"not_found\""), GateTesting.text(answer));
        verify(this.request, never()).getMethod();
    }

    @Test
    void theOperatorApiWithNoOperatorAuthenticationIsOffAndAnswers404() throws Exception {
        FederationAdminServlet servlet = new FederationAdminServlet();
        servlet.init(mock(ServletConfig.class));
        assertEquals(ComponentState.DISABLED, GateTesting.part("FederationAdminServlet").state());

        GateTesting.body(this.response);
        servlet.service(this.request, this.response);
        verify(this.response).setStatus(404);
        verify(this.request, never()).getMethod();
        assertFalse(GateTesting.part("FederationAdminServlet").reason().contains("token"), "an off part carries no reason");
    }
}
