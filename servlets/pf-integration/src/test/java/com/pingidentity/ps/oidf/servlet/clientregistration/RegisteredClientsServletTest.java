package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.pf.ClientStore;
import com.pingidentity.ps.oidf.pf.testkit.OperatorRequests;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorAuthenticator;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorScopes;
import com.pingidentity.ps.oidf.platform.pf.auth.OperatorTestKit;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * The operator surface that lists federation-registered clients. It was unauthenticated and always
 * on, and also returned a count of every client in the instance. These assert it now discloses
 * nothing without both being switched on and an operator the authenticator lets through with
 * oidf.admin.clients.read.
 */
class RegisteredClientsServletTest {

    private static Client federationClient(String id) {
        Client c = new Client();
        c.setClientId(id);
        ParamValues v = new ParamValues();
        v.setElements(List.of("auto_registered"));
        c.setExtendedParams(new java.util.HashMap<>(Map.of("status", v)));
        return c;
    }

    private static final String PATH = "/federation/registered-clients";

    private static HttpServletRequest get(String authorization) {
        return get(authorization, null);
    }

    private static HttpServletRequest get(String authorization, String dpop) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getMethod()).thenReturn("GET");
        when(req.getServletPath()).thenReturn(PATH);
        when(req.getRemoteAddr()).thenReturn("192.0.2.31");
        OperatorRequests.stub(req, PATH, authorization, dpop);
        return req;
    }

    private static OperatorAuthenticator development(String token) {
        return OperatorTestKit.unconfigured(DeploymentProfile.DEVELOPMENT).withStaticBearer(token);
    }

    @Test
    void isA404WhenNotExplicitlyEnabled() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        new RegisteredClientsServlet(store, development("s3cret"), false).doGet(get("Bearer s3cret"), resp);

        verify(resp).sendError(404);
        verifyNoInteractions(store);
    }

    @Test
    void refusesWithoutACredentialWithTheChallenge() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        new RegisteredClientsServlet(store, development("s3cret"), true).doGet(get(null), resp);

        verify(resp).setStatus(401);
        verify(resp).addHeader(org.mockito.ArgumentMatchers.eq("WWW-Authenticate"),
                org.mockito.ArgumentMatchers.startsWith("DPoP algs="));
        verifyNoInteractions(store);
    }

    @Test
    void refusesAWrongToken() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        new RegisteredClientsServlet(store, development("s3cret"), true).doGet(get("Bearer wrong"), resp);

        verify(resp).setStatus(401);
        verifyNoInteractions(store);
    }

    @Test
    void refusesEverythingWhenNothingIsConfigured() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        // Enabled but unconfigured must fail CLOSED - forgetting the configuration must not open the endpoint.
        new RegisteredClientsServlet(store, development(null), true).doGet(get("Bearer anything"), resp);

        verify(resp).setStatus(503);
        verifyNoInteractions(store);
    }

    @Test
    void anotherMethodIsNotARoute() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);
        HttpServletRequest req = get("Bearer s3cret");
        when(req.getMethod()).thenReturn("DELETE");

        new RegisteredClientsServlet(store, development("s3cret"), true).doGet(req, resp);

        verify(resp).sendError(404);
        verifyNoInteractions(store);
    }

    @Test
    void productionNeedsTheClientsScopeAndRefusesTheStaticBearer() throws Exception {
        ClientStore store = mock(ClientStore.class);
        when(store.getAll()).thenReturn(List.of(federationClient("https://rp.example")));
        OperatorTestKit kit = new OperatorTestKit();
        OperatorAuthenticator production = kit.authenticator(DeploymentProfile.PRODUCTION);

        String admin = kit.token(OperatorScopes.ADMIN_READ);
        HttpServletResponse lacking = mock(HttpServletResponse.class);
        new RegisteredClientsServlet(store, production, true).doGet(get("DPoP " + admin, kit.proof(admin, "GET", PATH)), lacking);
        verify(lacking).setStatus(403);

        HttpServletResponse refused = mock(HttpServletResponse.class);
        new RegisteredClientsServlet(store, production.withStaticBearer("s3cret"), true).doGet(get("Bearer s3cret"), refused);
        verify(refused).setStatus(503);
        verifyNoInteractions(store);

        String token = kit.token(OperatorScopes.ADMIN_CLIENTS_READ);
        HttpServletResponse ok = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(ok.getWriter()).thenReturn(new PrintWriter(body));
        new RegisteredClientsServlet(store, production, true).doGet(get("DPoP " + token, kit.proof(token, "GET", PATH)), ok);
        verify(ok).setStatus(200);
        assertTrue(body.toString().contains("https://rp.example"), body.toString());
    }

    @Test
    void listsOnlyMarkedClientsAndNoInstanceWideCount() throws Exception {
        ClientStore store = mock(ClientStore.class);
        Client unmarked = new Client();
        unmarked.setClientId("https://terraform-made.example");
        when(store.getAll()).thenReturn(List.of(federationClient("https://rp.example"), unmarked));
        HttpServletResponse resp = mock(HttpServletResponse.class);
        StringWriter body = new StringWriter();
        when(resp.getWriter()).thenReturn(new PrintWriter(body));

        new RegisteredClientsServlet(store, development("s3cret"), true).doGet(get("Bearer s3cret"), resp);

        String json = body.toString();
        assertTrue(json.contains("https://rp.example"), json);
        assertFalse(json.contains("terraform-made"),
                "a client without our marker must not be listed - the old shape-based guess swept these in");
        assertFalse(json.contains("total_clients"),
                "the instance-wide count disclosed more than the list itself");
        verify(resp, never()).sendError(anyInt());
    }

    @Test
    void settingsAreReadFromTheInitParamThenThePropertyThenTheEnvironment() {
        jakarta.servlet.ServletConfig config = mock(jakarta.servlet.ServletConfig.class);
        when(config.getInitParameter("p")).thenReturn("from-init");
        assertTrue("from-init".equals(com.pingidentity.ps.oidf.pf.OperatorApi.setting(config, "p", "s8b.test.property", "S8B_TEST_UNSET_ENV")));
        System.setProperty("s8b.test.property", "from-property");
        try {
            assertTrue("from-property".equals(com.pingidentity.ps.oidf.pf.OperatorApi.setting(null, "p", "s8b.test.property", "S8B_TEST_UNSET_ENV")));
            when(config.getInitParameter("p")).thenReturn(" ");
            assertTrue("from-property".equals(com.pingidentity.ps.oidf.pf.OperatorApi.setting(config, "p", "s8b.test.property", "S8B_TEST_UNSET_ENV")));
        } finally {
            System.clearProperty("s8b.test.property");
        }
        assertTrue(com.pingidentity.ps.oidf.pf.OperatorApi.setting(null, "p", "s8b.test.property", "S8B_TEST_UNSET_ENV") == null);
        System.setProperty("s8b.test.property", "  ");
        try {
            assertTrue(com.pingidentity.ps.oidf.pf.OperatorApi.setting(null, "p", "s8b.test.property", "PATH") != null, "the environment last");
        } finally {
            System.clearProperty("s8b.test.property");
        }
    }
}
