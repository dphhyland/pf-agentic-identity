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
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.sourceid.oauth20.domain.Client;
import org.sourceid.oauth20.domain.ParamValues;

/**
 * The operator surface that lists federation-registered clients. It was unauthenticated and always
 * on, and also returned a count of every client in the instance. These assert it now discloses
 * nothing without both being switched on and presenting the operator token.
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

    private static HttpServletRequest get(String authorization) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("Authorization")).thenReturn(authorization);
        return req;
    }

    @Test
    void isA404WhenNotExplicitlyEnabled() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        new RegisteredClientsServlet(store, "s3cret", false).doGet(get("Bearer s3cret"), resp);

        verify(resp).sendError(404);
        verifyNoInteractions(store);
    }

    @Test
    void refusesWithoutTheOperatorToken() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        new RegisteredClientsServlet(store, "s3cret", true).doGet(get(null), resp);

        verify(resp).sendError(401);
        verify(resp).setHeader("WWW-Authenticate", "Bearer");
        verifyNoInteractions(store);
    }

    @Test
    void refusesAWrongToken() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        new RegisteredClientsServlet(store, "s3cret", true).doGet(get("Bearer wrong"), resp);

        verify(resp).sendError(401);
        verifyNoInteractions(store);
    }

    @Test
    void refusesEverythingWhenNoTokenIsConfigured() throws Exception {
        ClientStore store = mock(ClientStore.class);
        HttpServletResponse resp = mock(HttpServletResponse.class);

        // Enabled but unconfigured must fail CLOSED - forgetting the token must not open the endpoint.
        new RegisteredClientsServlet(store, null, true).doGet(get("Bearer anything"), resp);

        verify(resp).sendError(401);
        verifyNoInteractions(store);
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

        new RegisteredClientsServlet(store, "s3cret", true).doGet(get("Bearer s3cret"), resp);

        String json = body.toString();
        assertTrue(json.contains("https://rp.example"), json);
        assertFalse(json.contains("terraform-made"),
                "a client without our marker must not be listed - the old shape-based guess swept these in");
        assertFalse(json.contains("total_clients"),
                "the instance-wide count disclosed more than the list itself");
        verify(resp, never()).sendError(anyInt());
    }
}
