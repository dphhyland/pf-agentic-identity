/*
 * SsfHttp.authorize: the receiver-bearer gate in front of every management/poll/SCIM endpoint.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.ReceiverAuthException;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.util.Set;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

/**
 * {@code SsfHttp.authorize} is the single choke point every SSF management, poll and SCIM servlet calls
 * before doing anything: missing bearer, inactive token, wrong scope, and introspection failure must each
 * be refused with the right status — this is the rejection path {@link SsfBootstrapTest} does not reach.
 */
class SsfHttpAuthorizeTest {

    private static final String SCOPE = "ssf.manage";

    @AfterEach
    void resetAuthenticator() {
        SsfSupport.installReceiverAuthenticator(null);
    }

    private static SsfConfiguration config() {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").receiverScope(SCOPE).build();
    }

    private static HttpServletRequest requestWithAuthHeader(String header) {
        HttpServletRequest req = mock(HttpServletRequest.class);
        when(req.getHeader("Authorization")).thenReturn(header);
        return req;
    }

    private static HttpServletResponse responseCapturingBody(ByteArrayOutputStream sink) throws Exception {
        HttpServletResponse resp = mock(HttpServletResponse.class);
        when(resp.getWriter()).thenReturn(new PrintWriter(sink));
        return resp;
    }

    @Test
    @Requirement("RFC6750 §3")
    void missingAuthorizationHeaderIs401() throws Exception {
        HttpServletRequest req = requestWithAuthHeader(null);
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse resp = responseCapturingBody(body);

        assertNull(SsfHttp.authorize(req, resp, config()));

        verify(resp).setStatus(401);
        verify(resp).setHeader("WWW-Authenticate", "Bearer");
        assertEquals("unauthorized", errorField(body.toString()));
    }

    @Test
    @Requirement("RFC6750 §2.1")
    void nonBearerAuthorizationHeaderIs401() throws Exception {
        HttpServletRequest req = requestWithAuthHeader("Basic dXNlcjpwYXNz");
        HttpServletResponse resp = responseCapturingBody(new ByteArrayOutputStream());

        assertNull(SsfHttp.authorize(req, resp, config()));

        verify(resp).setStatus(401);
    }

    @Test
    @Requirement("RFC6750 §3.1")
    void inactiveTokenIs401WithInvalidToken() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.inactive());
        HttpServletRequest req = requestWithAuthHeader("Bearer revoked-token");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse resp = responseCapturingBody(body);

        assertNull(SsfHttp.authorize(req, resp, config()));

        verify(resp).setStatus(401);
        verify(resp).setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
        assertEquals("invalid_token", errorField(body.toString()));
    }

    @Test
    @Requirement("RFC6750 §3.1")
    void activeTokenLackingScopeIs403() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.active("client-1", Set.of("some.other.scope")));
        HttpServletRequest req = requestWithAuthHeader("Bearer good-token");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse resp = responseCapturingBody(body);

        assertNull(SsfHttp.authorize(req, resp, config()));

        verify(resp).setStatus(403);
        assertEquals("insufficient_scope", errorField(body.toString()));
    }

    @Test
    @Requirement("RFC6750 §2.1")
    void activeTokenWithScopeIsAuthorized() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.active("client-1", Set.of(SCOPE)));
        HttpServletRequest req = requestWithAuthHeader("Bearer good-token");
        HttpServletResponse resp = mock(HttpServletResponse.class);

        AuthContext auth = SsfHttp.authorize(req, resp, config());

        assertNotNull(auth);
        assertEquals("client-1", auth.clientId());
    }

    // ─────────────────────────────── the provisioner scope ───────────────────────────────

    private static SsfConfiguration provisioning(String scope) {
        return new SsfConfiguration.Builder().issuer("https://op.example.com").receiverScope(SCOPE).provisionerScope(scope).build();
    }

    @Test
    @Requirement("RFC6750 §3.1")
    void theReceiverScopeDoesNotOpenTheProvisionerGate() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.active("receiver-a", Set.of(SCOPE)));
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse resp = responseCapturingBody(body);

        assertNull(SsfHttp.authorizeProvisioner(requestWithAuthHeader("Bearer t"), resp, provisioning("ssf.provision")));

        verify(resp).setStatus(403);
        assertEquals("insufficient_scope", errorField(body.toString()));

        // controls: that token is a good receiver token, and the provisioner's opens the gate it could not
        assertNotNull(SsfHttp.authorize(requestWithAuthHeader("Bearer t"), mock(HttpServletResponse.class), provisioning("ssf.provision")));
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.active("scim", Set.of("ssf.provision")));
        assertNotNull(SsfHttp.authorizeProvisioner(requestWithAuthHeader("Bearer t"), mock(HttpServletResponse.class),
                provisioning("ssf.provision")));
    }

    @Test
    void theProvisionerScopeDoesNotOpenTheReceiverGate() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.active("scim", Set.of("ssf.provision")));
        HttpServletResponse resp = responseCapturingBody(new ByteArrayOutputStream());

        assertNull(SsfHttp.authorize(requestWithAuthHeader("Bearer t"), resp, provisioning("ssf.provision")));

        verify(resp).setStatus(403);
    }

    @Test
    void withNoProvisionerScopeConfiguredEveryTokenIs403() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> AuthContext.active("scim", Set.of("ssf.provision", SCOPE)));
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse resp = responseCapturingBody(body);

        assertNull(SsfHttp.authorizeProvisioner(requestWithAuthHeader("Bearer t"), resp, provisioning(null)));

        verify(resp).setStatus(403);
        assertEquals("insufficient_scope", errorField(body.toString()));
    }

    @Test
    void introspectionFailureIs503NotABareServerError() throws Exception {
        SsfSupport.installReceiverAuthenticator(token -> {
            throw new ReceiverAuthException("PF unreachable");
        });
        HttpServletRequest req = requestWithAuthHeader("Bearer good-token");
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        HttpServletResponse resp = responseCapturingBody(body);

        assertNull(SsfHttp.authorize(req, resp, config()));

        verify(resp).setStatus(503);
        assertEquals("temporarily_unavailable", errorField(body.toString()));
    }

    /** Pulls the top-level {@code "error"} field out of the small hand-rolled JSON {@code writeError} emits. */
    private static String errorField(String json) {
        int idx = json.indexOf("\"error\":\"");
        if (idx < 0) {
            return null;
        }
        int start = idx + "\"error\":\"".length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
