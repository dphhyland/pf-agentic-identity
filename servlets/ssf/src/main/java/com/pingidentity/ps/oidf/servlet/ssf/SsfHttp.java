/*
 * Shared HTTP + receiver-authentication helpers for the SSF servlets.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.ReceiverAuthException;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;

/**
 * Small helpers shared by the SSF management and poll servlets: receiver bearer-token authorization (validate
 * the token against PingFederate, require the configured {@code receiverScope}) and JSON read/write. Keeping
 * these here means the two servlets can't drift on how they authenticate.
 */
final class SsfHttp {

    private static final Log log = LogFactory.getLog(SsfHttp.class);

    private SsfHttp() {
    }

    /**
     * What the SSF servlets that register no part of their own - stream management, poll, {@code events:emit}, SCIM -
     * do at {@code init}: nothing but answer whether the transmitter is up. The transmitter starts once, as the
     * {@code SSF} component's part, from {@code SsfConfigurationServlet} (load-on-startup), and is published whole or
     * not at all ({@link SsfComponents#transmitter}); until then these servlets answer 503 through its part's gate.
     * Before 0.6.0 every SSF servlet's {@code init} started it from its own init-params.
     */
    static boolean bootstrap(ServletConfig config) {
        return SsfSupport.isConfigured();
    }

    /**
     * The SSF servlets' gate for a servlet with no part of its own: the transmitter's part ({@code SsfConfigurationServlet}'s).
     * Answers 503 while SSF is starting, failed or refused, and 404 while it is off; true when it has answered.
     */
    static boolean gate(HttpServletResponse resp) throws IOException {
        return ComponentGate.oauthEndpoint(SsfComponents.transmitterPart(), resp);
    }

    /**
     * The servlet layer's wiring, run once the transmitter's state is published ({@link SsfSupport#start}): the receiver's
     * PingFederate actions and polling, and the audit source when {@code OIDF_SSF_AUDIT_EVENTS_ENABLED}.
     */
    static void afterConfigure() {
        wireReceiver();
        if (SsfSupport.configuration().auditEventsEnabled()) {
            try {
                SsfAuditLogSource.attach(SsfSupport.configuration());
            } catch (Throwable t) {
                // e.g. log4j-core absent outside PF — audit sourcing is optional, never fail boot
                log.info((Object) ("SSF audit source unavailable: " + t));
            }
        }
    }

    /**
     * Authenticate the request's {@code Authorization: Bearer} token and require the receiver scope. On failure,
     * writes the appropriate 401/403/503 error and returns {@code null}; on success returns the {@link AuthContext}.
     */
    static AuthContext authorize(HttpServletRequest req, HttpServletResponse resp, SsfConfiguration cfg) throws IOException {
        return authorize(req, resp, cfg.receiverScope());
    }

    /**
     * The same, for the SCIM endpoint, which takes the provisioner scope and not the receiver's: what it
     * does - have an account-disabled signed about a subject the caller names - is not a receiver's to ask
     * for. No provisioner scope configured means no provisioners, so every caller is a 403.
     */
    static AuthContext authorizeProvisioner(HttpServletRequest req, HttpServletResponse resp, SsfConfiguration cfg)
            throws IOException {
        return authorize(req, resp, cfg.provisionerScope());
    }

    /** {@code scope} may be null - nothing is configured to grant this - and then no token carries it. */
    private static AuthContext authorize(HttpServletRequest req, HttpServletResponse resp, String scope) throws IOException {
        String header = req.getHeader("Authorization");
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            resp.setHeader("WWW-Authenticate", "Bearer");
            writeError(resp, 401, "unauthorized", "missing bearer token");
            return null;
        }
        String token = header.substring(7).trim();
        AuthContext auth;
        try {
            auth = SsfSupport.receiverAuthenticator().authenticate(token);
        } catch (ReceiverAuthException e) {
            // With the cause: "token introspection failed" alone has hidden a certificate-name mismatch.
            log.warn((Object) ("receiver auth unavailable: " + e.getMessage()), e);
            writeError(resp, 503, "temporarily_unavailable", "token validation unavailable");
            return null;
        }
        if (!auth.isActive()) {
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            writeError(resp, 401, "invalid_token", "token is not active");
            return null;
        }
        if (scope == null || !auth.hasScope(scope)) {
            writeError(resp, 403, "insufficient_scope", scope == null
                    ? "no scope is configured to grant this, so no token can" : "token lacks scope " + scope);
            return null;
        }
        return auth;
    }

    /** Attach the PF action handler to the receiver and start remote polling (both idempotent). */
    private static synchronized void wireReceiver() {
        com.pingidentity.ps.oidf.ssf.SsfReceiverService receiver = SsfSupport.receiverService();
        if (receiver == null || receiverWired) {
            return;
        }
        if (SsfSupport.configuration().receiverActionsEnabled()) {
            receiver.addHandler(new com.pingidentity.ps.oidf.ssf.ReceiverActionHandler(new PfReceiverActions(),
                    SsfSupport.configuration().receiverLocalIssuers()));
        }
        SsfSupport.startReceiverPolling();
        receiverWired = true;
    }

    private static volatile boolean receiverWired;

    /** Test hook: forget the wiring, as {@code SsfSupport.resetForTests} forgets the state it wired. */
    static synchronized void resetForTests() {
        receiverWired = false;
    }

    static Map<String, Object> readBody(HttpServletRequest req) throws IOException {
        String body = new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        if (body.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return JsonUtil.parseJson(body);
        } catch (org.jose4j.lang.JoseException e) {
            throw new IllegalArgumentException("request body is not valid JSON", e);
        }
    }

    static void writeJson(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    /** A bare JSON array of objects. jose4j serialises only objects, so the array is composed around them. */
    static void writeJsonArray(HttpServletResponse resp, int status, List<Map<String, Object>> items) throws IOException {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append(JsonUtil.toJson(items.get(i)));
        }
        json.append(']');
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        try (PrintWriter out = resp.getWriter()) {
            out.write(json.toString());
        }
    }

    static void writeError(HttpServletResponse resp, int status, String error, String description) throws IOException {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null) {
            body.put("error_description", description);
        }
        writeJson(resp, status, body);
    }
}
