/*
 * Shared HTTP + receiver-authentication helpers for the SSF servlets.
 */
package com.pingidentity.ps.oidf.servlet.ssf;

import com.pingidentity.ps.oidf.ssf.AuthContext;
import com.pingidentity.ps.oidf.ssf.ReceiverAuthException;
import com.pingidentity.ps.oidf.ssf.SsfConfiguration;
import com.pingidentity.ps.oidf.ssf.SsfSupport;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
     * Fail-soft servlet bootstrap: install the JDBC store factory and configure the transmitter from
     * init-params / {@code oidf.ssf.*} system properties / {@code OIDF_SSF_*} env vars. If SSF isn't configured
     * (e.g. no issuer), it logs and returns {@code false} rather than throwing — a servlet must never break the
     * runtime web application just because SSF is absent. Returns {@code true} once configured.
     */
    static boolean bootstrap(ServletConfig config) {
        SsfSupport.installStoreFactory(new PfJdbcStoreFactory());
        try {
            SsfSupport.configure(SsfConfiguration.fromServletConfig(config));
            wireReceiver();
            return true;
        } catch (IllegalArgumentException e) {
            log.info((Object) ("SSF transmitter not configured (" + e.getMessage() + "); endpoints disabled "
                    + "until an issuer is set (init-param 'issuer', system property 'oidf.ssf.issuer', or "
                    + "env OIDF_SSF_ISSUER)"));
            return false;
        }
    }

    /**
     * Authenticate the request's {@code Authorization: Bearer} token and require the receiver scope. On failure,
     * writes the appropriate 401/403/503 error and returns {@code null}; on success returns the {@link AuthContext}.
     */
    static AuthContext authorize(HttpServletRequest req, HttpServletResponse resp, SsfConfiguration cfg) throws IOException {
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
            log.warn((Object) ("receiver auth unavailable: " + e.getMessage()));
            writeError(resp, 503, "temporarily_unavailable", "token validation unavailable");
            return null;
        }
        if (!auth.isActive()) {
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            writeError(resp, 401, "invalid_token", "token is not active");
            return null;
        }
        if (!auth.hasScope(cfg.receiverScope())) {
            writeError(resp, 403, "insufficient_scope", "token lacks scope " + cfg.receiverScope());
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
            receiver.addHandler(new com.pingidentity.ps.oidf.ssf.ReceiverActionHandler(new PfReceiverActions()));
        }
        SsfSupport.startReceiverPolling();
        receiverWired = true;
    }

    private static volatile boolean receiverWired;

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

    static void writeError(HttpServletResponse resp, int status, String error, String description) throws IOException {
        LinkedHashMap<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        if (description != null) {
            body.put("error_description", description);
        }
        writeJson(resp, status, body);
    }
}
