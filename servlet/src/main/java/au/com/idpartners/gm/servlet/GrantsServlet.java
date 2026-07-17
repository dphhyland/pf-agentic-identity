package au.com.idpartners.gm.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The Grant Management API, served from inside PingFederate.
 *
 * <pre>
 *   GET    /gm-api/grants/{grantId}             query   (section 6.2)
 *   DELETE /gm-api/grants/{grantId}             revoke  (section 6.3)
 *   POST   /gm-api/grants/{grantId}/evaluate    evaluate (section 6.7, proposed)
 * </pre>
 *
 * <p>PingFederate implements none of this itself: it advertises no
 * {@code grant_management_endpoint}, ignores the {@code grant_management_action}
 * authorization request parameter outright, and returns no {@code grant_id} on the token
 * response. What it has is a proprietary admin API at {@code /pf-ws/rest/oauth/...}. This
 * servlet puts the spec's shape on top of PF's own grant store.
 *
 * <p>What it deliberately does <em>not</em> attempt is section 5 — the authorization
 * request lifecycle ({@code create}/{@code replace}/{@code merge}, and {@code grant_id} in
 * the token response). That is authorization server behaviour, not an endpoint, and a
 * servlet cannot reach it. See {@code docs/pingfederate-gm-api-gaps.md}.
 */
public class GrantsServlet extends HttpServlet {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final Logger log = Logger.getLogger(getClass().getName());

    // The same operations the MCP surface uses. One copy of every authorisation rule.
    private GrantOperations ops;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        McpServlet.ServletConfigs cfg = McpServlet.ServletConfigs.of(config);
        this.ops = new GrantOperations(
                new PfTokenVerifier(cfg.audience()),
                new PdpClient(cfg.pdpUrl(), cfg.pdpToken(), cfg.pdpTimeoutMs()));
        log.info("Grant Management API ready; PDP at " + ops.pdp().getEvaluationUrl());
    }

    // ---- section 6.2: query ----

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String grantId = grantIdFrom(req.getPathInfo());
        if (grantId == null) {
            writeError(resp, 404, "not_found", "expected /grants/{grantId}");
            return;
        }
        Authorised a = authorise(req, resp, grantId, GrantEvaluator.SCOPE_QUERY);
        if (a == null) {
            return;
        }
        log.info("query grant=" + grantId + " client=" + a.token.getClientId());
        write(resp, 200, GrantEvaluator.describe(a.grant));
    }

    // ---- section 6.3: revoke ----

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String grantId = grantIdFrom(req.getPathInfo());
        if (grantId == null) {
            writeError(resp, 404, "not_found", "expected /grants/{grantId}");
            return;
        }
        Authorised a = authorise(req, resp, grantId, GrantEvaluator.SCOPE_REVOKE);
        if (a == null) {
            return;
        }
        try {
            ops.revoke(a.grant, a.token);
        } catch (GrantEvaluator.RefusedException e) {
            // authorise already passed, so this cannot fire; kept for the checked type.
            writeError(resp, e.refusal.status, e.refusal.code, e.refusal.userMessage);
            return;
        } catch (GrantOperations.UnavailableException e) {
            log.log(Level.SEVERE, "revoke failed for " + grantId, e);
            writeError(resp, 503, "service_unavailable", "The grant could not be revoked.");
            return;
        }
        log.info("revoked grant=" + grantId + " client=" + a.token.getClientId());
        // Section 6.3: no body.
        resp.setStatus(204);
    }

    // ---- section 6.7: evaluate ----

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String grantId = evaluateGrantIdFrom(req.getPathInfo());
        if (grantId == null) {
            writeError(resp, 404, "not_found", "expected /grants/{grantId}/evaluate");
            return;
        }

        TokenClaims token = verify(req, resp);
        if (token == null) {
            return;
        }

        Map<String, Object> body;
        try {
            body = MAPPER.readValue(req.getInputStream(), Map.class);
        } catch (IOException e) {
            writeError(resp, 400, "invalid_request", "The request body is not valid JSON.");
            return;
        }
        if (body == null) {
            // The literal `null` is valid JSON and decodes to null rather than throwing,
            // so it slips past the catch above and would be dereferenced below.
            writeError(resp, 400, "invalid_request", "The request body must be a JSON object.");
            return;
        }

        Map<String, Object> action = asMap(body.get("action"));
        Map<String, Object> resource = asMap(body.get("resource"));

        GrantView grant;
        try {
            grant = ops.lookup(grantId);
        } catch (GrantOperations.GrantStoreException e) {
            log.log(Level.SEVERE, "grant lookup failed for " + grantId, e);
            writeError(resp, 503, "service_unavailable", "The grant could not be read.");
            return;
        }

        GrantOperations.Decision decision;
        try {
            decision = ops.evaluate(grant, token,
                    str(resource.get("type")), str(resource.get("id")),
                    str(action.get("name")), asMap(action.get("properties")),
                    asMap(body.get("context")));
        } catch (GrantOperations.UnavailableException e) {
            // Section 6.7.4. Not a denial: we could not ask.
            log.log(Level.SEVERE, "PDP call failed", e);
            writeError(resp, 503, "service_unavailable", "The policy decision service is unavailable.");
            return;
        }

        log.info("evaluate grant=" + grantId + " action=" + str(action.get("name"))
                + " resource=" + str(resource.get("type")) + "/" + str(resource.get("id"))
                + " -> " + decision.permitted());

        writeDecision(resp, decision);
    }

    // ---- shared ----

    /** A verified token and the grant it is entitled to act on. */
    private record Authorised(TokenClaims token, GrantView grant) {
    }

    /**
     * Verifies the token, reads the grant, and checks this caller may act on it.
     *
     * <p>Returns null having already written the response when any of that fails, so
     * callers only proceed on the happy path.
     */
    private Authorised authorise(HttpServletRequest req, HttpServletResponse resp,
                                 String grantId, String scope) throws IOException {
        TokenClaims token;
        try {
            token = ops.verify(bearerFrom(req));
        } catch (PfTokenVerifier.InvalidTokenException e) {
            // Never echo the reason: it tells an attacker which part of the token to fix.
            log.log(Level.FINE, "token rejected", e);
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            writeError(resp, 401, "invalid_token", "The access token is not valid.");
            return null;
        }
        GrantView grant;
        try {
            grant = ops.lookup(grantId);
        } catch (GrantOperations.GrantStoreException e) {
            log.log(Level.SEVERE, "grant lookup failed for " + grantId, e);
            writeError(resp, 503, "service_unavailable", "The grant could not be read.");
            return null;
        }
        try {
            GrantEvaluator.authorise(grant, token, scope);
        } catch (GrantEvaluator.RefusedException e) {
            log.info("refused: " + e.refusal.code + ": " + e.getMessage());
            writeError(resp, e.refusal.status, e.refusal.code, e.refusal.userMessage);
            return null;
        }
        return new Authorised(token, grant);
    }

    private TokenClaims verify(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        try {
            return ops.verify(bearerFrom(req));
        } catch (PfTokenVerifier.InvalidTokenException e) {
            log.log(Level.FINE, "token rejected", e);
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            writeError(resp, 401, "invalid_token", "The access token is not valid.");
            return null;
        }
    }

    /**
     * {@code /{id}} -> {@code id}, for query and revoke.
     *
     * <p>The servlet is mapped at {@code /grants/*}, so the container has already consumed
     * the context path and the servlet path: pathInfo is only what follows.
     */
    static String grantIdFrom(String pathInfo) {
        if (pathInfo == null) {
            return null;
        }
        String[] parts = pathInfo.split("/");
        // ["", "{id}"]
        if (parts.length != 2 || parts[1].isEmpty()) {
            return null;
        }
        return parts[1];
    }

    /** {@code /{id}/evaluate} -> {@code id}. */
    static String evaluateGrantIdFrom(String pathInfo) {
        if (pathInfo == null) {
            return null;
        }
        String[] parts = pathInfo.split("/");
        // ["", "{id}", "evaluate"]
        if (parts.length != 3 || !"evaluate".equals(parts[2]) || parts[1].isEmpty()) {
            return null;
        }
        return parts[1];
    }

    static String bearerFrom(HttpServletRequest req) {
        String header = req.getHeader("Authorization");
        if (header == null) {
            return null;
        }
        String[] parts = header.split("\\s+", 2);
        if (parts.length != 2 || !parts[0].equalsIgnoreCase("bearer")) {
            return null;
        }
        return parts[1];
    }

    /**
     * Renders a decision in the spec's response shape.
     *
     * <p>{@code trace} appears only for an AS-side refusal -- a denial reached before the
     * PDP was consulted -- so a client can tell "policy said no" from "the AS said no on
     * the grant's own terms".
     */
    private void writeDecision(HttpServletResponse resp, GrantOperations.Decision d)
            throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decision", d.permitted());
        if (!d.reasonId().isEmpty() || !d.message().isEmpty()) {
            Map<String, Object> reason = new LinkedHashMap<>();
            reason.put("id", d.reasonId());
            reason.put("message", d.message());
            body.put("context", Map.of("reasons", List.of(reason)));
        }
        if (!d.fromPdp()) {
            body.put("trace", Map.of("step",
                    "Denied by the authorization server. The PDP was not consulted."));
        }
        write(resp, 200, body);
    }

    private void writeError(HttpServletResponse resp, int status, String code, String description)
            throws IOException {
        write(resp, status, Map.of("error", code, "error_description", description));
    }

    private void write(HttpServletResponse resp, int status, Object body) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        MAPPER.writeValue(resp.getOutputStream(), body);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : Map.of();
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }
}
