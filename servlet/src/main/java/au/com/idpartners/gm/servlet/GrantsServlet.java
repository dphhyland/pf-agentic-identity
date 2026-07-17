package au.com.idpartners.gm.servlet;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.access.AccessGrantManagerAccessor;
import com.pingidentity.sdk.accessgrant.AccessGrantManager;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
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

    private PfTokenVerifier verifier;
    private PdpClient pdp;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.verifier = new PfTokenVerifier(param(config, "audience", System.getenv("GM_AUDIENCE")));

        String pdpUrl = param(config, "pdpUrl", System.getenv("AUTHZEN_BASE_URL"));
        if (pdpUrl == null || pdpUrl.isBlank()) {
            // Refuse to start rather than answer every evaluation with a 503 that looks
            // like the PDP is down.
            throw new ServletException("pdpUrl init-param (or AUTHZEN_BASE_URL) is required");
        }
        String pdpToken = param(config, "pdpToken", System.getenv("AUTHZEN_BEARER_TOKEN"));
        int timeout = Integer.parseInt(param(config, "pdpTimeoutMs", "10000"));

        this.pdp = new PdpClient(pdpUrl, pdpToken, timeout);
        log.info("Grant Management API ready; PDP at " + pdp.getEvaluationUrl());
    }

    private static String param(ServletConfig config, String name, String fallback) {
        String v = config.getInitParameter(name);
        return v == null || v.isBlank() ? fallback : v;
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
            AccessGrantManagerAccessor.getAccessGrantManager().revokeGrant(grantId);
        } catch (Exception e) {
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
            grant = lookup(grantId);
        } catch (GrantStoreException e) {
            log.log(Level.SEVERE, "grant lookup failed for " + grantId, e);
            writeError(resp, 503, "service_unavailable", "The grant could not be read.");
            return;
        }

        Map<String, Object> decisionRequest;
        try {
            decisionRequest = GrantEvaluator.buildDecisionRequest(
                    grant, token,
                    str(resource.get("type")), str(resource.get("id")),
                    str(action.get("name")), asMap(action.get("properties")),
                    asMap(body.get("context")));
        } catch (GrantEvaluator.RefusedException e) {
            // Refused by the AS before the PDP was consulted -- section 8.4.2.
            log.info("refused: " + e.refusal.code + ": " + e.getMessage());
            writeDecision(resp, false, e.refusal.code, e.refusal.userMessage,
                    "Denied by the authorization server. The PDP was not consulted.");
            return;
        }

        Map<String, Object> decision;
        try {
            decision = pdp.evaluate(decisionRequest);
        } catch (PdpClient.PdpUnavailableException e) {
            // Section 6.7.4. Not a denial: we could not ask.
            log.log(Level.SEVERE, "PDP call failed", e);
            writeError(resp, 503, "service_unavailable", "The policy decision service is unavailable.");
            return;
        }

        if (decision == null) {
            // A 200 whose body is the literal `null` decodes to null rather than
            // throwing. A PDP we cannot understand is an outage, not a denial.
            log.severe("PDP returned a null document");
            writeError(resp, 503, "service_unavailable", "The policy decision service is unavailable.");
            return;
        }

        boolean permitted = Boolean.TRUE.equals(decision.get("decision"));
        log.info("evaluate grant=" + grantId + " action=" + str(action.get("name"))
                + " resource=" + str(resource.get("type")) + "/" + str(resource.get("id"))
                + " -> " + permitted);

        writeResponse(resp, permitted, userReasonsOf(decision));
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
        TokenClaims token = verify(req, resp);
        if (token == null) {
            return null;
        }
        GrantView grant;
        try {
            grant = lookup(grantId);
        } catch (GrantStoreException e) {
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
            return verifier.verify(bearerFrom(req));
        } catch (PfTokenVerifier.InvalidTokenException e) {
            // Never echo the reason: it tells an attacker which part of the token to fix.
            log.log(Level.FINE, "token rejected", e);
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            writeError(resp, 401, "invalid_token", "The access token is not valid.");
            return null;
        }
    }

    /** The grant store could not be read. Distinct from the grant not existing. */
    private static class GrantStoreException extends Exception {
        GrantStoreException(Throwable cause) {
            super(cause);
        }
    }

    /**
     * Reads the grant in-process.
     *
     * <p>Returns null for a grant that does not exist, and throws when the store itself
     * could not be read. Those are different answers and must not share a signal: "no
     * such grant" is a decision, "I could not look" is an outage, and reporting the
     * second as the first tells a client its consent is gone when it is not.
     *
     * <p>The attributes are passed as a supplier so they are only fetched when the grant
     * carries no native consent -- otherwise every request would pay for a second read.
     */
    private GrantView lookup(String grantId) throws GrantStoreException {
        try {
            AccessGrantManager manager = AccessGrantManagerAccessor.getAccessGrantManager();
            return GrantView.from(manager.getByGuid(grantId), () -> {
                try {
                    return manager.getGrantAttributes(grantId);
                } catch (Exception e) {
                    log.log(Level.WARNING, "could not read grant attributes for " + grantId, e);
                    return null;
                }
            });
        } catch (Exception e) {
            throw new GrantStoreException(e);
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
     * The user-facing half of the PDP's reasons, and only that half.
     *
     * <p>AuthZEN's reason_admin may name internal policy detail; section 8.4.3 says it
     * must not reach the client. Dropping it here is structural, not a filter that can be
     * forgotten downstream.
     */
    static List<Map<String, Object>> userReasonsOf(Map<String, Object> decision) {
        List<Map<String, Object>> out = new ArrayList<>();
        Map<String, Object> context = asMap(decision.get("context"));
        if (context.isEmpty()) {
            return out;
        }
        Map<String, Object> reasonUser = asMap(context.get("reason_user"));
        if (reasonUser.isEmpty()) {
            return out;
        }
        Object message = reasonUser.containsKey("en")
                ? reasonUser.get("en")
                : reasonUser.values().iterator().next();

        Map<String, Object> reason = new LinkedHashMap<>();
        if (context.get("id") != null) {
            reason.put("id", context.get("id"));
        }
        reason.put("message", str(message));
        out.add(reason);
        return out;
    }

    private void writeResponse(HttpServletResponse resp, boolean decision,
                               List<Map<String, Object>> reasons) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decision", decision);
        if (!reasons.isEmpty()) {
            body.put("context", Map.of("reasons", reasons));
        }
        write(resp, 200, body);
    }

    private void writeDecision(HttpServletResponse resp, boolean decision, String id,
                               String message, String step) throws IOException {
        Map<String, Object> reason = new LinkedHashMap<>();
        reason.put("id", id);
        reason.put("message", message);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("decision", decision);
        body.put("context", Map.of("reasons", List.of(reason)));
        body.put("trace", Map.of("step", step));
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
