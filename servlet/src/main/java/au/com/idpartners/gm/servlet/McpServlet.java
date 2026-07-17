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
 * The Grant Management API as MCP tools, so an AI agent can ask before it acts.
 *
 * <pre>
 *   POST /gm-api/mcp        JSON-RPC 2.0 over MCP's Streamable HTTP transport
 * </pre>
 *
 * <p>An add-on to {@link GrantsServlet}: same WAR, same PingFederate, same rules. It adds
 * no authorisation logic of its own -- everything goes through {@link GrantOperations},
 * so the agent surface cannot become the loose way in.
 *
 * <h2>Whose token</h2>
 *
 * <p>The one design decision that matters. This server holds <b>no credential</b>. It
 * authenticates each call with the bearer token on the MCP request -- the agent's own --
 * exactly as the REST surface does.
 *
 * <p>The alternative, giving the MCP server a client credential and letting the agent
 * name a grant id, would be a confused deputy: the agent could interrogate any grant the
 * server can reach, and the {@code act} chain that identifies it would be bypassed
 * entirely. The agent would be invisible to policy again. So: the agent brings its own
 * delegated token ({@code sub: alice, act: {sub: agent}}), or it gets nothing.
 *
 * <h2>What is exposed, and what is not</h2>
 *
 * <p>Read-only: evaluate and describe. <b>Revoke is deliberately absent.</b> Ending a
 * user's consent is irreversible and is not a decision an agent should reach through a
 * tool call -- the REST surface has it, for software with a human behind it.
 */
public class McpServlet extends HttpServlet {

    /**
     * The MCP revision this server implements. If a client asks for another, we answer
     * with this one and let it decide -- per the spec, disagreeing on the version is the
     * client's call, not ours.
     */
    private static final String PROTOCOL_VERSION = "2025-06-18";
    private static final String SERVER_NAME = "grant-management";
    private static final String SERVER_VERSION = "1.0.0";

    // JSON-RPC 2.0 error codes.
    private static final int PARSE_ERROR = -32700;
    private static final int INVALID_REQUEST = -32600;
    private static final int METHOD_NOT_FOUND = -32601;
    private static final int INVALID_PARAMS = -32602;
    private static final int INTERNAL_ERROR = -32603;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final Logger log = Logger.getLogger(getClass().getName());

    private GrantOperations ops;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        ServletConfigs cfg = ServletConfigs.of(config);
        this.ops = new GrantOperations(
                new PfTokenVerifier(cfg.audience()),
                new PdpClient(cfg.pdpUrl(), cfg.pdpToken(), cfg.pdpTimeoutMs()));
        log.info("MCP tools ready at /mcp; PDP at " + ops.pdp().getEvaluationUrl());
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        Map<String, Object> message;
        try {
            message = MAPPER.readValue(req.getInputStream(), Map.class);
        } catch (IOException e) {
            writeError(resp, null, PARSE_ERROR, "invalid JSON");
            return;
        }
        if (message == null) {
            writeError(resp, null, INVALID_REQUEST, "empty request");
            return;
        }

        Object id = message.get("id");
        String method = str(message.get("method"));
        if (method == null) {
            writeError(resp, id, INVALID_REQUEST, "no method");
            return;
        }

        // A notification has no id and takes no response.
        if (id == null) {
            log.fine("notification: " + method);
            resp.setStatus(202);
            return;
        }

        try {
            switch (method) {
                case "initialize" -> writeResult(resp, id, initialize());
                case "tools/list" -> writeResult(resp, id, Map.of("tools", toolDefinitions()));
                case "tools/call" -> callTool(req, resp, id, GrantOperations.asMap(message.get("params")));
                case "ping" -> writeResult(resp, id, Map.of());
                default -> writeError(resp, id, METHOD_NOT_FOUND, "unknown method: " + method);
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, "MCP " + method + " failed", e);
            writeError(resp, id, INTERNAL_ERROR, "internal error");
        }
    }

    private Map<String, Object> initialize() {
        return Map.of(
                "protocolVersion", PROTOCOL_VERSION,
                "capabilities", Map.of("tools", Map.of()),
                "serverInfo", Map.of("name", SERVER_NAME, "version", SERVER_VERSION),
                "instructions",
                "Ask before you act. These tools tell you whether a user's existing consent "
                        + "still permits an operation -- which is not the same as your token being "
                        + "valid. A consent can be valid, unexpired, and name an account the user "
                        + "has since closed. Call evaluate_grant before touching a resource, and "
                        + "read the guidance field: it says whether asking the user to consent "
                        + "again would help, or whether the access is simply gone.");
    }

    /**
     * The tools.
     *
     * <p>The descriptions are load-bearing: they are the only thing a model reads before
     * deciding whether to call, so they say what the tool is <em>for</em> rather than
     * what it does mechanically.
     */
    private static List<Map<String, Object>> toolDefinitions() {
        Map<String, Object> evaluateSchema = Map.of(
                "type", "object",
                "properties", Map.of(
                        "grant_id", Map.of("type", "string",
                                "description", "The grant to ask about. This is the 'agid' claim "
                                        + "in your own access token."),
                        "resource_type", Map.of("type", "string",
                                "description", "What kind of thing, e.g. 'account' or 'payment'."),
                        "resource_id", Map.of("type", "string",
                                "description", "Which one, e.g. the account number."),
                        "action", Map.of("type", "string",
                                "description", "What you want to do, e.g. 'read_balance', "
                                        + "'read_transactions', 'initiate_payment'."),
                        "amount", Map.of("type", "number",
                                "description", "For payments: the amount. Consent may cap it.")),
                "required", List.of("grant_id", "resource_type", "resource_id", "action"));

        Map<String, Object> describeSchema = Map.of(
                "type", "object",
                "properties", Map.of(
                        "grant_id", Map.of("type", "string",
                                "description", "The grant to describe. This is the 'agid' claim "
                                        + "in your own access token.")),
                "required", List.of("grant_id"));

        return List.of(
                Map.of("name", "evaluate_grant",
                        "description",
                        "Check whether a user's consent still permits an operation on a specific "
                                + "resource, before you attempt it. Answers the question a valid "
                                + "token cannot: the user may have withdrawn the account, or never "
                                + "had the access they consented to share. Always call this before "
                                + "acting on someone's data.",
                        "inputSchema", evaluateSchema),
                Map.of("name", "describe_grant",
                        "description",
                        "See what a user actually consented to: which scopes, which accounts, and "
                                + "which actions. Useful for explaining to the user what you may do, "
                                + "or for deciding whether an operation is worth attempting.",
                        "inputSchema", describeSchema));
    }

    private void callTool(HttpServletRequest req, HttpServletResponse resp, Object id,
                          Map<String, Object> params) throws IOException {
        String name = str(params.get("name"));
        Map<String, Object> args = GrantOperations.asMap(params.get("arguments"));

        // The agent's own token. This server holds no credential of its own, so an agent
        // with no token gets nothing -- it cannot borrow ours.
        TokenClaims token;
        try {
            token = ops.verify(GrantsServlet.bearerFrom(req));
        } catch (PfTokenVerifier.InvalidTokenException e) {
            log.log(Level.FINE, "MCP token rejected", e);
            resp.setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"");
            // 401 rather than a JSON-RPC error: MCP's HTTP transport carries auth, so an
            // auth failure belongs at the transport layer where the client's OAuth flow
            // can see and act on it.
            resp.setStatus(401);
            resp.setContentType("application/json");
            MAPPER.writeValue(resp.getOutputStream(),
                    Map.of("error", "invalid_token",
                            "error_description", "The access token is not valid."));
            return;
        }

        String grantId = str(args.get("grant_id"));
        if (grantId == null || grantId.isBlank()) {
            writeError(resp, id, INVALID_PARAMS, "grant_id is required");
            return;
        }

        GrantView grant;
        try {
            grant = ops.lookup(grantId);
        } catch (GrantOperations.GrantStoreException e) {
            log.log(Level.SEVERE, "grant lookup failed for " + grantId, e);
            writeToolError(resp, id, "The grant could not be read. This is a service problem, "
                    + "not a decision: do not assume you are denied. Try again shortly.");
            return;
        }

        switch (name == null ? "" : name) {
            case "evaluate_grant" -> evaluateTool(resp, id, grant, token, args);
            case "describe_grant" -> describeTool(resp, id, grant, token);
            default -> writeError(resp, id, INVALID_PARAMS, "unknown tool: " + name);
        }
    }

    private void evaluateTool(HttpServletResponse resp, Object id, GrantView grant,
                              TokenClaims token, Map<String, Object> args) throws IOException {
        String resourceType = str(args.get("resource_type"));
        String resourceId = str(args.get("resource_id"));
        String action = str(args.get("action"));
        if (resourceType == null || resourceId == null || action == null) {
            writeError(resp, id, INVALID_PARAMS,
                    "resource_type, resource_id and action are required");
            return;
        }

        Map<String, Object> props = new LinkedHashMap<>();
        if (args.get("amount") instanceof Number amount) {
            props.put("amount", amount);
        }

        GrantOperations.Decision d;
        try {
            d = ops.evaluate(grant, token, resourceType, resourceId, action, props, null);
        } catch (GrantOperations.UnavailableException e) {
            log.log(Level.SEVERE, "MCP evaluate: PDP unavailable", e);
            // The distinction the model must not lose: this is not a denial.
            writeToolError(resp, id, "The decision service is unavailable, so the question could "
                    + "not be answered. This is NOT a denial. Do not assume you are refused, and "
                    + "do not ask the user to consent again. Retry shortly.");
            return;
        }

        log.info("MCP evaluate grant=" + grant.guid() + " agent=" + token.getActor()
                + " action=" + action + " -> " + d.permitted());

        // The result is written for a model to act on, so it says what to do next. The
        // retryable split is the whole point: sending a user through an authorization
        // flow for an entitlement denial wastes their time and returns the same answer.
        String guidance;
        if (d.permitted()) {
            guidance = "PERMITTED. You may proceed with this operation.";
        } else if (d.retryable()) {
            guidance = "DENIED, but this is a consent problem. Asking the user to grant consent "
                    + "for this specific resource or action could fix it.";
        } else {
            guidance = "DENIED, and asking the user to consent again will NOT help: they do not "
                    + "hold this access themselves, or the grant is gone. Do not retry and do not "
                    + "start a consent flow. Tell the user what happened and stop.";
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("permitted", d.permitted());
        result.put("reason", d.reasonId());
        result.put("explanation", d.message());
        result.put("guidance", guidance);
        result.put("consent_would_help", d.retryable());

        writeToolResult(resp, id, result, false);
    }

    private void describeTool(HttpServletResponse resp, Object id, GrantView grant,
                              TokenClaims token) throws IOException {
        Map<String, Object> consent;
        try {
            consent = ops.describe(grant, token);
        } catch (GrantEvaluator.RefusedException e) {
            log.info("MCP describe refused: " + e.refusal.code + ": " + e.getMessage());
            // A refusal is an answer, not a transport failure.
            writeToolResult(resp, id, Map.of(
                    "reason", e.refusal.code,
                    "explanation", e.refusal.userMessage,
                    "guidance", "You cannot read this grant. Check you are using the grant id from "
                            + "your own token's 'agid' claim, and that your token carries the "
                            + "grant_management_query scope."), true);
            return;
        }
        writeToolResult(resp, id, consent, false);
    }

    // ---- JSON-RPC plumbing ----

    /**
     * A tool result. MCP carries these as content blocks; JSON in a text block is the
     * interoperable way to hand a model structured data.
     *
     * <p>{@code isError} means the tool could not do its job -- not that the answer was
     * no. A denial is a successful evaluation.
     */
    private void writeToolResult(HttpServletResponse resp, Object id, Object payload, boolean isError)
            throws IOException {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("content", List.of(Map.of(
                "type", "text",
                "text", MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(payload))));
        result.put("isError", isError);
        writeResult(resp, id, result);
    }

    private void writeToolError(HttpServletResponse resp, Object id, String message)
            throws IOException {
        writeToolResult(resp, id, Map.of("error", message), true);
    }

    private void writeResult(HttpServletResponse resp, Object id, Object result) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jsonrpc", "2.0");
        body.put("id", id);
        body.put("result", result);
        write(resp, body);
    }

    private void writeError(HttpServletResponse resp, Object id, int code, String message)
            throws IOException {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("code", code);
        error.put("message", message);

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("jsonrpc", "2.0");
        body.put("id", id);
        body.put("error", error);
        write(resp, body);
    }

    /**
     * Streamable HTTP permits a single JSON response when the server has nothing to
     * stream, which is every one of these: each tool call is one request, one answer.
     * A JSON-RPC error is still HTTP 200 -- the transport succeeded.
     */
    private void write(HttpServletResponse resp, Object body) throws IOException {
        resp.setStatus(200);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        MAPPER.writeValue(resp.getOutputStream(), body);
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    /** Shared reading of the init-params both servlets take. */
    record ServletConfigs(String pdpUrl, String pdpToken, String audience, int pdpTimeoutMs) {
        static ServletConfigs of(ServletConfig config) throws ServletException {
            String pdpUrl = param(config, "pdpUrl", System.getenv("AUTHZEN_BASE_URL"));
            if (pdpUrl == null || pdpUrl.isBlank()) {
                throw new ServletException("pdpUrl init-param (or AUTHZEN_BASE_URL) is required");
            }
            return new ServletConfigs(
                    pdpUrl,
                    param(config, "pdpToken", System.getenv("AUTHZEN_BEARER_TOKEN")),
                    param(config, "audience", System.getenv("GM_AUDIENCE")),
                    Integer.parseInt(param(config, "pdpTimeoutMs", "10000")));
        }

        private static String param(ServletConfig config, String name, String fallback) {
            String v = config.getInitParameter(name);
            return v == null || v.isBlank() ? fallback : v;
        }
    }
}
