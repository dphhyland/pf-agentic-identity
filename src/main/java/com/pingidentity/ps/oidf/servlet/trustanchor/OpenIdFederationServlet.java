package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.common.PfJwksSigningKeyProvider;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;

/**
 * OpenID Federation entity servlet acting as a trust anchor / intermediate. Serves the entity
 * configuration at {@code /.well-known/openid-federation} and the federation entity, fetch, list
 * and resolve endpoints, delegating to {@link FederationService} and applying optional CORS headers.
 */
@WebServlet(urlPatterns={"/.well-known/openid-federation", "/federation/entity", "/federation/fetch", "/federation/list", "/federation/resolve"})
public class OpenIdFederationServlet
extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private FederationService federationService;
    private FederationConfiguration federationConfiguration;
    private static final Log log = LogFactory.getLog(OpenIdFederationServlet.class);

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            this.federationConfiguration = FederationConfiguration.fromServletConfig(config);
            this.federationService = new FederationService(this.federationConfiguration,
                new PfJwksSigningKeyProvider(this.federationConfiguration.signingAlgorithm()));
        }
        catch (Exception e) {
            throw new ServletException("Failed to initialize OpenID Federation servlet", e);
        }
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        this.applyCorsHeaders(resp);
        String oidcIssuer = OAuthIssuerUtils.getInstance().getIssuerValue(req);
        try {
            switch (path) {
                case "/.well-known/openid-federation": {
                    this.handleFederationMetadata(resp, oidcIssuer);
                    break;
                }
                case "/federation/entity": {
                    this.handleEntityStatement(req, resp, oidcIssuer);
                    break;
                }
                case "/federation/fetch": {
                    this.handleFetch(req, resp, oidcIssuer);
                    break;
                }
                case "/federation/list": {
                    this.handleList(req, resp, oidcIssuer);
                    break;
                }
                case "/federation/resolve": {
                    this.handleResolve(req, resp, oidcIssuer);
                    break;
                }
                default: {
                    writeError(resp, 404, "not_found", "Unknown endpoint", new Exception("endpoint not supported"));
                    break;
                }
            }
        }
        catch (IllegalArgumentException e) {
            writeError(resp, 400, "invalid_request", e.getMessage(), e);
        }
        catch (Exception e) {
            writeError(resp, 500, "server_error", e.getMessage(), e);
        }
    }

    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        this.applyCorsHeaders(resp);
        resp.setStatus(204);
    }

    private void handleFederationMetadata(HttpServletResponse resp, String oidcIssuer) throws Exception {
        String jwt = this.federationService.createEntityConfigurationJwt(oidcIssuer);
        resp.setStatus(200);
        resp.setContentType("application/entity-statement+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    private void applyCorsHeaders(HttpServletResponse resp) {
        if (this.federationConfiguration == null || !this.federationConfiguration.corsEnabled()) {
            return;
        }
        resp.setHeader("Access-Control-Allow-Origin", this.federationConfiguration.corsAllowOrigin());
        resp.setHeader("Access-Control-Allow-Methods", this.federationConfiguration.corsAllowMethods());
        resp.setHeader("Access-Control-Allow-Headers", this.federationConfiguration.corsAllowHeaders());
        resp.setHeader("Access-Control-Max-Age", Integer.toString(this.federationConfiguration.corsMaxAge()));
        resp.setHeader("Vary", "Origin");
    }

    private void handleEntityStatement(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws Exception {
        String sub = required(req, "sub");
        String iss = optional(req, "iss");
        String jwt = this.federationService.createEntityStatement(sub, iss, oidcIssuer);
        resp.setStatus(200);
        resp.setContentType("application/entity-statement+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    private void handleFetch(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws Exception {
        String iss = required(req, "iss");
        String sub = required(req, "sub");
        String jwt = this.federationService.fetchEntityStatement(iss, sub, oidcIssuer);
        resp.setStatus(200);
        resp.setContentType("application/entity-statement+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    private void handleList(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws IOException {
        String entityType = optional(req, "entity_type");
        List<String> entities = this.federationService.listSubordinates(entityType);
        writeJson(resp, 200, toJsonStringArray(entities));
    }

    private void handleResolve(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws Exception {
        String sub = required(req, "sub");
        String trustAnchor = optional(req, "trust_anchor");
        Map<String, Object> resolved = this.federationService.resolveTrustChain(sub, trustAnchor, oidcIssuer);
        writeJson(resp, 200, JsonUtil.toJson(resolved));
    }

    private static String required(HttpServletRequest req, String name) {
        String value = req.getParameter(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required parameter: " + name);
        }
        return value;
    }

    private static String optional(HttpServletRequest req, String name) {
        String value = req.getParameter(name);
        return value == null || value.isBlank() ? null : value;
    }

    private static void writeJson(HttpServletResponse resp, int status, String json) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        try (PrintWriter out = resp.getWriter()) {
            out.write(json);
        }
    }

    private static String toJsonStringArray(List<String> values) {
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (String value : values) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append(jsonQuote(value));
        }
        sb.append(']');
        return sb.toString();
    }

    private static String jsonQuote(String value) {
        if (value == null) {
            return "null";
        }
        StringBuilder sb = new StringBuilder(value.length() + 2);
        sb.append('\"');
        int i = 0;
        while (i < value.length()) {
            char c = value.charAt(i);
            switch (c) {
                case '\"': {
                    sb.append("\\\"");
                    break;
                }
                case '\\': {
                    sb.append("\\\\");
                    break;
                }
                case '\b': {
                    sb.append("\\b");
                    break;
                }
                case '\f': {
                    sb.append("\\f");
                    break;
                }
                case '\n': {
                    sb.append("\\n");
                    break;
                }
                case '\r': {
                    sb.append("\\r");
                    break;
                }
                case '\t': {
                    sb.append("\\t");
                    break;
                }
                default: {
                    if (c < ' ') {
                        sb.append(String.format("\\u%04x", c));
                        break;
                    }
                    sb.append(c);
                }
            }
            ++i;
        }
        sb.append('\"');
        return sb.toString();
    }

    private static void writeError(HttpServletResponse resp, int status, String error, String description, Throwable t) throws IOException {
        log.error("error:", t);
        writeJson(resp, status, JsonUtil.toJson(Map.of("error", error, "error_description", description)));
    }
}

