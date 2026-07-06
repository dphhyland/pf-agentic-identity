package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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
 * Servlet for OpenID Federation explicit client registration. Accepts a signed
 * entity statement ({@code application/entity-statement+jwt}) or a trust-chain
 * JSON body ({@code application/trust-chain+json}) at {@code /federation/register}
 * and returns a signed explicit-registration response.
 */
@WebServlet
public class OpenIdRegistrationServlet
extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private RegistrationService RegistrationService;
    private static final Log log = LogFactory.getLog(OpenIdRegistrationServlet.class);

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {
            RegistrationConfiguration registrationConfiguration = RegistrationConfiguration.fromServletConfig(config);
            this.RegistrationService = new RegistrationService(registrationConfiguration);
        }
        catch (Exception e) {
            throw new ServletException("Failed to initialize OpenID Registration servlet", e);
        }
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        try {
            switch (path) {
                case "/federation/register": {
                    this.handleExplicitRegister(req, resp);
                    break;
                }
                default: {
                    writeError(resp, 404, "not_found", "Unknown endpoint", new Exception("Endpoint not supported"));
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

    private void handleExplicitRegister(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ExplicitRegistrationRequest registrationRequest;
        String contentType = req.getContentType();
        String mediaType = baseMediaType(contentType);
        String oidcIssuer = OAuthIssuerUtils.getInstance().getIssuerValue(req);
        if ("application/entity-statement+jwt".equalsIgnoreCase(mediaType)) {
            String requestJwt = readRequestBody(req);
            registrationRequest = ExplicitRegistrationRequest.fromJwt(requestJwt, oidcIssuer);
        } else if ("application/trust-chain+json".equalsIgnoreCase(mediaType)) {
            String body = readRequestBody(req);
            registrationRequest = ExplicitRegistrationRequest.fromTrustChainJson(body);
        } else {
            writeError(resp, 400, "invalid_request", "Unsupported content-type: " + contentType, null);
            return;
        }
        RegisteredClient registeredClient = this.RegistrationService.explicitRegister(registrationRequest, oidcIssuer);
        writeEntityStatement(resp, 201, registeredClient.signedJwt());
    }

    private static String baseMediaType(String contentType) {
        if (contentType == null) {
            return "";
        }
        int semi = contentType.indexOf(59);
        return (semi < 0 ? contentType : contentType.substring(0, semi)).trim();
    }

    private static String readRequestBody(HttpServletRequest req) throws IOException {
        return new String(req.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    }

    private static void writeJson(HttpServletResponse resp, int status, String json) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/json");
        try (PrintWriter out = resp.getWriter()) {
            out.write(json);
        }
    }

    private static void writeEntityStatement(HttpServletResponse resp, int status, String jwt) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/explicit-registration-response+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    private static void writeError(HttpServletResponse resp, int status, String error, String description, Throwable t) throws IOException {
        if (t != null) {
            log.error("error:", t);
        }
        writeJson(resp, status, JsonUtil.toJson(Map.of("error", error, "error_description", description)));
    }
}

