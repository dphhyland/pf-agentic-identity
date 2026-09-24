package com.pingidentity.ps.oidf.servlet.clientregistration;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.function.Function;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.servlet.trustanchor.FederationErrors;

/**
 * Servlet for OpenID Federation explicit client registration. Accepts a signed
 * entity statement ({@code application/entity-statement+jwt}) or a trust-chain
 * JSON body ({@code application/trust-chain+json}) at {@code /federation/register}
 * and returns a signed explicit-registration response.
 */
@WebServlet(urlPatterns = {"/federation/register"})
public class OpenIdRegistrationServlet
extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private RegistrationService RegistrationService;
    private final Function<HttpServletRequest, String> issuerResolver;

    public OpenIdRegistrationServlet() {
        this(null, req -> OAuthIssuerUtils.getInstance().getIssuerValue(req));
    }

    /** Test seam: a pre-built service and an issuer resolver, so the servlet runs without PF's runtime. */
    OpenIdRegistrationServlet(RegistrationService service, Function<HttpServletRequest, String> issuerResolver) {
        this.RegistrationService = service;
        this.issuerResolver = Objects.requireNonNull(issuerResolver, "issuerResolver");
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        if (this.RegistrationService != null) {
            return;
        }
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
                    FederationErrors.write(resp, FederationError.NOT_FOUND, "unknown endpoint", null);
                    break;
                }
            }
        }
        catch (RegistrationRejectedException e) {
            FederationErrors.write(resp, e.status(), e.error(), e.getMessage(), e);
        }
        catch (Exception e) {
            // A chain the validator refused is a FederationException carrying its §8.9 code
            // (invalid_trust_chain, invalid_metadata, invalid_trust_anchor, temporarily_unavailable).
            FederationErrors.write(resp, e);
        }
    }

    private void handleExplicitRegister(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        ExplicitRegistrationRequest registrationRequest;
        String contentType = req.getContentType();
        String mediaType = baseMediaType(contentType);
        String oidcIssuer = this.issuerResolver.apply(req);
        if ("application/entity-statement+jwt".equalsIgnoreCase(mediaType)) {
            String requestJwt = readRequestBody(req);
            registrationRequest = ExplicitRegistrationRequest.fromJwt(requestJwt, oidcIssuer);
        } else if ("application/trust-chain+json".equalsIgnoreCase(mediaType)) {
            String body = readRequestBody(req);
            registrationRequest = ExplicitRegistrationRequest.fromTrustChainJson(body);
        } else {
            FederationErrors.write(resp, FederationError.INVALID_REQUEST, "Unsupported content-type: " + contentType, null);
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

    private static void writeEntityStatement(HttpServletResponse resp, int status, String jwt) throws IOException {
        resp.setStatus(status);
        resp.setContentType("application/explicit-registration-response+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }
}

