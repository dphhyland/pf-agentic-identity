package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.jose.JdkHttpClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.PfJwksSigningKeyProvider;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.ListRequest;
import com.pingidentity.ps.oidf.federation.ResolveRequest;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;

/**
 * This deployment's federation endpoints (OpenID Federation 1.0 §8, §9): its Entity Configuration at
 * {@code /.well-known/openid-federation}, and the fetch, list and resolve endpoints, delegating to
 * {@link FederationService}. Every failure is answered as §8.9 says, through {@link FederationErrors}.
 * {@code /federation/entity} is a non-standard endpoint kept for older callers; it is not advertised.
 */
// loadOnStartup: init (and the subordinate prewarm it kicks off) must run at war deploy, not
// lazily on first request — lazy init would put the prewarm INSIDE the first token exchange,
// which is the exact cold-fetch-on-the-request-path problem it exists to remove.
@WebServlet(urlPatterns={"/.well-known/openid-federation", "/federation/entity", "/federation/fetch", "/federation/list", "/federation/resolve"}, loadOnStartup=1)
public class OpenIdFederationServlet
extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private FederationService federationService;
    private FederationConfiguration federationConfiguration;
    private final Function<HttpServletRequest, String> issuerResolver;
    private static final Log log = LogFactory.getLog(OpenIdFederationServlet.class);

    public OpenIdFederationServlet() {
        this.issuerResolver = req -> OAuthIssuerUtils.getInstance().getIssuerValue(req);
    }

    /**
     * Test seam: a ready service and configuration, and an issuer resolver, so the servlet runs without a
     * booted PingFederate ({@link OAuthIssuerUtils} and PF's signing keys need one).
     */
    OpenIdFederationServlet(FederationService service, FederationConfiguration configuration,
                            Function<HttpServletRequest, String> issuerResolver) {
        this.federationService = service;
        this.federationConfiguration = configuration;
        this.issuerResolver = issuerResolver;
    }

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        PfAuditEventSink.install();
        if (this.federationService != null) {
            return;
        }
        try {
            this.federationConfiguration = FederationConfiguration.fromServletConfig(config);
            FederationRuntimeConfig runtime = FederationRuntimeConfig.get();
            // The war's context path (e.g. "/oidf") — the entity's identity is PF's path-less OAuth
            // issuer, but the /federation/* endpoints it advertises live under this prefix. Without
            // it a peer following federation_fetch_endpoint gets a 404 at the root path.
            String contextPath = config.getServletContext() == null ? "" : config.getServletContext().getContextPath();
            // The trust controller is operator configuration, so it is exempt from the outbound policy's
            // address rules (it may legitimately be a private/internal host). Everything else - a
            // subordinate's configuration, whatever a resolved subject's hints point at - is screened.
            OutboundUrlPolicy outbound = OutboundUrlPolicy.fromEnvironment().trusting(runtime.trustControllerHost(), runtime.trustControllerBaseUrl());
            JdkHttpGetClient http = new JdkHttpGetClient(this.federationConfiguration.ignoreSslErrors(), outbound);
            FederationService.Builder service = FederationService.builder(this.federationConfiguration,
                            new PfJwksSigningKeyProvider(this.federationConfiguration.signingAlgorithm()))
                    .subordinateFetcher(http)
                    // A subordinate hosted by this same authority (see HostedEntityServlet) resolves through
                    // AuthoritySupport ahead of the fetch-based foreign path, unconditionally — harmless even
                    // if HostedEntityServlet is never configured, since every lookup then returns null.
                    .hostedSubordinateLookup(AuthoritySupport::hostedSubordinateClaims)
                    .hostedSubordinateIds(AuthoritySupport::hostedEntityIds)
                    .hostedConfiguration(AuthoritySupport::hostedEntityConfiguration)
                    // Asked per request: HostedEntityServlet may be initialised after this servlet.
                    .hosting(AuthoritySupport::isHostingConfigured)
                    .federationBasePath(contextPath);
            TrustAnchorSet anchors = resolverAnchors(runtime);
            if (anchors != null) {
                String base = runtime.trustControllerBaseUrl() != null ? runtime.trustControllerBaseUrl() : anchors.entityIds().get(0);
                service.resolver(anchors, new HttpTrustControllerGateway(http, base), Set.of(), ValidatorOptions.defaults());
                if (runtime.trustMarkStatusCheck()) {
                    // §8.4 is POST-only; the same outbound policy screens it.
                    service.trustMarkStatus(new JdkHttpClient(this.federationConfiguration.ignoreSslErrors(), outbound));
                }
                log.info("Federation resolve endpoint enabled for trust anchors " + anchors.entityIds() + " (discovery: "
                        + this.federationConfiguration.resolveDiscovery().name().toLowerCase(java.util.Locale.ROOT) + ")");
            }
            this.federationService = service.build();
            // Fetch each configured subordinate's entity configuration off the request path —
            // a cold cache otherwise puts a live cross-network fetch inside the first token
            // exchange after every restart (see FederationService#prewarmSubordinatesAsync).
            this.federationService.prewarmSubordinatesAsync();
        }
        catch (Exception e) {
            throw new ServletException("Failed to initialize OpenID Federation servlet", e);
        }
    }

    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String path = req.getServletPath();
        this.applyCorsHeaders(resp);
        String oidcIssuer = this.issuerResolver.apply(req);
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
                    FederationErrors.write(resp, FederationError.NOT_FOUND, "unknown endpoint", null);
                    break;
                }
            }
        }
        catch (Exception e) {
            FederationErrors.write(resp, e);
        }
    }

    /**
     * The anchors the resolve endpoint resolves against - the deployment's pinned anchor set - or null when
     * none is configured, which leaves the endpoint unadvertised and answering {@code invalid_trust_anchor}.
     */
    static TrustAnchorSet resolverAnchors(FederationRuntimeConfig runtime) {
        if (!runtime.isTrustControllerConfigured() && !TrustAnchorSet.looksLikeAnchorMap(runtime.trustAnchorJwks())) {
            return null;
        }
        try {
            return runtime.trustAnchors();
        } catch (RuntimeException e) {
            log.warn("Federation resolve endpoint disabled: " + e.getMessage());
            return null;
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

    /** §8.1: {@code sub} is the parameter; {@code iss}, which draft-era clients send, is accepted when it names this entity. */
    private void handleFetch(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws Exception {
        String jwt = this.federationService.fetchSubordinateStatement(optional(req, "iss"), optional(req, "sub"), oidcIssuer);
        resp.setStatus(200);
        resp.setContentType("application/entity-statement+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    /** §8.2: {@code entity_type} may repeat and every one must match; the two booleans are true or false. */
    private void handleList(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws IOException {
        ListRequest request = new ListRequest(repeated(req, "entity_type"), booleanParameter(req, "trust_marked"),
                optional(req, "trust_mark_type"), booleanParameter(req, "intermediate"));
        List<String> entities = this.federationService.listSubordinates(request);
        writeJson(resp, 200, toJsonStringArray(entities));
    }

    /** §8.3: a signed {@code resolve-response+jwt}; {@code trust_anchor} and {@code entity_type} may repeat. */
    private void handleResolve(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer) throws Exception {
        ResolveRequest request = new ResolveRequest(optional(req, "sub"), repeated(req, "trust_anchor"), repeated(req, "entity_type"));
        String jwt = this.federationService.resolve(request, oidcIssuer);
        resp.setStatus(200);
        resp.setContentType("application/resolve-response+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    /** Every value of a repeatable parameter; the request records drop blank ones. */
    private static List<String> repeated(HttpServletRequest req, String name) {
        String[] values = req.getParameterValues(name);
        return values == null ? List.of() : Arrays.asList(values);
    }

    private static Boolean booleanParameter(HttpServletRequest req, String name) {
        String value = optional(req, name);
        if (value == null) {
            return null;
        }
        if ("true".equalsIgnoreCase(value.trim())) {
            return Boolean.TRUE;
        }
        if ("false".equalsIgnoreCase(value.trim())) {
            return Boolean.FALSE;
        }
        throw new FederationException(FederationError.INVALID_REQUEST, name + " must be true or false");
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
}

