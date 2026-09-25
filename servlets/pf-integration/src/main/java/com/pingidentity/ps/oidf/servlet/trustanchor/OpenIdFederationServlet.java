package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.jose.OutboundUrlPolicy;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.jose.JdkHttpClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;
import com.pingidentity.ps.oidf.pf.AuthorityDataSource;
import com.pingidentity.ps.oidf.pf.PfAuditEventSink;
import com.pingidentity.ps.oidf.pf.PfJwksSigningKeyProvider;
import com.pingidentity.ps.oidf.pf.PfProviderMetadata;
import com.pingidentity.ps.oidf.pf.RequestScopedServlet;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;
import com.pingidentity.ps.oidf.clientattestation.AttestationSupport;
import com.pingidentity.ps.oidf.federation.EndpointAuthPolicy;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.FederationService;
import com.pingidentity.ps.oidf.federation.FederationConfiguration;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.ListRequest;
import com.pingidentity.ps.oidf.federation.ResolveRequest;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.keyhistory.KeyHistory;
import com.pingidentity.ps.oidf.keyhistory.KeyHistorySupport;
import com.pingidentity.ps.oidf.trustmark.TrustMarkIssuer;
import com.pingidentity.ps.oidf.trustmark.TrustMarkSupport;

/**
 * This deployment's federation endpoints (OpenID Federation 1.0 §8, §9): its Entity Configuration at
 * {@code /.well-known/openid-federation}, and the fetch, list and resolve endpoints, delegating to
 * {@link FederationService}. Every failure is answered as §8.9 says, through {@link FederationErrors}.
 * {@code /federation/entity} is a non-standard endpoint kept for older callers; it is not advertised.
 */
// loadOnStartup: init (and the subordinate prewarm it kicks off) must run at war deploy, not
// lazily on first request — lazy init would put the prewarm INSIDE the first token exchange,
// which is the exact cold-fetch-on-the-request-path problem it exists to remove.
@WebServlet(urlPatterns={"/.well-known/openid-federation", "/federation/entity", "/federation/fetch", "/federation/list", "/federation/resolve",
        "/federation/trust_mark", "/federation/trust_mark_status", "/federation/trust_marked_list", "/federation/historical_keys"}, loadOnStartup=1)
public class OpenIdFederationServlet
extends RequestScopedServlet {
    private static final long serialVersionUID = 1L;
    private FederationService federationService;
    private FederationConfiguration federationConfiguration;
    private final Function<HttpServletRequest, String> issuerResolver;
    /** PingFederate's own discovery documents, which this entity's openid_provider and AS metadata start from. */
    private final PfProviderMetadata providerMetadata;
    private static final Log log = LogFactory.getLog(OpenIdFederationServlet.class);
    private static final String TRUST_MARK_STATUS = "/federation/trust_mark_status";
    /** Where a client's spent endpoint-assertion {@code jti} values are kept, apart from every other replay cache user. */
    private static final String ENDPOINT_REPLAY_NAMESPACE = "oidf-endpoint-auth:";
    /** Each federation endpoint this servlet serves, by the §5.1.1 metadata name §8.8.1 builds its {@code _auth_methods} from. */
    static final Map<String, String> ENDPOINTS = Map.of(
            "/federation/fetch", "federation_fetch_endpoint",
            "/federation/list", "federation_list_endpoint",
            "/federation/resolve", "federation_resolve_endpoint",
            "/federation/trust_mark", "federation_trust_mark_endpoint",
            TRUST_MARK_STATUS, "federation_trust_mark_status_endpoint",
            "/federation/trust_marked_list", "federation_trust_mark_list_endpoint",
            "/federation/historical_keys", "federation_historical_keys_endpoint");

    public OpenIdFederationServlet() {
        this.issuerResolver = req -> OAuthIssuerUtils.getInstance().getIssuerValue(req);
        this.providerMetadata = new PfProviderMetadata();
    }

    /**
     * Test seam: a ready service and configuration, and an issuer resolver, so the servlet runs without a
     * booted PingFederate ({@link OAuthIssuerUtils} and PF's signing keys need one).
     */
    OpenIdFederationServlet(FederationService service, FederationConfiguration configuration,
                            Function<HttpServletRequest, String> issuerResolver) {
        this(service, configuration, issuerResolver, new PfProviderMetadata((type, req) -> "{}", java.time.Clock.systemUTC()));
    }

    /** Test seam, as above, reading discovery documents from {@code providerMetadata}. */
    OpenIdFederationServlet(FederationService service, FederationConfiguration configuration,
                            Function<HttpServletRequest, String> issuerResolver, PfProviderMetadata providerMetadata) {
        this.federationService = service;
        this.federationConfiguration = configuration;
        this.issuerResolver = issuerResolver;
        this.providerMetadata = providerMetadata;
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
                    .providerMetadata(this.providerMetadata)
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
            // Hosting is configured now, not on HostedEntityServlet's first request, when the environment names an authority:
            // fetches about hosted entities are answered from the first request on.
            try {
                HostedEntityServlet.configureAuthority(null);
            } catch (RuntimeException e) {
                log.error("Hosting could not be configured at start-up; HostedEntityServlet tries again on its first request", e);
            }
            service.subordinateConstraints(runtime.subordinateConstraints());
            FederationRuntimeConfig.TrustMarkIssuingSettings marks = runtime.trustMarkIssuing();
            service.ownTrustMarks(marks.carried()).trustMarkIssuers(marks.issuers()).trustMarkOwners(marks.owners());
            if (!marks.types().isEmpty()) {
                // The grants live in the authority's store; HostedEntityServlet points the registry at it too, but starts
                // only on its first request, so the store is resolved here as well - whichever runs first configures it.
                if (!TrustMarkSupport.isConfigured()) {
                    AuthorityDataSource.fromEnvironment().ifPresent(TrustMarkSupport::configureJdbcRegistry);
                }
                service.trustMarkIssuing(new TrustMarkIssuer(marks.types(), TrustMarkSupport.shared(), AuthoritySupport::isActiveHostedEntity,
                        java.time.Clock.systemUTC()));
                log.info("Issuing Trust Marks of types " + marks.types().keySet());
            }
            FederationRuntimeConfig.KeyHistorySettings keyHistory = runtime.keyHistory();
            KeyHistory history = null;
            if (keyHistory.enabled()) {
                if (!KeyHistorySupport.isConfigured()) {
                    AuthorityDataSource.fromEnvironment().ifPresent(KeyHistorySupport::configureJdbcStore);
                }
                history = new KeyHistory(KeyHistorySupport.shared(), java.time.Clock.systemUTC(), java.time.Duration.ofSeconds(keyHistory.graceSeconds()));
                service.historicalKeys(history);
            }
            EndpointAuthPolicy endpointAuth = runtime.endpointAuth();
            // A spent jti is kept where attestation keeps its own - Redis when configured - so a replay is caught on any node.
            service.endpointAuth(endpointAuth, (client, jti, ttl) -> AttestationSupport.replayCache().firstSeen(ENDPOINT_REPLAY_NAMESPACE + client, jti, ttl));
            if (endpointAuth.anyEnabled()) {
                java.util.Map<String, String> modes = new java.util.TreeMap<>();
                for (String endpoint : EndpointAuthPolicy.ENDPOINTS) {
                    if (endpointAuth.mode(endpoint) != EndpointAuthPolicy.Mode.NONE) {
                        modes.put(endpoint, endpointAuth.mode(endpoint).name().toLowerCase(java.util.Locale.ROOT));
                    }
                }
                log.info("Client authentication at the federation endpoints (OpenID Federation 1.0 §8.8): " + modes + ", signed with "
                        + endpointAuth.signingAlgorithms());
            }
            this.federationService = service.build();
            if (history != null) {
                recordSigningKey(history, this.federationService.signingKey());
            }
            FederationService issuing = this.federationService;
            if (issuing.issuesTrustMarks()) {
                // A hosted entity's configuration carries the marks this entity issues it, signed as the authority.
                AuthoritySupport.configureTrustMarks(subject -> {
                    try {
                        return issuing.issuedTrustMarks(subject, AuthoritySupport.authorityEntityId());
                    } catch (org.jose4j.lang.JoseException e) {
                        throw new IllegalStateException("could not sign a Trust Mark for " + subject, e);
                    }
                });
            }
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
        this.providerMetadata.refresh(oidcIssuer, req);
        try {
            String endpoint = ENDPOINTS.get(path);
            if (endpoint != null && !TRUST_MARK_STATUS.equals(path)) {
                if (req.getParameter("client_assertion") != null || req.getParameter("client_assertion_type") != null) {
                    throw new FederationException(FederationError.INVALID_REQUEST, "a client authenticates with a POST, its assertion"
                            + " in the body, never in a query string (OpenID Federation 1.0 §8.8)");
                }
                // An endpoint that requires client authentication refuses a GET here.
                this.federationService.authenticateClient(endpoint, null, null, oidcIssuer);
            }
            this.serve(path, req, resp, oidcIssuer, null, false);
        }
        catch (Exception e) {
            FederationErrors.write(resp, e);
        }
    }

    /**
     * One endpoint's answer to a request that has been let through: a POST when {@code post}, from {@code client} when it
     * authenticated (§8.8).
     */
    private void serve(String path, HttpServletRequest req, HttpServletResponse resp, String oidcIssuer, String client, boolean post)
            throws Exception {
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
                this.handleResolve(req, resp, oidcIssuer, client);
                break;
            }
            case "/federation/trust_mark": {
                this.handleTrustMark(req, resp, oidcIssuer, client);
                break;
            }
            case "/federation/historical_keys": {
                String jwt = this.federationService.historicalKeys(oidcIssuer);
                resp.setStatus(200);
                resp.setContentType("application/jwk-set+jwt");
                try (PrintWriter out = resp.getWriter()) {
                    out.write(jwt);
                }
                break;
            }
            case "/federation/trust_marked_list": {
                writeJson(resp, 200, toJsonStringArray(this.federationService.trustMarkedEntities(optional(req, "trust_mark_type"),
                        optional(req, "sub"))));
                break;
            }
            case TRUST_MARK_STATUS: {
                if (!post) {
                    resp.setHeader("Allow", "POST");
                    FederationErrors.write(resp, 405, "invalid_request", "the Trust Mark Status endpoint takes POST (OpenID Federation 1.0 §8.4.1)", null);
                    break;
                }
                String jwt = this.federationService.trustMarkStatus(optional(req, "trust_mark"), oidcIssuer);
                resp.setStatus(200);
                resp.setContentType("application/trust-mark-status-response+jwt");
                try (PrintWriter out = resp.getWriter()) {
                    out.write(jwt);
                }
                break;
            }
            default: {
                FederationErrors.write(resp, FederationError.NOT_FOUND, "unknown endpoint", null);
                break;
            }
        }
    }

    /**
     * Notices a rotation of this entity's Federation Entity Key since it last started - PingFederate's signing key is
     * read once, at start-up - and publishes the key it replaced (§8.7). Signing with a key revoked as compromised stops
     * the federation endpoints starting; a history that cannot be written only loses that rotation.
     */
    static void recordSigningKey(KeyHistory history, java.util.Map<String, Object> signingKey) throws ServletException {
        try {
            history.observe(signingKey).ifPresent(retired -> log.info("Federation Entity Key " + retired.kid() + " retired; this entity now signs with "
                    + signingKey.get("kid")));
        } catch (AuthorityRegistryException e) {
            if (AuthorityRegistryException.STALE_UPDATE.equals(e.reason())) {
                throw new ServletException("This entity signs with a Federation Entity Key that was revoked: " + e.getMessage()
                        + ". Rotate PingFederate's signing key before starting it again.", e);
            }
            log.error("Could not record this entity's signing key in its history; a rotation since the last start goes unpublished", e);
        }
    }

    /**
     * POST is how the Trust Mark Status endpoint is asked (§8.4.1), and how a client that authenticates asks any endpoint that
     * takes client authentication (§8.8): the assertion and the endpoint's own parameters in the body, none in the query
     * string. Anywhere else a POST that doesn't authenticate is refused - the endpoint takes GET.
     */
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        this.applyCorsHeaders(resp);
        String path = req.getServletPath();
        String endpoint = ENDPOINTS.get(path);
        if (endpoint == null) {
            resp.setHeader("Allow", "GET");
            FederationErrors.write(resp, 405, "invalid_request", "this endpoint takes GET", null);
            return;
        }
        try {
            String oidcIssuer = this.issuerResolver.apply(req);
            String assertion = optional(req, "client_assertion");
            String assertionType = optional(req, "client_assertion_type");
            boolean authenticating = assertion != null || assertionType != null;
            EndpointAuthPolicy.Mode mode = this.federationService.endpointAuth().mode(endpoint);
            if (!authenticating && !TRUST_MARK_STATUS.equals(path) && mode != EndpointAuthPolicy.Mode.REQUIRED) {
                if (mode == EndpointAuthPolicy.Mode.NONE) {
                    resp.setHeader("Allow", "GET");
                    FederationErrors.write(resp, 405, "invalid_request", "this endpoint takes GET", null);
                    return;
                }
                throw new FederationException(FederationError.INVALID_REQUEST, "a POST here authenticates the client: send"
                        + " client_assertion and client_assertion_type in the body, or ask with a GET (OpenID Federation 1.0 §8.8)");
            }
            if (authenticating && req.getQueryString() != null) {
                throw new FederationException(FederationError.INVALID_REQUEST, "an authenticated request carries its parameters in"
                        + " the POST body, not the query string (OpenID Federation 1.0 §8.8)");
            }
            String client = this.federationService.authenticateClient(endpoint, assertionType, assertion, oidcIssuer);
            this.serve(path, req, resp, oidcIssuer, client, true);
        }
        catch (Exception e) {
            FederationErrors.write(resp, e);
        }
    }

    /**
     * §8.6: the mark of {@code trust_mark_type} this entity issues to {@code sub}, as {@code application/trust-mark+jwt}. A client
     * that authenticated asks only for its own: §8.6.1 lets an endpoint serve it another entity's, and this one doesn't.
     */
    private void handleTrustMark(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer, String client) throws Exception {
        String subject = optional(req, "sub");
        if (client != null && subject != null && !EntityId.same(client, subject)) {
            throw new FederationException(FederationError.INVALID_REQUEST, "an authenticated client is given its own Trust Marks"
                    + " here, not another entity's (OpenID Federation 1.0 §8.6.1)");
        }
        String jwt = this.federationService.trustMark(optional(req, "trust_mark_type"), subject, oidcIssuer);
        resp.setStatus(200);
        resp.setContentType("application/trust-mark+jwt");
        try (PrintWriter out = resp.getWriter()) {
            out.write(jwt);
        }
    }

    /**
     * The anchors the resolve endpoint resolves against - the deployment's pinned anchor set - or null when
     * none is configured, which leaves the endpoint unadvertised and answering {@code invalid_trust_anchor}.
     */
    static TrustAnchorSet resolverAnchors(FederationRuntimeConfig runtime) {
        if (!runtime.isTrustControllerConfigured() && !TrustAnchorSet.looksLikeAnchorMap(runtime.trustAnchorJwks()) && runtime.selfAnchor() == null) {
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

    /**
     * §8.3: a signed {@code resolve-response+jwt}; {@code trust_anchor} and {@code entity_type} may repeat. A client that
     * authenticated is its audience (§8.3.2).
     */
    private void handleResolve(HttpServletRequest req, HttpServletResponse resp, String oidcIssuer, String client) throws Exception {
        ResolveRequest request = new ResolveRequest(optional(req, "sub"), repeated(req, "trust_anchor"), repeated(req, "entity_type"));
        String jwt = this.federationService.resolve(request, oidcIssuer, client);
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

