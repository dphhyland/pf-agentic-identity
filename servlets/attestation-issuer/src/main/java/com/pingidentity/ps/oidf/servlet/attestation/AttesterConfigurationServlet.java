/*
 * Attester discovery document: what a workload needs to know to obtain a Client Attestation.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.agent.AgentRegistrySupport;
import com.pingidentity.ps.oidf.issuer.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.issuer.AttestationMinter;
import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.issuer.ClientResolverPlugins;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators;
import com.pingidentity.ps.oidf.issuer.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import com.pingidentity.ps.oidf.pf.PfMgmtClientStore;
import com.pingidentity.ps.oidf.issuer.SpiffeBinding;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.net.TrustedProxies;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;

/**
 * Serves the <em>issuance-side</em> attester metadata at {@code /.well-known/client-attester}: the
 * endpoints, evidence types, and proof requirements a workload must satisfy to exchange its identity
 * evidence for a Client Attestation at {@link AttestationIssuanceServlet}. This is the counterpart of the
 * <em>verification-side</em> capability lists the OP advertises in its Entity Configuration
 * ({@code AttestationMetadataConfig}); the two describe different actors and are deliberately separate
 * documents.
 *
 * <p>The {@code /.well-known/client-attester} document is a static, cacheable, <strong>parameterless</strong>
 * resource (RFC 8615) carrying only deployment-wide facts; it advertises a
 * {@code client_configuration_endpoint}. The per-client view is served separately from
 * {@code /federation/attester-configuration?client_id=<id>} (resolved through the same
 * {@link IssuanceClientResolver} the issuance endpoint uses, so the status gate applies): the attester
 * {@code issuer}, the {@code evidence_audience} the workload must mint into its SVID, the pinned trust
 * domain, and the RAR <em>type names</em> it may request. The full entitlement ceiling, the instance
 * bindings, and the signing configuration are deliberately not exposed.
 *
 * <p>The advertised endpoint URLs are derived from the request: its own scheme and host, or behind a proxy
 * {@code OIDF_TRUSTED_PROXIES} lists, what that proxy says in {@code X-Forwarded-Proto}/{@code -Host}/{@code -Port} (or
 * RFC 7239 {@code Forwarded}) - platform's {@link TrustedProxies} (plan item H-ATT-3, F-0061). From any other sender
 * those headers are ignored, so a caller cannot make the document name a host of its choosing. The
 * {@code challengeRequired} init-param mirrors the issuance servlet's and must be configured to the same value.
 *
 * <p>CORS (H-ATT-3): {@code Access-Control-Allow-Origin} is sent only to an origin {@value #CORS_SETTING} lists, with
 * {@code Vary: Origin}, for {@code GET}; by default none is. Workloads and SDKs fetch these documents from servers,
 * which CORS does not restrict, so the default costs them nothing. What it stops is a web page reading the documents
 * through a visitor's browser - the browser can reach an attester the page's author cannot, inside a private network,
 * and the per-client view names a client's issuer, trust domain and RAR types.
 */
// loadOnStartup: its part of ATTESTATION_ISSUER registers at deploy, not on the first request (finding F-0193); its init
// never throws.
@WebServlet(urlPatterns = {"/.well-known/client-attester", "/federation/.well-known/client-attester",
        "/federation/attester-configuration"}, loadOnStartup = 1)
public class AttesterConfigurationServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * Evidence formats the issuance endpoint can validate — read off the validator registry, so a newly
     * registered evidence type is advertised without editing anything here.
     */
    static List<String> evidenceTypesSupported() {
        return InstanceAttestationValidators.defaults().ids();
    }

    /** The client-authentication method the advertised token endpoint accepts. */
    static final List<String> TOKEN_ENDPOINT_AUTH_METHODS = List.of("attest_jwt_client_auth");

    /** The browser origins allowed to read the documents. */
    static final String CORS_SETTING = "OIDF_ATTESTER_CORS_ORIGINS";

    /** An origin as a browser serialises it: scheme, host and an optional port, no path. */
    private static final Pattern ORIGIN = Pattern.compile("https?://([a-z0-9]([a-z0-9.-]{0,252})?|\\[[0-9a-f:.]{2,45}\\])(:[0-9]{1,5})?");

    private volatile IssuanceClientResolver clientResolver;
    private boolean challengeRequired;
    /** The origins, in lower case, allowed to read the documents from a browser; none by default. */
    private volatile Set<String> corsOrigins = Set.of();

    /** This servlet's part of ATTESTATION_ISSUER, from init; null when a test's constructor made it and init never ran. */
    private transient volatile ComponentParts.Part part;

    /**
     * Registers the servlet's part of {@code ATTESTATION_ISSUER} and reads {@code challengeRequired} strictly, through
     * the attestation-issuer catalogue (plan item ST-5): {@code true} or {@code false}, any case; anything else leaves
     * the part {@code FAILED_CONFIG}, naming the setting, and the documents answer 503.
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        ComponentParts.Part begun = Startup.begin(Startup.ATTESTATION_ISSUER, "AttesterConfigurationServlet");
        this.part = begun;
        begun.start(() -> {
            boolean challengeRequired = AttestationIssuanceServlet.challengeRequired(config);
            Set<String> origins = corsOrigins(AttestationIssuanceServlet.corsOrigins(config));
            TrustedProxies.check();
            this.challengeRequired = challengeRequired;
            this.corsOrigins = origins;
        });
    }

    /**
     * {@value #CORS_SETTING}'s origins, in lower case; empty when unset.
     *
     * @throws SettingRefused naming the setting, for an entry that is not {@code scheme://host[:port]}
     */
    static Set<String> corsOrigins(Set<String> configured) {
        if (configured == null) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String origin : configured) {
            String lower = origin.toLowerCase(Locale.ROOT);
            if (!ORIGIN.matcher(lower).matches()) {
                throw new SettingRefused(CORS_SETTING, CORS_SETTING + ": '" + origin
                        + "' is not an origin, http(s)://host[:port] with no path; '*' is not allowed");
            }
            out.add(lower);
        }
        return Set.copyOf(out);
    }

    void setCorsOrigins(Set<String> origins) {
        this.corsOrigins = corsOrigins(origins);
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (ComponentGate.oauthEndpoint(this.part, resp)) {
            return;
        }
        super.service(req, resp);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        applyCors(req, resp, this.corsOrigins);
        resp.setContentType("application/json");
        String issuer = opIssuer(req);
        Map<String, Object> doc = metadata(baseUrl(req), this.challengeRequired, AgentRegistrySupport.isConfigured(), issuer);

        // The /.well-known document is a static, cacheable, deployment-wide resource — it takes no
        // parameters (per RFC 8615, a well-known URI is a fixed resource). It advertises the deployment
        // evidence audience so a workload can mint its evidence WITHOUT knowing any client_id. The
        // per-client view is served ONLY from the client-configuration endpoint (for operators).
        boolean isClientConfigEndpoint = req.getRequestURI() != null
                && req.getRequestURI().endsWith("/federation/attester-configuration");
        if (!isClientConfigEndpoint) {
            String audience = deploymentEvidenceAudience();
            if (audience != null) {
                doc.put("evidence_audience", audience);
            }
            // Surface the resolver plugins: the full supported set, and which are active — the SPIFFE-ID →
            // client mapping (and its downscoping ceiling) come from these at mint time.
            doc.put("resolver_plugins_supported", ClientResolverPlugins.supported());
            doc.put("resolver_plugins_active", AttesterResolvers.activePluginIds(clientResolver()));
            // The audience the workload must set in its token-endpoint PoP: PF's configured OP issuer,
            // which is stable regardless of how the request was routed (the "aud trap" — the dialed URL
            // can differ from the issuer behind a proxy). Advertised so the SDK does not have to guess it.
            if (issuer != null) {
                doc.put("pop_audience", issuer);
            }
            resp.setHeader("Cache-Control", "public, max-age=300");
            write(resp, 200, doc);
            return;
        }

        String clientId = trimmed(req.getParameter("client_id"));
        if (clientId == null) {
            resp.setHeader("Cache-Control", "no-store");
            write(resp, 400, Map.of("error", "invalid_request", "error_description", "client_id is required"));
            return;
        }
        AttestationIssuanceConfig config;
        try {
            config = clientResolver().resolve(clientId);
        } catch (IssuanceException e) {
            // Deliberately collapsed to a single code: the document must not distinguish
            // unknown / disabled / misconfigured clients.
            resp.setHeader("Cache-Control", "no-store");
            write(resp, 404, Map.of("error", "invalid_client"));
            return;
        }
        doc.putAll(clientMetadata(config));
        resp.setHeader("Cache-Control", "no-store");
        write(resp, 200, doc);
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
        applyCors(req, resp, this.corsOrigins);
        resp.setHeader("Allow", "GET, OPTIONS");
        resp.setStatus(204);
    }

    /** The deployment-wide document without the authorization server's pointers, for a deployment whose issuer is not known. */
    static Map<String, Object> metadata(String baseUrl, boolean challengeRequired, boolean agentIdSupported) {
        return metadata(baseUrl, challengeRequired, agentIdSupported, null);
    }

    /**
     * The deployment-wide document: endpoints, evidence formats, and proof requirements, and - when {@code asIssuer}, the
     * authorization server's issuer, is known - where that server's metadata is (F-0118).
     */
    static Map<String, Object> metadata(String baseUrl, boolean challengeRequired, boolean agentIdSupported, String asIssuer) {
        List<String> algorithms = sortedAlgorithms(ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("attestation_endpoint", baseUrl + "/federation/attestation");
        // The attester's challenge endpoint, for the instance-key proof. The token endpoint's challenges come from
        // the authorization server's own endpoint, which its metadata names; a challenge from one is refused at the
        // other (CAS §4.1), so this document names only the attester's.
        m.put("challenge_endpoint", baseUrl + AttestationIssuanceChallengeServlet.PATH);
        // The PF token endpoint that accepts the minted attestation as client authentication
        // (attest_jwt_client_auth, via ClientAttestationAuthFilter): a client SDK finds it from the PF host alone.
        // Its PoP's challenge is not the one above: it comes from the authorization server's challenge_endpoint, which
        // the document at authorization_server_metadata names (F-0118).
        m.put("token_endpoint", baseUrl + "/as/token.oauth2");
        m.put("token_endpoint_auth_methods_supported", TOKEN_ENDPOINT_AUTH_METHODS);
        String asMetadata = authorizationServerMetadata(asIssuer);
        if (asMetadata != null) {
            // RFC 9728 §2's member: "JSON array containing a list of OAuth authorization server issuer identifiers, as
            // defined in [RFC8414]" - the identifier RFC 8414 §3.3 has the client compare with the issuer the metadata
            // names ("If these values are not identical, the data contained in the response MUST NOT be used").
            m.put("authorization_servers", List.of(asIssuer));
            // And its RFC 8414 §3 location, named as RFC 9728 §5.1 names a protected resource's ("resource_metadata: The
            // URL of the protected resource metadata"): the document whose challenge_endpoint the token endpoint accepts.
            m.put("authorization_server_metadata", asMetadata);
        }
        // The per-client issuance view (issuer, evidence_audience, RAR types) — a separate endpoint that
        // takes ?client_id, keeping this /.well-known document a static, parameterless, cacheable resource.
        m.put("client_configuration_endpoint", baseUrl + "/federation/attester-configuration");
        m.put("challenge_required", challengeRequired);
        m.put("evidence_types_supported", evidenceTypesSupported());
        // The self-described catalogue behind that list: id, format family, title, description.
        m.put("evidence_types", InstanceAttestationValidators.defaults().supported());
        m.put("instance_proof_typ", InstanceKeyProofValidator.TYP);
        m.put("instance_proof_signing_alg_values_supported", algorithms);
        m.put("instance_proof_max_age_seconds", ClientAttestationConfig.DEFAULT_POP_MAX_AGE_SECONDS);
        m.put("attestation_typ", AttestationMinter.TYP);
        m.put("attestation_signing_alg_values_supported", algorithms);
        // Phase 2.4: whether this deployment has an AgentRegistry configured — optional, since a registry
        // is not yet standard, and a workload should not expect an agent_id claim on an attestation
        // minted by a deployment where this is false.
        m.put("agent_id_supported", agentIdSupported);
        return m;
    }

    /** The per-client view appended for {@code ?client_id=}: only what the workload needs, nothing else. */
    static Map<String, Object> clientMetadata(AttestationIssuanceConfig config) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", config.issuer());
        // The aud the workload must mint into its SVID / projected token (== the attester issuer).
        m.put("evidence_audience", config.issuer());
        m.put("evidence_type", config.evidenceType());
        if (config.expectedTrustDomain() != null) {
            m.put("spiffe_trust_domain", config.expectedTrustDomain());
        }
        m.put("attestation_ttl_seconds", config.ttlSeconds());
        List<String> types = authorizationDetailTypes(config);
        if (!types.isEmpty()) {
            m.put("authorization_details_types", types);
        }
        return m;
    }

    /** Distinct RAR {@code type} names across the client ceiling and every binding's entitlement. */
    static List<String> authorizationDetailTypes(AttestationIssuanceConfig config) {
        Set<String> types = new LinkedHashSet<>();
        collectTypes(config.clientCeiling(), types);
        for (SpiffeBinding binding : config.bindings()) {
            collectTypes(binding.entitlement(), types);
        }
        return List.copyOf(types);
    }

    private static void collectTypes(List<Map<String, Object>> details, Set<String> out) {
        for (Map<String, Object> detail : details) {
            Object type = detail.get("type");
            if (type instanceof String && !((String) type).isBlank()) {
                out.add((String) type);
            }
        }
    }

    /**
     * RFC 8414 §3's metadata URL for {@code issuer}: "/.well-known/oauth-authorization-server" inserted "between the host
     * component and the path component, if any", after "any terminating "/"" is removed. Null for no issuer, or one that
     * is not an absolute URL without a query or fragment (RFC 8414 §2).
     */
    static String authorizationServerMetadata(String issuer) {
        if (issuer == null) {
            return null;
        }
        java.net.URI uri;
        try {
            uri = new java.net.URI(issuer);
        } catch (java.net.URISyntaxException e) {
            return null;
        }
        if (uri.getScheme() == null || uri.getRawAuthority() == null || uri.getRawQuery() != null || uri.getRawFragment() != null) {
            return null;
        }
        String path = uri.getRawPath();
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return uri.getScheme() + "://" + uri.getRawAuthority() + "/.well-known/oauth-authorization-server" + path;
    }

    /**
     * PingFederate's configured OP issuer (its base URL), which the workload must use as the
     * token-endpoint PoP audience. Read via PF's own {@code OAuthIssuerUtils} so it matches exactly what
     * the token endpoint expects; returns {@code null} if PF cannot resolve it (then the field is omitted
     * and the SDK falls back to the token endpoint URL).
     */
    private static String opIssuer(HttpServletRequest req) {
        try {
            String issuer = PfInternals.issuer(req);
            return issuer == null || issuer.isBlank() ? null : issuer;
        } catch (Throwable t) {
            return null;
        }
    }

    /**
     * The externally-visible base URL (scheme://host[:port] + context path), preferring
     * {@code X-Forwarded-*} headers over the connection's own coordinates.
     */
    static String baseUrl(HttpServletRequest req) {
        TrustedProxies.Origin origin = TrustedProxies.current().origin(req.getRemoteAddr(),
                name -> AttestationIssuanceServlet.headerValues(req, name));
        String host = origin.host();
        String scheme = origin.scheme() != null ? origin.scheme() : req.getScheme();
        StringBuilder base = new StringBuilder(scheme).append("://");
        if (host != null) {
            base.append(host);
            // A forwarded host may already carry a port; only append X-Forwarded-Port if it does not.
            Integer port = origin.port();
            if (port != null && !hasPort(host) && !isDefaultPort(scheme, String.valueOf(port))) {
                base.append(':').append(port);
            }
        } else {
            base.append(req.getServerName());
            int port = req.getServerPort();
            if (port > 0 && !isDefaultPort(scheme, String.valueOf(port))) {
                base.append(':').append(port);
            }
        }
        String context = req.getContextPath();
        if (context != null && !context.isEmpty() && !"/".equals(context)) {
            base.append(context);
        }
        return base.toString();
    }

    private static boolean isDefaultPort(String scheme, String port) {
        return ("https".equalsIgnoreCase(scheme) && "443".equals(port))
                || ("http".equalsIgnoreCase(scheme) && "80".equals(port));
    }

    /** Whether a host, a name or {@code [IPv6]}, carries a {@code :port}. */
    static boolean hasPort(String host) {
        return host.startsWith("[") ? host.contains("]:") : host.contains(":");
    }

    private static List<String> sortedAlgorithms(Set<String> algorithms) {
        List<String> out = new ArrayList<>(algorithms);
        Collections.sort(out);
        return out;
    }

    /**
     * The deployment-wide evidence audience a workload mints into its evidence, without knowing any
     * client. Derived from the attestation clients' shared attester issuer; returns null if they are
     * absent or disagree (in which case the workload falls back to the per-client configuration endpoint).
     */
    private String deploymentEvidenceAudience() {
        try {
            String common = null;
            for (com.pingidentity.ps.oidf.issuer.AttesterClient c : clientResolver().attestationClients()) {
                String issuer = c.config().issuer();
                if (issuer == null) {
                    continue;
                }
                if (common == null) {
                    common = issuer;
                } else if (!common.equals(issuer)) {
                    return null; // ambiguous — do not advertise a single audience
                }
            }
            return common;
        } catch (IssuanceException e) {
            return null;
        }
    }

    // ---- seams for tests / runtime defaults -------------------------------------------------------

    void setClientResolver(IssuanceClientResolver resolver) {
        this.clientResolver = resolver;
    }

    IssuanceClientResolver clientResolver() {
        IssuanceClientResolver local = this.clientResolver;
        if (local == null) {
            synchronized (this) {
                if (this.clientResolver == null) {
                    this.clientResolver = defaultClientResolver();
                }
                local = this.clientResolver;
            }
        }
        return local;
    }

    /** The runtime default resolver — CIMD document if configured, else the PF client store. */
    protected IssuanceClientResolver defaultClientResolver() {
        return AttesterResolvers.fromEnvironment();
    }

    /**
     * CORS for a listed origin only: {@code Access-Control-Allow-Origin} naming it and {@code GET} as the one method.
     * {@code Vary: Origin} whenever any origin is listed, since the answer then depends on the request's.
     */
    static void applyCors(HttpServletRequest req, HttpServletResponse resp, Set<String> allowed) {
        if (allowed.isEmpty()) {
            return;
        }
        resp.addHeader("Vary", "Origin");
        String origin = req.getHeader("Origin");
        if (origin != null && allowed.contains(origin.toLowerCase(Locale.ROOT))) {
            resp.setHeader("Access-Control-Allow-Origin", origin);
            resp.setHeader("Access-Control-Allow-Methods", "GET");
        }
    }

    private static void write(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    private static String trimmed(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
