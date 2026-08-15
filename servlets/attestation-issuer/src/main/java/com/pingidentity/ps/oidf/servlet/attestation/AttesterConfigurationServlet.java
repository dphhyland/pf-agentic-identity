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
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
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
 * <p>The advertised endpoint URLs are derived from the request, honouring
 * {@code X-Forwarded-Proto}/{@code X-Forwarded-Host}/{@code X-Forwarded-Port} so the document is correct
 * behind a TLS-terminating proxy. The {@code challengeRequired} init-param mirrors the issuance servlet's
 * and must be configured to the same value.
 */
@WebServlet(urlPatterns = {"/.well-known/client-attester", "/federation/.well-known/client-attester",
        "/federation/attester-configuration"})
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

    private volatile IssuanceClientResolver clientResolver;
    private boolean challengeRequired;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.challengeRequired = Boolean.parseBoolean(config.getInitParameter("challengeRequired"));
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        applyCors(resp);
        resp.setContentType("application/json");
        Map<String, Object> doc = metadata(baseUrl(req), this.challengeRequired, AgentRegistrySupport.isConfigured());

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
            String popAudience = opIssuer(req);
            if (popAudience != null) {
                doc.put("pop_audience", popAudience);
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
        applyCors(resp);
        resp.setStatus(204);
    }

    /** The deployment-wide document: endpoints, evidence formats, and proof requirements. */
    static Map<String, Object> metadata(String baseUrl, boolean challengeRequired, boolean agentIdSupported) {
        List<String> algorithms = sortedAlgorithms(ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("attestation_endpoint", baseUrl + "/federation/attestation");
        m.put("challenge_endpoint", baseUrl + "/federation/attestation-challenge");
        // The PF token endpoint that accepts the minted attestation as client authentication
        // (attest_jwt_client_auth, via ClientAttestationAuthFilter). Advertised so a client SDK can run
        // the whole flow from the PF host alone.
        m.put("token_endpoint", baseUrl + "/as/token.oauth2");
        m.put("token_endpoint_auth_methods_supported", TOKEN_ENDPOINT_AUTH_METHODS);
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
     * PingFederate's configured OP issuer (its base URL), which the workload must use as the
     * token-endpoint PoP audience. Read via PF's own {@code OAuthIssuerUtils} so it matches exactly what
     * the token endpoint expects; returns {@code null} if PF cannot resolve it (then the field is omitted
     * and the SDK falls back to the token endpoint URL).
     */
    private static String opIssuer(HttpServletRequest req) {
        try {
            String issuer = org.sourceid.oauth20.issuer.OAuthIssuerUtils.getInstance().getIssuerValue(req);
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
        String proto = firstForwardedValue(req.getHeader("X-Forwarded-Proto"));
        String host = firstForwardedValue(req.getHeader("X-Forwarded-Host"));
        String scheme = proto != null ? proto : req.getScheme();
        StringBuilder base = new StringBuilder(scheme).append("://");
        if (host != null) {
            base.append(host);
            // A forwarded host may already carry a port; only append X-Forwarded-Port if it does not.
            String port = firstForwardedValue(req.getHeader("X-Forwarded-Port"));
            if (port != null && !host.contains(":") && !isDefaultPort(scheme, port)) {
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

    /** Forwarded headers may be comma-joined lists (one hop per proxy); the first value is the client edge. */
    private static String firstForwardedValue(String header) {
        if (header == null || header.isBlank()) {
            return null;
        }
        int comma = header.indexOf(',');
        String value = comma < 0 ? header : header.substring(0, comma);
        String t = value.trim();
        return t.isEmpty() ? null : t;
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

    private static void applyCors(HttpServletResponse resp) {
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers", "Content-Type");
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
