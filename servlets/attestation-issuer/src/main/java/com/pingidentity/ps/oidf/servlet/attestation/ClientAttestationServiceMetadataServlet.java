/*
 * Client Attestation Service discovery metadata endpoint (/.well-known/client-attestation-service).
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;
import org.sourceid.oauth20.issuer.OAuthIssuerUtils;

/**
 * Serves the {@code openid-client-attestation-service-1_0} discovery document at
 * {@code /.well-known/client-attestation-service} (see {@code docs/openid-client-attestation-service-1_0.md}
 * §5). A workload (or the tooling that provisions it) reads this to discover the issuance and challenge
 * endpoints and — the heart of the document — the <em>claim contract</em> for minting: which request
 * members are required, which claims the instance-key proof must carry (the default set plus any
 * deployment-required custom claims), and which claims the minted attestation will contain.
 *
 * <p>This is deliberately a separate, spec-conformant document from {@link AttesterConfigurationServlet}'s
 * {@code /.well-known/client-attester} — that document is this deployment's own richer discovery surface
 * (resolver plugins, per-client configuration, PoP audience); this one is the fixed CAS 1.0 shape a
 * generic conformant client can rely on across deployments.
 *
 * <p>The claim lists mirror what {@link AttestationIssuanceServlet} actually enforces: the default proof
 * claims ({@code aud}, {@code jti}, plus {@code challenge} when required) are fixed by the endpoint, while
 * {@code custom_claims_required} comes from the same configuration the issuance servlet enforces
 * ({@code customClaimsRequired} init-param / {@code OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED}), so the
 * advertisement and the enforcement cannot drift apart.
 */
@WebServlet(urlPatterns = {"/.well-known/client-attestation-service"})
public class ClientAttestationServiceMetadataServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static final String ATTESTATION_PATH = "/federation/attestation";
    static final String CHALLENGE_PATH = "/federation/attestation-challenge";

    /** Request members every issuance request must carry ({@code svid} is the SPIFFE-era alias). */
    static final List<String> REQUEST_PARAMETERS_REQUIRED =
            List.of("client_id", "instance_key", "instance_attestation", "proof");
    /** Proof claims the endpoint always enforces; {@code challenge} joins when the challenge is required. */
    static final List<String> PROOF_CLAIMS_REQUIRED = List.of("aud", "jti");
    /** Claims minted into every issued attestation. */
    static final List<String> ATTESTATION_CLAIMS_ISSUED =
            List.of("iss", "sub", "iat", "exp", "cnf", "workload");
    /** Claims minted only when applicable (an entitlement was granted). */
    static final List<String> ATTESTATION_CLAIMS_OPTIONAL = List.of("authorization_details");

    private static final List<String> DEFAULT_ATTESTATION_ALGS = List.of("RS256", "PS256", "ES256");

    private boolean challengeRequired;
    private boolean challengeEndpointEnabled = true;
    private List<String> attestationSigningAlgs = DEFAULT_ATTESTATION_ALGS;
    private List<String> customClaimsRequired = List.of();
    private List<String> customClaimsSupported = List.of();
    private volatile InstanceAttestationValidators instanceValidators;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.challengeRequired = Boolean.parseBoolean(config.getInitParameter("challengeRequired"));
        this.challengeEndpointEnabled = parseBoolean(config.getInitParameter("challengeEndpointEnabled"), true);
        this.attestationSigningAlgs =
                parseList(config.getInitParameter("attestationSigningAlgValuesSupported"), DEFAULT_ATTESTATION_ALGS);
        this.customClaimsRequired = AttestationIssuanceServlet.customClaimsFrom(
                config.getInitParameter("customClaimsRequired"),
                "oidf.attestation.custom.claims.required", "OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED");
        this.customClaimsSupported = AttestationIssuanceServlet.customClaimsFrom(
                config.getInitParameter("customClaimsSupported"),
                "oidf.attestation.custom.claims.supported", "OIDF_ATTESTATION_CUSTOM_CLAIMS_SUPPORTED");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        applyCors(resp);
        String issuer = OAuthIssuerUtils.getInstance().getIssuerValue(req);
        resp.setStatus(200);
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "public, max-age=3600");
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(metadata(issuer)));
        }
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) {
        applyCors(resp);
        resp.setStatus(204);
    }

    /** Builds the metadata document for the given externally-visible issuer base URL. */
    Map<String, Object> metadata(String issuer) {
        LinkedHashMap<String, Object> m = new LinkedHashMap<>();
        m.put("issuer", issuer);
        m.put("attestation_endpoint", issuer + ATTESTATION_PATH);
        if (this.challengeEndpointEnabled) {
            m.put("challenge_endpoint", issuer + CHALLENGE_PATH);
        }
        m.put("challenge_required", this.challengeRequired);
        m.put("instance_attestation_formats_supported", instanceValidators().formats());
        m.put("client_metadata_sources_supported", metadataSources());
        m.put("attestation_signing_alg_values_supported", this.attestationSigningAlgs);
        m.put("proof_signing_alg_values_supported",
                ClientAttestationConfig.DEFAULT_ASYMMETRIC_ALGORITHMS.stream().sorted().toList());
        m.put("request_parameters_required", REQUEST_PARAMETERS_REQUIRED);
        List<String> proofClaims = new ArrayList<>(PROOF_CLAIMS_REQUIRED);
        if (this.challengeRequired) {
            proofClaims.add("challenge");
        }
        m.put("proof_claims_required", List.copyOf(proofClaims));
        m.put("attestation_claims_issued", ATTESTATION_CLAIMS_ISSUED);
        m.put("attestation_claims_optional", ATTESTATION_CLAIMS_OPTIONAL);
        if (!this.customClaimsRequired.isEmpty()) {
            m.put("custom_claims_required", this.customClaimsRequired);
        }
        if (!this.customClaimsSupported.isEmpty()) {
            m.put("custom_claims_supported", this.customClaimsSupported);
        }
        m.put("narrowing_behavior", "reject");
        return m;
    }

    /** Client metadata sources in assurance order, mirroring the issuance servlet's composite resolver. */
    private static List<String> metadataSources() {
        List<String> sources = new ArrayList<>();
        if (AttestationIssuanceServlet.env("oidf.cimd.trust.bundles", "OIDF_CIMD_TRUST_BUNDLES") != null) {
            sources.add("cimd");
        }
        sources.add("registration");
        return List.copyOf(sources);
    }

    // ---- seams for tests / runtime defaults -------------------------------------------------------

    void setInstanceValidators(InstanceAttestationValidators validators) {
        this.instanceValidators = validators;
    }

    InstanceAttestationValidators instanceValidators() {
        InstanceAttestationValidators local = this.instanceValidators;
        if (local == null) {
            synchronized (this) {
                if (this.instanceValidators == null) {
                    this.instanceValidators = defaultInstanceValidators();
                }
                local = this.instanceValidators;
            }
        }
        return local;
    }

    /** The same format wiring as the issuance endpoint: every built-in type, plus wallet when configured. */
    private static InstanceAttestationValidators defaultInstanceValidators() {
        InstanceAttestationValidators registry = InstanceAttestationValidators.defaults();
        InstanceAttestationValidator wallet = AttestationIssuanceServlet.walletValidatorFromEnv();
        if (wallet != null) {
            registry = registry.with(wallet);
        }
        return registry;
    }

    private static List<String> parseList(String value, List<String> fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        List<String> out = new ArrayList<>();
        for (String token : value.split(",")) {
            String trimmed = token.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
        return out.isEmpty() ? fallback : List.copyOf(out);
    }

    private static boolean parseBoolean(String value, boolean fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        return Boolean.parseBoolean(value.trim());
    }

    private static void applyCors(HttpServletResponse resp) {
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers", "Accept, Content-Type");
    }
}
