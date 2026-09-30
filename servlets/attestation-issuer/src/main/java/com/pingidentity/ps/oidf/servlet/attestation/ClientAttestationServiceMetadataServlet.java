/*
 * Client Attestation Service discovery metadata endpoint (/.well-known/client-attestation-service).
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.clientattestation.ClientAttestationConfig;
import com.pingidentity.ps.oidf.platform.health.ComponentParts;
import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.pf.component.ComponentGate;
import com.pingidentity.ps.oidf.platform.pf.internals.PfInternals;
import com.pingidentity.ps.oidf.platform.pf.settings.InitParams;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidators;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jose4j.json.JsonUtil;

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
// loadOnStartup: its part of ATTESTATION_ISSUER registers at deploy, not on the first request (finding F-0193), so a
// setting its catalogue entry refuses is FAILED_CONFIG before anything is served; its init never throws.
@WebServlet(urlPatterns = {"/.well-known/client-attestation-service"}, loadOnStartup = 1)
public class ClientAttestationServiceMetadataServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static final String ATTESTATION_PATH = "/federation/attestation";
    /** The client attestation service's own challenge endpoint - never the authorization server's (CAS §4.1). */
    static final String CHALLENGE_PATH = AttestationIssuanceChallengeServlet.PATH;

    /** Request members every issuance request must carry ({@code svid} is the SPIFFE-era alias). */
    static final List<String> REQUEST_PARAMETERS_REQUIRED =
            List.of("client_id", "instance_key", "instance_attestation", "proof");
    /**
     * Proof claims the endpoint always enforces; {@code challenge} joins when the challenge is required. {@code iat}
     * and {@code exp} are required since S4c (CAS §4.3, which lists both as REQUIRED; InstanceKeyProofValidator).
     */
    static final List<String> PROOF_CLAIMS_REQUIRED = List.of("aud", "jti", "iat", "exp");
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

    /** This servlet's part of ATTESTATION_ISSUER, from init; null when a test's constructor made it and init never ran. */
    private transient volatile ComponentParts.Part part;

    /**
     * Registers the servlet's part of {@code ATTESTATION_ISSUER} and reads its settings, strictly, through the
     * attestation-issuer catalogue (plan item ST-5): a value an entry refuses leaves the part {@code FAILED_CONFIG},
     * naming the setting, and the document answers 503.
     */
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        ComponentParts.Part begun = Startup.begin(Startup.ATTESTATION_ISSUER, "ClientAttestationServiceMetadataServlet");
        this.part = begun;
        begun.start(() -> this.start(Settings.of(AttestationIssuanceServlet.SETTINGS).with(InitParams.sources(config))));
    }

    /** The start function: every setting read before any is kept. */
    void start(Settings settings) {
        boolean challengeRequired = settings.bool("challengeRequired");
        boolean challengeEndpointEnabled = settings.bool("challengeEndpointEnabled");
        Set<String> algs = settings.words("attestationSigningAlgValuesSupported");
        List<String> customClaimsRequired = AttestationIssuanceServlet.claims(settings, "OIDF_ATTESTATION_CUSTOM_CLAIMS_REQUIRED");
        List<String> customClaimsSupported = AttestationIssuanceServlet.claims(settings, "OIDF_ATTESTATION_CUSTOM_CLAIMS_SUPPORTED");
        settings.string("OIDF_CIMD_TRUST_BUNDLES");
        this.challengeRequired = challengeRequired;
        this.challengeEndpointEnabled = challengeEndpointEnabled;
        this.attestationSigningAlgs = List.copyOf(algs);
        this.customClaimsRequired = customClaimsRequired;
        this.customClaimsSupported = customClaimsSupported;
    }

    @Override
    protected void service(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        if (ComponentGate.servlet(this.part, resp)) {
            return;
        }
        super.service(req, resp);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        applyCors(resp);
        String issuer = PfInternals.issuer(req);
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
        return metadataSources(System::getProperty, System::getenv);
    }

    /**
     * As above, over the given property and environment reads. {@code cimd} is advertised only when
     * {@code OIDF_CIMD_TRUST_BUNDLES} is set and {@code OIDF_DEPLOYMENT_PROFILE=development}: under any other profile
     * the attester refuses the CIMD source (plan item M-1), and a document that still listed it would promise
     * clients a source they cannot be issued from.
     */
    static List<String> metadataSources(Function<String, String> props, Function<String, String> env) {
        List<String> sources = new ArrayList<>();
        String bundles = Settings.of(AttestationIssuanceServlet.SETTINGS).with(Sources.of(env, props, null))
                .string("OIDF_CIMD_TRUST_BUNDLES");
        if (bundles != null && DeploymentProfile.of(env).isDevelopment()) {
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

    private static void applyCors(HttpServletResponse resp) {
        resp.setHeader("Access-Control-Allow-Origin", "*");
        resp.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers", "Accept, Content-Type");
    }
}
