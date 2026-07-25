/*
 * Attestation issuance endpoint: a SPIFFE workload exchanges its JWT-SVID for a Client Attestation.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.AttesterClient;
import com.pingidentity.ps.oidf.common.AttestationMinter;
import com.pingidentity.ps.oidf.common.AttestationSupport;
import com.pingidentity.ps.oidf.common.AttesterSigningKey;
import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationException;
import com.pingidentity.ps.oidf.common.EvidenceValidator;
import com.pingidentity.ps.oidf.common.GcpSaTokenValidator;
import com.pingidentity.ps.oidf.common.GkeTokenValidator;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.IssuanceException;
import com.pingidentity.ps.oidf.common.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.PfMgmtClientStore;
import com.pingidentity.ps.oidf.common.RarEntitlement;
import com.pingidentity.ps.oidf.common.RemoteJwksCache;
import com.pingidentity.ps.oidf.common.SpiffeBinding;
import com.pingidentity.ps.oidf.common.SpiffeJwtEvidenceValidator;
import com.pingidentity.ps.oidf.common.SpireSelectorIntrospector;
import com.pingidentity.ps.oidf.common.WorkloadIntrospector;
import com.pingidentity.ps.oidf.common.SpiffeSvid;
import com.pingidentity.ps.oidf.common.SpiffeSvidValidator;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.JsonWebKey;

/**
 * Issues a Client Attestation to a workload that proves its identity with a SPIFFE JWT-SVID. A workload
 * that wants to act as an instance of a registered client {@code POST}s here with its {@code client_id},
 * its instance public JWK, its SVID, and a proof of possession of the instance key. The servlet resolves
 * the client's issuance config (attester key, SPIFFE trust bundle, one-to-many instance bindings),
 * validates the SVID against the bundle, checks the SPIFFE ID is bound to the client, verifies the
 * instance-key proof (with challenge/replay protection), enforces the RFC 9396 entitlement ceiling, and
 * mints a short-lived attestation signed with the client's per-client attester key
 * ({@link AttesterSigningKey}: OpenBao transit or inline JWK).
 *
 * <p>This is the <em>issuance</em> side only. The minted attestation is later presented by the workload
 * (with a fresh proof of possession) at the AS token endpoint via the existing client-authentication
 * path, which this servlet does not touch.
 *
 * <p>Response: {@code 200 {"attestation":"<jwt>","expires_in":N}} ({@code Cache-Control: no-store}); on
 * failure a JSON body {@code {"error":..,"error_description":..}} with a stable code and 4xx/5xx status.
 */
@WebServlet(urlPatterns = {"/federation/attestation"})
public class AttestationIssuanceServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;
    private static final Log LOGGER = LogFactory.getLog(AttestationIssuanceServlet.class);
    private static final long PROOF_REPLAY_TTL_SECONDS = ClientAttestationConfig.DEFAULT_POP_MAX_AGE_SECONDS;

    private volatile IssuanceClientResolver clientResolver;
    private volatile AttesterSigningKey attesterSigningKey;
    private volatile SpiffeSvidValidator svidValidator = new SpiffeSvidValidator();
    private volatile GkeTokenValidator gkeTokenValidator = new GkeTokenValidator();
    private volatile GcpSaTokenValidator gcpSaTokenValidator = new GcpSaTokenValidator();
    private volatile RemoteJwksCache jwksCache = new RemoteJwksCache();
    private volatile InstanceKeyProofValidator proofValidator = new InstanceKeyProofValidator();
    private volatile WorkloadIntrospector workloadIntrospector;
    private boolean challengeRequired;

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        this.challengeRequired = Boolean.parseBoolean(config.getInitParameter("challengeRequired"));
        String baoUrl = config.getInitParameter("openBaoUrl");
        String baoToken = config.getInitParameter("openBaoToken");
        if (baoUrl != null && baoToken != null) {
            this.attesterSigningKey = new AttesterSigningKey(baoUrl, baoToken);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        resp.setContentType("application/json");
        resp.setHeader("Cache-Control", "no-store");
        resp.setHeader("Pragma", "no-cache");
        try {
            IssuanceRequest request = parseRequest(req);
            Map<String, Object> body = issue(request);
            write(resp, 200, body);
        } catch (IssuanceException e) {
            if (e.status() >= 500) {
                LOGGER.warn((Object) ("Attestation issuance failed: " + e.error() + " - " + e.getMessage()), e);
            }
            write(resp, e.status(), error(e.error(), e.getMessage()));
        }
    }

    /**
     * Runs the issuance flow for a parsed request. Package-visible so tests can drive it directly with an
     * injected {@link IssuanceClientResolver} and {@link AttesterSigningKey}.
     */
    Map<String, Object> issue(IssuanceRequest request) throws IssuanceException {
        if (request.instanceKey == null || request.instanceKey.isEmpty()) {
            throw IssuanceException.invalidRequest("missing instance_key");
        }
        if (isBlank(request.svid)) {
            throw IssuanceException.invalidRequest("missing svid");
        }
        if (isBlank(request.proof)) {
            throw IssuanceException.invalidRequest("missing proof");
        }

        // 1-3. The workload names no client — it presents only its evidence. The attester reverse-maps
        //       the evidence's identity onto the client it is bound to: validate the evidence under each
        //       attestation client's trust config, and the one whose bundle verifies it AND whose bindings
        //       contain the resulting SPIFFE ID is the match. Which client an identity belongs to is the
        //       attester's knowledge alone.
        Match match = resolveByEvidence(request.svid);
        AttestationIssuanceConfig config = match.config;
        SpiffeSvid svid = match.svid;
        SpiffeBinding binding = match.binding;
        String clientId = match.clientId;

        // 4. Prove the caller holds the instance key it asks to bind, with freshness + replay protection.
        InstanceKeyProofValidator.Result proof =
                this.proofValidator.validate(request.proof, request.instanceKey, config.issuer());
        if (proof.challenge() != null && !proof.challenge().isBlank()) {
            if (!AttestationSupport.challengeService().consume(proof.challenge())) {
                throw IssuanceException.invalidInstanceProof("challenge is unknown, expired, or already used");
            }
        } else if (this.challengeRequired) {
            throw IssuanceException.invalidInstanceProof("a server-issued challenge is required");
        }
        if (!AttestationSupport.replayCache().firstSeen(clientId, proof.jti(), PROOF_REPLAY_TTL_SECONDS)) {
            throw IssuanceException.invalidInstanceProof("proof jti has already been used (replay)");
        }

        // 5. Introspect the workload beyond the bare SVID — SPIRE registration selectors, etc. — and
        //    merge those attributes over the binding's declared metadata. These ride into the attestation
        //    and are available to the issuance policy for downscoping.
        Map<String, Object> workloadAttributes = new LinkedHashMap<>(binding.metadata());
        Map<String, Object> introspected = workloadIntrospector().introspect(svid);
        if (introspected != null) {
            workloadAttributes.putAll(introspected);
        }

        // 6. Resolve the granted entitlement against the effective ceiling, then apply any
        //    selector-conditioned downscoping the policy requires.
        List<Map<String, Object>> ceiling = config.effectiveCeiling(binding);
        List<Map<String, Object>> granted;
        if (!request.requestedDetails.isEmpty()) {
            try {
                granted = RarEntitlement.authorize(request.requestedDetails, ceiling);
            } catch (ClientAttestationException e) {
                throw mapEntitlementError(e);
            }
        } else {
            granted = ceiling;
        }

        // 7. Mint + sign with the attester key. The attester assigns the client_id (the attestation sub);
        //    the workload learns it only from the attestation it receives back.
        JwsSigner signer = attesterSigningKey().signerFor(config.signingKeyRef(), config.signingJwk());
        String attestation = AttestationMinter.mint(config.issuer(), clientId, request.instanceKey,
                svid, workloadAttributes, granted, config.ttlSeconds(), signer);

        LOGGER.info((Object) ("Issued client attestation: client_id=" + clientId
                + " spiffe_id=" + svid.spiffeId() + " ttl=" + config.ttlSeconds() + "s"));
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("attestation", attestation);
        body.put("expires_in", config.ttlSeconds());
        return body;
    }

    // ---- seams for tests / runtime defaults -------------------------------------------------------

    void setClientResolver(IssuanceClientResolver resolver) {
        this.clientResolver = resolver;
    }

    void setAttesterSigningKey(AttesterSigningKey key) {
        this.attesterSigningKey = key;
    }

    void setChallengeRequired(boolean required) {
        this.challengeRequired = required;
    }

    void setGkeTokenValidator(GkeTokenValidator validator) {
        this.gkeTokenValidator = validator;
    }

    void setJwksCache(RemoteJwksCache cache) {
        this.jwksCache = cache;
    }

    RemoteJwksCache jwksCache() {
        return this.jwksCache;
    }

    void setWorkloadIntrospector(WorkloadIntrospector introspector) {
        this.workloadIntrospector = introspector;
    }

    /**
     * The workload introspector — a SPIRE selector lookup if {@code oidf.attester.spire.entries.url}
     * (env {@code OIDF_ATTESTER_SPIRE_ENTRIES_URL}) is set, else a no-op. Lazily initialized so tests can
     * inject one and the runtime path needs no live SPIRE by default.
     */
    WorkloadIntrospector workloadIntrospector() {
        WorkloadIntrospector local = this.workloadIntrospector;
        if (local == null) {
            synchronized (this) {
                if (this.workloadIntrospector == null) {
                    this.workloadIntrospector = defaultWorkloadIntrospector();
                }
                local = this.workloadIntrospector;
            }
        }
        return local;
    }

    protected WorkloadIntrospector defaultWorkloadIntrospector() {
        String url = System.getProperty("oidf.attester.spire.entries.url");
        if (url == null || url.isBlank()) {
            url = System.getenv("OIDF_ATTESTER_SPIRE_ENTRIES_URL");
        }
        if (url != null && !url.isBlank()) {
            LOGGER.info((Object) ("Workload introspection via SPIRE entries endpoint: " + url));
            return new SpireSelectorIntrospector(url.trim());
        }
        return WorkloadIntrospector.none();
    }

    /** The validator for the client's configured evidence type. */
    private EvidenceValidator evidenceValidator(AttestationIssuanceConfig config) {
        if (AttestationIssuanceConfig.EVIDENCE_GKE_SA_TOKEN.equals(config.evidenceType())) {
            return this.gkeTokenValidator;
        }
        if (AttestationIssuanceConfig.EVIDENCE_GCP_ID_TOKEN.equals(config.evidenceType())) {
            return this.gcpSaTokenValidator;
        }
        return new SpiffeJwtEvidenceValidator(this.svidValidator);
    }

    /** The attester's private mapping: evidence identity → the client it is bound to. */
    private static final class Match {
        final String clientId;
        final AttestationIssuanceConfig config;
        final SpiffeSvid svid;
        final SpiffeBinding binding;

        Match(String clientId, AttestationIssuanceConfig config, SpiffeSvid svid, SpiffeBinding binding) {
            this.clientId = clientId;
            this.config = config;
            this.svid = svid;
            this.binding = binding;
        }
    }

    /**
     * Reverse-maps a workload's evidence onto the client it is bound to. Tries each attestation client's
     * trust config: the client whose bundle cryptographically verifies the evidence AND whose bindings
     * contain the resolved SPIFFE ID is the match. A SPIFFE ID bound to two clients is a configuration
     * error and is rejected rather than resolved arbitrarily.
     */
    private Match resolveByEvidence(String evidence) throws IssuanceException {
        List<AttesterClient> clients = clientResolver().attestationClients();
        if (clients.isEmpty()) {
            throw IssuanceException.invalidClient("no attestation clients are configured");
        }
        Match match = null;
        boolean anyValidated = false;
        IssuanceException deferredServerError = null;
        for (AttesterClient candidate : clients) {
            AttestationIssuanceConfig config = candidate.config();
            List<JsonWebKey> bundleKeys;
            SpiffeSvid svid;
            try {
                bundleKeys = config.bundleUrl() != null ? jwksCache().get(config.bundleUrl()) : config.bundleKeys();
                svid = evidenceValidator(config).validate(evidence, bundleKeys, config);
            } catch (IssuanceException e) {
                // A 5xx (e.g. the trust bundle could not be fetched) is an attester-side fault, not
                // "bad evidence" — remember it and surface it only if nothing else matches.
                if (e.status() >= 500) {
                    deferredServerError = e;
                }
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug((Object) ("evidence rejected by client " + candidate.clientId()
                            + " [" + config.evidenceType() + "]: " + e.error() + " " + e.getMessage()));
                }
                // Otherwise this client's trust config simply does not accept the evidence — try the next.
                continue;
            }
            anyValidated = true;
            SpiffeBinding binding = config.bindingFor(svid.spiffeId()).orElse(null);
            if (binding == null) {
                continue;
            }
            if (match != null) {
                throw IssuanceException.invalidClient(
                        "SPIFFE ID is bound to more than one client: " + svid.spiffeId());
            }
            match = new Match(candidate.clientId(), config, svid, binding);
        }
        if (match != null) {
            return match;
        }
        if (anyValidated) {
            throw IssuanceException.spiffeIdNotAuthorized("evidence identity is not registered with any client");
        }
        if (deferredServerError != null) {
            throw deferredServerError;
        }
        throw IssuanceException.invalidSvid("no attester client accepts this evidence");
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

    /**
     * The runtime default resolver. If the system property {@code oidf.attester.cimd.url} is set, the
     * attester's SPIFFE-ID → client mapping is read from that Client ID Metadata Document; otherwise it
     * reads clients from PingFederate's management store. Overridable so tests bypass both.
     */
    protected IssuanceClientResolver defaultClientResolver() {
        return AttesterResolvers.fromEnvironment();
    }

    private AttesterSigningKey attesterSigningKey() {
        AttesterSigningKey local = this.attesterSigningKey;
        if (local == null) {
            synchronized (this) {
                if (this.attesterSigningKey == null) {
                    this.attesterSigningKey = AttesterSigningKey.fromEnvironment();
                }
                local = this.attesterSigningKey;
            }
        }
        return local;
    }

    private static IssuanceException mapEntitlementError(ClientAttestationException e) {
        if (ClientAttestationException.ACCESS_DENIED.equals(e.error())) {
            return IssuanceException.accessDenied(e.getMessage());
        }
        return IssuanceException.invalidRequest(e.getMessage());
    }

    // ---- request parsing --------------------------------------------------------------------------

    private static IssuanceRequest parseRequest(HttpServletRequest req) throws IssuanceException {
        Map<String, Object> json;
        try {
            byte[] raw = req.getInputStream().readAllBytes();
            json = JsonUtil.parseJson(new String(raw, StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw IssuanceException.invalidRequest("request body is not valid JSON");
        }
        IssuanceRequest request = new IssuanceRequest();
        request.clientId = asString(json.get("client_id"));
        request.instanceKey = asObject(json.get("instance_key"));
        request.svid = asString(json.get("svid"));
        request.proof = asString(json.get("proof"));
        request.requestedDetails = asObjectList(json.get("authorization_details"));
        return request;
    }

    private static String asString(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asObject(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> asObjectList(Object value) throws IssuanceException {
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List)) {
            throw IssuanceException.invalidRequest("authorization_details must be a JSON array");
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Object item : (List<?>) value) {
            if (!(item instanceof Map)) {
                throw IssuanceException.invalidRequest("each authorization_details entry must be a JSON object");
            }
            out.add((Map<String, Object>) item);
        }
        return out;
    }

    private static Map<String, Object> error(String code, String description) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", code);
        if (description != null) {
            body.put("error_description", description);
        }
        return body;
    }

    private static void write(HttpServletResponse resp, int status, Map<String, Object> body) throws IOException {
        resp.setStatus(status);
        try (PrintWriter out = resp.getWriter()) {
            out.write(JsonUtil.toJson(body));
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    /** Parsed issuance request. */
    static final class IssuanceRequest {
        String clientId;
        Map<String, Object> instanceKey;
        String svid;
        String proof;
        List<Map<String, Object>> requestedDetails = List.of();
    }
}
