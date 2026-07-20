/*
 * Attestation issuance endpoint: a SPIFFE workload exchanges its JWT-SVID for a Client Attestation.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.common.AttestationIssuanceConfig;
import com.pingidentity.ps.oidf.common.AttestationMinter;
import com.pingidentity.ps.oidf.common.AttestationSupport;
import com.pingidentity.ps.oidf.common.AttesterSigningKey;
import com.pingidentity.ps.oidf.common.ClientAttestationConfig;
import com.pingidentity.ps.oidf.common.ClientAttestationException;
import com.pingidentity.ps.oidf.common.IssuanceClientResolver;
import com.pingidentity.ps.oidf.common.IssuanceException;
import com.pingidentity.ps.oidf.common.InstanceKeyProofValidator;
import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.PfMgmtClientStore;
import com.pingidentity.ps.oidf.common.RarEntitlement;
import com.pingidentity.ps.oidf.common.SpiffeBinding;
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
    private volatile InstanceKeyProofValidator proofValidator = new InstanceKeyProofValidator();
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
        if (isBlank(request.clientId)) {
            throw IssuanceException.invalidRequest("missing client_id");
        }
        if (request.instanceKey == null || request.instanceKey.isEmpty()) {
            throw IssuanceException.invalidRequest("missing instance_key");
        }
        if (isBlank(request.svid)) {
            throw IssuanceException.invalidRequest("missing svid");
        }
        if (isBlank(request.proof)) {
            throw IssuanceException.invalidRequest("missing proof");
        }

        // 1. Load the client + status gate; parse its issuance config (bundle source seam).
        AttestationIssuanceConfig config = clientResolver().resolve(request.clientId);

        // 2. Validate the SVID against the client's SPIFFE trust bundle.
        SpiffeSvid svid = this.svidValidator.validate(
                request.svid, config.bundleKeys(), config.issuer(), config.expectedTrustDomain());

        // 3. The SPIFFE ID must be one bound to this client.
        SpiffeBinding binding = config.bindingFor(svid.spiffeId()).orElseThrow(
                () -> IssuanceException.spiffeIdNotAuthorized(
                        "SPIFFE ID is not registered for this client: " + svid.spiffeId()));

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
        if (!AttestationSupport.replayCache().firstSeen(request.clientId, proof.jti(), PROOF_REPLAY_TTL_SECONDS)) {
            throw IssuanceException.invalidInstanceProof("proof jti has already been used (replay)");
        }

        // 5. Resolve the granted entitlement against the effective ceiling.
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

        // 6. Mint + sign with the per-client attester key.
        JwsSigner signer = attesterSigningKey().signerFor(config.signingKeyRef(), config.signingJwk());
        String attestation = AttestationMinter.mint(config.issuer(), request.clientId, request.instanceKey,
                svid, binding.metadata(), granted, config.ttlSeconds(), signer);

        LOGGER.info((Object) ("Issued client attestation: client_id=" + request.clientId
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

    private IssuanceClientResolver clientResolver() {
        IssuanceClientResolver local = this.clientResolver;
        if (local == null) {
            synchronized (this) {
                if (this.clientResolver == null) {
                    this.clientResolver = new PfIssuanceClientResolver(new PfMgmtClientStore());
                }
                local = this.clientResolver;
            }
        }
        return local;
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
