/*
 * Successful result of attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.util.List;
import java.util.Map;

/**
 * Outcome of a successful {@link ClientAttestationVerifier} run: the authenticated {@code client_id},
 * the confirmed instance key ({@code cnf.jwk}), the proof-of-possession mode that was used and the
 * trusted Attester that issued the attestation.
 */
public final class ClientAttestationResult {
    public enum Mode {
        /** Dedicated Client Attestation PoP JWT ({@code attest_jwt_client_auth}). */
        POP_JWT,
        /** DPoP combined mode (PoP method {@code dpop_combined}). */
        DPOP
    }

    private final String clientId;
    private final Map<String, Object> cnfJwk;
    private final Mode mode;
    private final String attesterIssuer;
    private final String proofJti;
    private final List<Map<String, Object>> entitledAuthorizationDetails;
    private final List<Map<String, Object>> grantedAuthorizationDetails;
    private final Map<String, Object> workload;
    private final String agentId;
    private final String rarModelsFingerprint;

    public ClientAttestationResult(String clientId, Map<String, Object> cnfJwk, Mode mode, String attesterIssuer, String proofJti) {
        this(clientId, cnfJwk, mode, attesterIssuer, proofJti, java.util.List.of(), java.util.List.of(), java.util.Map.of());
    }

    public ClientAttestationResult(String clientId, Map<String, Object> cnfJwk, Mode mode, String attesterIssuer, String proofJti,
                                   List<Map<String, Object>> entitledAuthorizationDetails,
                                   List<Map<String, Object>> grantedAuthorizationDetails) {
        this(clientId, cnfJwk, mode, attesterIssuer, proofJti, entitledAuthorizationDetails,
                grantedAuthorizationDetails, java.util.Map.of());
    }

    public ClientAttestationResult(String clientId, Map<String, Object> cnfJwk, Mode mode, String attesterIssuer, String proofJti,
                                   List<Map<String, Object>> entitledAuthorizationDetails,
                                   List<Map<String, Object>> grantedAuthorizationDetails,
                                   Map<String, Object> workload) {
        this(clientId, cnfJwk, mode, attesterIssuer, proofJti, entitledAuthorizationDetails,
                grantedAuthorizationDetails, workload, null);
    }

    /**
     * @param agentId the attester-minted {@code agent_id} (Phase 2.6), or {@code null} if the
     *                attestation carried none — see {@link ClientAttestation}'s own javadoc: never a
     *                substitute for {@code clientId} anywhere this is consumed
     */
    public ClientAttestationResult(String clientId, Map<String, Object> cnfJwk, Mode mode, String attesterIssuer, String proofJti,
                                   List<Map<String, Object>> entitledAuthorizationDetails,
                                   List<Map<String, Object>> grantedAuthorizationDetails,
                                   Map<String, Object> workload, String agentId) {
        this(clientId, cnfJwk, mode, attesterIssuer, proofJti, entitledAuthorizationDetails,
                grantedAuthorizationDetails, workload, agentId, null);
    }

    /**
     * @param rarModelsFingerprint the {@code RarModels.fingerprint()} of the model set that checked the request's
     *                             {@code authorization_details}, or {@code null} for a result no model checked
     */
    public ClientAttestationResult(String clientId, Map<String, Object> cnfJwk, Mode mode, String attesterIssuer, String proofJti,
                                   List<Map<String, Object>> entitledAuthorizationDetails,
                                   List<Map<String, Object>> grantedAuthorizationDetails,
                                   Map<String, Object> workload, String agentId, String rarModelsFingerprint) {
        this.clientId = clientId;
        this.cnfJwk = cnfJwk;
        this.mode = mode;
        this.attesterIssuer = attesterIssuer;
        this.proofJti = proofJti;
        this.entitledAuthorizationDetails = entitledAuthorizationDetails;
        this.grantedAuthorizationDetails = grantedAuthorizationDetails;
        this.workload = workload == null ? java.util.Map.of() : workload;
        this.agentId = agentId;
        this.rarModelsFingerprint = rarModelsFingerprint;
    }

    public String clientId() {
        return this.clientId;
    }

    public Map<String, Object> cnfJwk() {
        return this.cnfJwk;
    }

    public Mode mode() {
        return this.mode;
    }

    public String attesterIssuer() {
        return this.attesterIssuer;
    }

    public String proofJti() {
        return this.proofJti;
    }

    /** The entitlement the attestation asserts (RFC 9396 {@code authorization_details}); empty if none. */
    public List<Map<String, Object>> entitledAuthorizationDetails() {
        return this.entitledAuthorizationDetails;
    }

    /**
     * The request's {@code authorization_details} that were found within the attestation's: the request's own,
     * without the {@code _principal_sub} and {@code _agent_id} markers; empty if none were requested.
     */
    public List<Map<String, Object>> grantedAuthorizationDetails() {
        return this.grantedAuthorizationDetails;
    }

    /**
     * SHA-256, lower-case hex, of the model set that checked the request's {@code authorization_details}
     * ({@code RarModels.fingerprint()}), or {@code null} when no model checked this result. The RAR plugin compares
     * it with its own.
     */
    public String rarModelsFingerprint() {
        return this.rarModelsFingerprint;
    }

    /**
     * The attestation's {@code workload} claim — how the platform attested the caller: its SPIFFE ID,
     * the attestor, and any introspected attributes (SPIRE selectors). Empty if the attestation carried
     * none. This is what lets an issued access token name the workload behind the client.
     */
    public Map<String, Object> workload() {
        return this.workload;
    }

    /** The attester-minted {@code agent_id}, or {@code null} if the attestation carried none. */
    public String agentId() {
        return this.agentId;
    }
}
