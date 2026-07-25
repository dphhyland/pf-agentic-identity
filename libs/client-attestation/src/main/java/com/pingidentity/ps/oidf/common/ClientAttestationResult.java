/*
 * Successful result of attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.common;

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
        this.clientId = clientId;
        this.cnfJwk = cnfJwk;
        this.mode = mode;
        this.attesterIssuer = attesterIssuer;
        this.proofJti = proofJti;
        this.entitledAuthorizationDetails = entitledAuthorizationDetails;
        this.grantedAuthorizationDetails = grantedAuthorizationDetails;
        this.workload = workload == null ? java.util.Map.of() : workload;
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

    /** The requested {@code authorization_details} that were authorized against the entitlement; empty if none requested. */
    public List<Map<String, Object>> grantedAuthorizationDetails() {
        return this.grantedAuthorizationDetails;
    }

    /**
     * The attestation's {@code workload} claim — how the platform attested the caller: its SPIFFE ID,
     * the attestor, and any introspected attributes (SPIRE selectors). Empty if the attestation carried
     * none. This is what lets an issued access token name the workload behind the client.
     */
    public Map<String, Object> workload() {
        return this.workload;
    }
}
