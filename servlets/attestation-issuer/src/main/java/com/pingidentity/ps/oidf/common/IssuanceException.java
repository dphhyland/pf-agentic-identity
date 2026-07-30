/*
 * Typed failure for the attestation issuance endpoint.
 */
package com.pingidentity.ps.oidf.common;

/**
 * Carries a stable error code and HTTP status for a failed attestation-issuance request
 * ({@code /federation/attestation}). The endpoint renders these as a JSON body
 * {@code {"error":..,"error_description":..}} with the corresponding status, mirroring OAuth error
 * shape. (Distinct from {@link ClientAttestationException}, which models the AS-side <em>verification</em>
 * of an attestation; issuance is a separate protocol surface.)
 */
public final class IssuanceException extends Exception {
    private static final long serialVersionUID = 1L;

    private final String error;
    private final int status;

    public IssuanceException(String error, int status, String message) {
        super(message);
        this.error = error;
        this.status = status;
    }

    public String error() {
        return this.error;
    }

    public int status() {
        return this.status;
    }

    /** The request body is missing a required field or is otherwise malformed. */
    public static IssuanceException invalidRequest(String message) {
        return new IssuanceException("invalid_request", 400, message);
    }

    /** The named client is unknown, disabled, or not configured for attestation issuance. */
    public static IssuanceException invalidClient(String message) {
        return new IssuanceException("invalid_client", 400, message);
    }

    /** The presented SPIFFE JWT-SVID failed validation (signature, audience, expiry, trust domain). */
    public static IssuanceException invalidSvid(String message) {
        return new IssuanceException("invalid_svid", 401, message);
    }

    /**
     * A presented instance attestation of a non-SPIFFE format (e.g. a wallet Wallet Instance Attestation)
     * failed validation (signature, trust root, audience, expiry, key binding).
     */
    public static IssuanceException invalidInstanceAttestation(String message) {
        return new IssuanceException("invalid_instance_attestation", 401, message);
    }

    /** The instance-key proof of possession failed (bad signature, stale/missing challenge, replay). */
    public static IssuanceException invalidInstanceProof(String message) {
        return new IssuanceException("invalid_instance_proof", 401, message);
    }

    /** The validated SPIFFE ID is not bound to the requested client. */
    public static IssuanceException spiffeIdNotAuthorized(String message) {
        return new IssuanceException("spiffe_id_not_authorized", 403, message);
    }

    /** The validated instance (of a non-SPIFFE format) is not bound to the requested client. */
    public static IssuanceException instanceNotAuthorized(String message) {
        return new IssuanceException("instance_not_authorized", 403, message);
    }

    /** The requested authorization_details exceed the instance's entitlement ceiling. */
    public static IssuanceException accessDenied(String message) {
        return new IssuanceException("access_denied", 403, message);
    }

    /** A dependency needed to issue the attestation (e.g. the vault signer) is unavailable. */
    public static IssuanceException serverError(String message) {
        return new IssuanceException("server_error", 500, message);
    }
}
