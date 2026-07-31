/*
 * An enrolment or re-issuance was refused.
 */
package com.pingidentity.ps.oidf.enrolment;

/**
 * Signals a refusal, with a stable {@code error} code and an HTTP status.
 *
 * <p>Every distinct refusal has its own code. "Access denied" with no reason makes a production
 * incident undiagnosable, and this flow has a lot of ways to fail legitimately — a stale challenge, a
 * development attestation on a production verifier, a device out of compliance, a user verification
 * that has aged out. The client needs to tell them apart too: {@link #USER_VERIFICATION_REQUIRED} is
 * the one it can actually recover from, by putting the human back in front of the phone.
 */
public class EnrolmentException extends Exception {
    private static final long serialVersionUID = 1L;

    /** Malformed or incomplete request. */
    public static final String INVALID_REQUEST = "invalid_request";
    /** The challenge was never issued, has expired, or has already been used. */
    public static final String INVALID_CHALLENGE = "invalid_challenge";
    /** The App Attest object did not verify. */
    public static final String INVALID_ATTESTATION = "invalid_attestation";
    /** The human's authentication could not be verified. */
    public static final String USER_AUTHENTICATION_FAILED = "user_authentication_failed";
    /** Authentication succeeded but below the assurance required to bind a signing key. */
    public static final String INSUFFICIENT_ASSURANCE = "insufficient_assurance";
    /** The Secure Enclave key proof did not verify, or was replayed. */
    public static final String INVALID_KEY_PROOF = "invalid_key_proof";
    /** No such instance. */
    public static final String UNKNOWN_INSTANCE = "unknown_instance";
    /** The instance is suspended or revoked. */
    public static final String INSTANCE_NOT_ACTIVE = "instance_not_active";
    /** The device is not compliant, or has never been assessed. */
    public static final String DEVICE_NOT_COMPLIANT = "device_not_compliant";
    /**
     * User verification has aged out. The recoverable one: the client should re-authenticate the owner
     * and retry. This is the server-side time-box firing.
     */
    public static final String USER_VERIFICATION_REQUIRED = "user_verification_required";
    /** A dependency failed. */
    public static final String SERVER_ERROR = "server_error";

    private final String error;
    private final int status;

    public EnrolmentException(String error, int status, String message) {
        super(message);
        this.error = error;
        this.status = status;
    }

    public EnrolmentException(String error, int status, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
        this.status = status;
    }

    public String error() {
        return this.error;
    }

    public int status() {
        return this.status;
    }

    public static EnrolmentException invalidRequest(String message) {
        return new EnrolmentException(INVALID_REQUEST, 400, message);
    }

    public static EnrolmentException invalidChallenge(String message) {
        return new EnrolmentException(INVALID_CHALLENGE, 400, message);
    }

    public static EnrolmentException invalidAttestation(String message) {
        return new EnrolmentException(INVALID_ATTESTATION, 401, message);
    }

    public static EnrolmentException userAuthenticationFailed(String message) {
        return new EnrolmentException(USER_AUTHENTICATION_FAILED, 401, message);
    }

    public static EnrolmentException insufficientAssurance(String message) {
        return new EnrolmentException(INSUFFICIENT_ASSURANCE, 403, message);
    }

    public static EnrolmentException invalidKeyProof(String message) {
        return new EnrolmentException(INVALID_KEY_PROOF, 401, message);
    }

    public static EnrolmentException unknownInstance(String message) {
        return new EnrolmentException(UNKNOWN_INSTANCE, 404, message);
    }

    public static EnrolmentException instanceNotActive(String message) {
        return new EnrolmentException(INSTANCE_NOT_ACTIVE, 403, message);
    }

    public static EnrolmentException deviceNotCompliant(String message) {
        return new EnrolmentException(DEVICE_NOT_COMPLIANT, 403, message);
    }

    public static EnrolmentException userVerificationRequired(String message) {
        return new EnrolmentException(USER_VERIFICATION_REQUIRED, 401, message);
    }

    public static EnrolmentException serverError(String message, Throwable cause) {
        return new EnrolmentException(SERVER_ERROR, 500, message, cause);
    }
}
