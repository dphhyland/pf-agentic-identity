/*
 * A failure to verify an App Attest attestation or assertion.
 */
package com.pingidentity.ps.oidf.appattest;

/**
 * Signals that an App Attest object did not verify. Carries a stable {@code reason} code so callers can
 * emit a distinct audit event per failure mode rather than a single opaque "attestation rejected" —
 * without that, a rejected enrolment is undiagnosable in production.
 *
 * <p>The reason codes are deliberately fine-grained and stable; treat them as part of this library's
 * contract.
 */
public class AppAttestException extends Exception {
    private static final long serialVersionUID = 1L;

    /** The attestation object was not well-formed CBOR, or was missing a required member. */
    public static final String MALFORMED = "malformed_attestation";
    /** {@code fmt} was not {@code apple-appattest}. */
    public static final String UNSUPPORTED_FORMAT = "unsupported_format";
    /** The x5c chain did not validate to Apple's App Attestation Root CA. */
    public static final String UNTRUSTED_CHAIN = "untrusted_certificate_chain";
    /** The credCert carried no nonce extension, or it did not match SHA-256(authData ‖ clientDataHash). */
    public static final String NONCE_MISMATCH = "nonce_mismatch";
    /** SHA-256 of the attested public key did not equal the credential id / key id. */
    public static final String KEY_ID_MISMATCH = "key_id_mismatch";
    /** {@code rpIdHash} did not equal SHA-256 of the configured App ID. */
    public static final String APP_ID_MISMATCH = "app_id_mismatch";
    /**
     * The aaguid names an environment this verifier is not configured to accept — in practice, a
     * development attestation reaching a production verifier.
     */
    public static final String ENVIRONMENT_NOT_ACCEPTED = "environment_not_accepted";
    /** The attestation's signature counter was not zero, so this is not a fresh attestation. */
    public static final String BAD_COUNTER = "bad_counter";
    /** An assertion's signature did not verify under the previously attested public key. */
    public static final String BAD_SIGNATURE = "bad_signature";
    /** An assertion's counter did not advance, which is a replay. */
    public static final String COUNTER_NOT_ADVANCED = "counter_not_advanced";

    private final String reason;

    public AppAttestException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public AppAttestException(String reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    /** The stable failure code — log this, and branch audit events on it. */
    public String reason() {
        return this.reason;
    }
}
