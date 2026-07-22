/*
 * Typed failure for attestation-based client authentication.
 */
package com.pingidentity.ps.oidf.common;

/**
 * Carries the OAuth error code that a failed attestation verification maps to, per
 * draft-ietf-oauth-attestation-based-client-auth Section 7. Most failures are {@code invalid_client};
 * {@code use_attestation_challenge} and {@code use_fresh_attestation} signal that the client should
 * retry with a server-provided challenge / a freshly issued attestation respectively.
 */
public final class ClientAttestationException extends Exception {
    private static final long serialVersionUID = 1L;
    public static final String INVALID_CLIENT = "invalid_client";
    public static final String USE_ATTESTATION_CHALLENGE = "use_attestation_challenge";
    public static final String USE_FRESH_ATTESTATION = "use_fresh_attestation";
    /** RFC 9396 §5: the requested authorization_details is malformed or of an unknown type. */
    public static final String INVALID_AUTHORIZATION_DETAILS = "invalid_authorization_details";
    /** The request is well-formed but exceeds what the attestation entitles the client to. */
    public static final String ACCESS_DENIED = "access_denied";
    /** The presentation omits a claim this AS requires to be disclosed (federation-gated disclosure). */
    public static final String INSUFFICIENT_DISCLOSURE = "insufficient_disclosure";

    private final String error;

    public ClientAttestationException(String error, String message) {
        super(message);
        this.error = error;
    }

    public ClientAttestationException(String error, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
    }

    public String error() {
        return this.error;
    }

    public static ClientAttestationException invalidClient(String message) {
        return new ClientAttestationException(INVALID_CLIENT, message);
    }

    public static ClientAttestationException invalidClient(String message, Throwable cause) {
        return new ClientAttestationException(INVALID_CLIENT, message, cause);
    }

    public static ClientAttestationException useChallenge(String message) {
        return new ClientAttestationException(USE_ATTESTATION_CHALLENGE, message);
    }

    public static ClientAttestationException useFreshAttestation(String message) {
        return new ClientAttestationException(USE_FRESH_ATTESTATION, message);
    }

    public static ClientAttestationException invalidAuthorizationDetails(String message) {
        return new ClientAttestationException(INVALID_AUTHORIZATION_DETAILS, message);
    }

    public static ClientAttestationException accessDenied(String message) {
        return new ClientAttestationException(ACCESS_DENIED, message);
    }

    public static ClientAttestationException insufficientDisclosure(String message) {
        return new ClientAttestationException(INSUFFICIENT_DISCLOSURE, message);
    }
}
