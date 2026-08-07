/*
 * A verified human authentication.
 */
package com.pingidentity.ps.oidf.enrolment;

import java.time.Instant;
import java.util.Objects;

/**
 * The outcome of verifying that a human authenticated.
 *
 * <p>{@code authenticatedAt} is the IdP's time, not ours, because it is what the server-side time-box
 * is measured from. Trusting the moment we happened to process the request would let a client bank an
 * authentication and present it later.
 *
 * @param subject          the IdP subject — the only identifier here that names a person, and it goes
 *                         no further than the registry
 * @param authenticatedAt  when the IdP says the ceremony completed
 * @param assuranceLevel   what was actually achieved, not what was asked for
 * @param credentialId     the authenticator used, for the enrolment evidence record
 * @param aaguid           the authenticator model, where the IdP exposes it
 */
public record UserAuthentication(
        String subject,
        Instant authenticatedAt,
        AssuranceLevel assuranceLevel,
        String credentialId,
        String aaguid) {

    public UserAuthentication {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(authenticatedAt, "authenticatedAt");
        Objects.requireNonNull(assuranceLevel, "assuranceLevel");
        if (subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
    }

    /** Whether this authentication reaches the level required to bind an authenticator. */
    public boolean meetsAssurance(AssuranceLevel required) {
        return this.assuranceLevel.ordinal() >= required.ordinal();
    }

    /**
     * Authenticator assurance, ordered. Names follow NIST SP 800-63B so the value can be carried into a
     * CAEP {@code assurance-level-change} event under the {@code NIST-AAL} namespace without translation.
     */
    public enum AssuranceLevel {
        /** Single factor. Not sufficient to bind a signing key. */
        AAL1,
        /** Two factors, or one multi-factor authenticator — a passkey with user verification. */
        AAL2,
        /** Hardware-based authenticator with verifier impersonation resistance. */
        AAL3
    }
}
