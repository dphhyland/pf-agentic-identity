/*
 * Seam: establishes that a human authenticated, and at what assurance.
 */
package com.pingidentity.ps.oidf.enrolment;

/**
 * Verifies that the person driving an enrolment really authenticated, and reports the assurance
 * achieved. The production implementation checks a PingOne authentication result produced by a
 * FIDO2/passkey policy with user verification required.
 *
 * <p>This is a seam so the rest of the ceremony is testable without a live tenant. It is deliberately
 * narrow: it answers "who authenticated, how, and how strongly", and nothing else. Everything about
 * the device is established separately by App Attest — conflating the two is how designs end up
 * trusting a device because a user logged in, or vice versa.
 *
 * <p>Implementations MUST fail closed. Returning a result with a lower assurance than requested is
 * correct; inventing one is not. NIST SP 800-63B §6.1.2.1 requires the user to authenticate at or
 * above the level the new authenticator will be used at, and {@link EnrolmentService} enforces that
 * against {@link UserAuthentication#meetsAssurance}.
 */
public interface UserAuthenticationVerifier {

    /**
     * Verifies an authentication result presented by the client.
     *
     * @param evidence the opaque result from the IdP — for PingOne, the token or flow result the app
     *                 received on completing the passkey ceremony
     * @return who authenticated and how
     * @throws EnrolmentException {@code user_authentication_failed} if it cannot be verified
     */
    UserAuthentication verify(String evidence) throws EnrolmentException;
}
