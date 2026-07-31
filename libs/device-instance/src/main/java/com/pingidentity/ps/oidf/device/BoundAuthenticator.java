/*
 * The passkey that bound a device to its owner at enrolment.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;

/**
 * A reference to the authenticator that proved the human at enrolment.
 *
 * <p>Only a reference is kept. The credential itself lives with PingOne, and a passkey private key is
 * never available to anyone in any case. What matters downstream is being able to answer, during a
 * dispute, which authenticator backed this binding and when — so the reference and the timestamp are
 * the record, per NIST SP 800-63B's requirement that enrolment evidence be a first-class artefact
 * rather than a boolean.
 *
 * @param id                the registry identifier
 * @param deviceId          the device this authenticator bound
 * @param credentialId      the WebAuthn credential id, base64url
 * @param aaguid            the authenticator model identifier, where the RP exposes it
 * @param authenticatorType e.g. {@code passkey}
 * @param boundAt           when the binding ceremony completed
 */
public record BoundAuthenticator(
        String id,
        String deviceId,
        String credentialId,
        String aaguid,
        String authenticatorType,
        Instant boundAt) {

    public BoundAuthenticator {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (deviceId == null || deviceId.isBlank()) {
            throw new IllegalArgumentException("deviceId must not be blank");
        }
    }
}
