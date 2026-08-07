/*
 * An enrolled device. Never named in a token.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;

/**
 * A device that has completed App Attest verification and hosts one or more agent instances.
 *
 * <p><strong>Nothing here ever reaches a resource server.</strong> Device data is more sensitive than
 * instance data — model, OS version and a stable device identifier together are a strong fingerprint —
 * so it lives in the registry and in attestations presented only to us. A resource server gets the
 * instance identifier and nothing more.
 *
 * @param id                   the device identifier, internal to the registry
 * @param platform             e.g. {@code ios}
 * @param model                e.g. {@code iPhone16,2}
 * @param osVersion            the OS version at enrolment
 * @param appAttestKeyId       base64url of the App Attest key id — Apple's guidance is to persist this,
 *                             not the attestation object
 * @param appAttestEnvironment {@code appattest} or {@code appattestdevelop}, recorded so a development
 *                             enrolment can never later be mistaken for a production one
 * @param appAttestSignCount   the highest App Attest assertion counter seen, for replay detection
 * @param complianceState      the most recent posture reported by the compliance source
 * @param complianceCheckedAt  when that posture was reported
 * @param ownerUserId          the owning user — the only link from a device to a human
 */
public record Device(
        String id,
        String platform,
        String model,
        String osVersion,
        String appAttestKeyId,
        String appAttestEnvironment,
        long appAttestSignCount,
        ComplianceState complianceState,
        Instant complianceCheckedAt,
        String ownerUserId) {

    public Device {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (ownerUserId == null || ownerUserId.isBlank()) {
            throw new IllegalArgumentException("ownerUserId must not be blank");
        }
        if (complianceState == null) {
            complianceState = ComplianceState.UNKNOWN;
        }
    }

    public Device withCompliance(ComplianceState state, Instant checkedAt) {
        return new Device(this.id, this.platform, this.model, this.osVersion, this.appAttestKeyId,
                this.appAttestEnvironment, this.appAttestSignCount, state, checkedAt, this.ownerUserId);
    }

    public Device withAppAttestSignCount(long counter) {
        return new Device(this.id, this.platform, this.model, this.osVersion, this.appAttestKeyId,
                this.appAttestEnvironment, counter, this.complianceState, this.complianceCheckedAt,
                this.ownerUserId);
    }

    /** True when this device enrolled against Apple's development attestation service. */
    public boolean isDevelopmentEnrolment() {
        return "appattestdevelop".equals(this.appAttestEnvironment);
    }
}
