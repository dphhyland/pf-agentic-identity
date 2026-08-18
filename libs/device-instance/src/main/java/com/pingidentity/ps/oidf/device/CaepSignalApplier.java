/*
 * The event -> registry mapping shared by every CAEP receiver.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Turns a verified CAEP 1.0 event into a change in the instance registry. This is the mapping two
 * receivers share: {@code services/device-enrolment}'s direct compliance endpoint, and
 * {@code servlets/ssf}'s SSF receiver. Both verify their own transport (SET signature, issuer,
 * audience, freshness, replay) and resolve the event's subject their own way — a device-scoped
 * {@code opaque} identifier, or a user-scoped {@code iss_sub}/{@code email} that must fan out to every
 * device that subject owns — before calling in here with a plain device or owner id. This class owns
 * only what happens to the registry once that resolution is done.
 *
 * <p>This is what closes the loop: a device falls out of compliance, the signal arrives, every agent
 * instance on that device is suspended, and the next token request fails — without the agent
 * re-authenticating, without waiting for its attestation to expire, and without reaching the device.
 */
public final class CaepSignalApplier {

    private static final Log LOGGER = LogFactory.getLog(CaepSignalApplier.class);

    private final InstanceRegistry registry;

    public CaepSignalApplier(InstanceRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    /**
     * CAEP {@code device-compliance-change}: records the new posture, then suspends every
     * {@link InstanceStatus#ACTIVE} instance on the device if it just became non-compliant.
     *
     * <p>Deliberately does not auto-resume on a return to compliant: a device coming back into
     * compliance does not by itself re-establish that the owner is present, and the user-verification
     * window may well have lapsed meanwhile. Resumption is an explicit act.
     *
     * @param currentCaepStatus the event's required {@code current_status} claim ({@code compliant} or
     *     {@code not-compliant})
     * @return the ids of instances suspended
     */
    public List<String> deviceComplianceChange(String deviceId, String currentCaepStatus) throws RegistryException {
        Objects.requireNonNull(deviceId, "deviceId");
        ComplianceState state = ComplianceState.fromCaepValue(currentCaepStatus);
        this.registry.updateCompliance(deviceId, state, Instant.now());

        List<String> changed = new ArrayList<>();
        if (state != ComplianceState.COMPLIANT) {
            for (AgentInstance instance : this.registry.instancesOnDevice(deviceId)) {
                if (instance.status() == InstanceStatus.ACTIVE) {
                    this.registry.setStatus(instance.id(), InstanceStatus.SUSPENDED,
                            "device compliance became " + state);
                    changed.add(instance.id());
                }
            }
        }
        LOGGER.info((Object) ("CAEP device-compliance-change: device=" + deviceId + " state=" + state
                + " suspended=" + changed.size()));
        return changed;
    }

    /** CAEP {@code session-revoked} naming a device: revokes every instance on it. */
    public List<String> sessionRevokedForDevice(String deviceId) throws RegistryException {
        Objects.requireNonNull(deviceId, "deviceId");
        return revokeAll(this.registry.instancesOnDevice(deviceId), "session revoked by CAEP signal");
    }

    /** CAEP {@code session-revoked} naming the human: revokes every instance on every device they own. */
    public List<String> sessionRevokedForOwner(String pingOneSubject) throws RegistryException {
        Objects.requireNonNull(pingOneSubject, "pingOneSubject");
        List<String> revoked = new ArrayList<>();
        for (Device device : this.registry.devicesOwnedBy(pingOneSubject)) {
            revoked.addAll(revokeAll(this.registry.instancesOnDevice(device.id()), "session revoked by CAEP signal"));
        }
        return revoked;
    }

    /**
     * CAEP {@code credential-change}: only a {@code revoke}/{@code delete} of a {@code fido2*}
     * credential is acted on — a {@code create} is somebody adding a second authenticator, not losing
     * one.
     */
    public List<String> credentialChange(String deviceId, String changeType, String credentialType)
            throws RegistryException {
        Objects.requireNonNull(deviceId, "deviceId");
        if (!"revoke".equals(changeType) && !"delete".equals(changeType)) {
            return List.of();
        }
        if (credentialType != null && !credentialType.startsWith("fido2")) {
            return List.of();
        }
        return revokeAll(this.registry.instancesOnDevice(deviceId),
                "the passkey that authorised this binding was " + changeType + "d");
    }

    private List<String> revokeAll(List<AgentInstance> instances, String reason) throws RegistryException {
        List<String> revoked = new ArrayList<>();
        for (AgentInstance instance : instances) {
            this.registry.revoke(instance.id(), reason);
            revoked.add(instance.id());
        }
        return revoked;
    }
}
