/*
 * A registered agent instance — one install of one agent on one device.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;

/**
 * One install of an agent on one device.
 *
 * <p>{@code id} is the pseudonymous identifier that becomes the attestation's {@code sub} and the
 * delegated token's {@code act.sub}. It is opaque and non-guessable by construction
 * ({@link InstanceIdentifiers}), and it is the <em>only</em> handle a downstream resource server ever
 * sees. Resolving it to a device or a human requires this registry, which is the point: the identifier
 * is stable enough to risk-assess on, and useless for correlation without us.
 *
 * @param id                 the opaque instance identifier
 * @param platformEntityId   the agent platform's federation entity id — the leaf of the trust chain
 * @param agentBuild         the agent build/version this install is running
 * @param cnfJkt             RFC 7638 thumbprint of the Secure Enclave key bound to this instance
 * @param status             whether it may still obtain tokens
 * @param deviceId           the device hosting it; one device hosts many instances
 * @param enrolledAt         when the binding ceremony completed
 * @param attestationExp     when the most recently minted attestation expires
 * @param uvLastVerifiedAt   when the owner last completed user verification — the server-side half of
 *                           the time-box, and the control that actually holds, since the client-side
 *                           window is only app-enforced
 */
public record AgentInstance(
        String id,
        String platformEntityId,
        String agentBuild,
        String cnfJkt,
        InstanceStatus status,
        String deviceId,
        Instant enrolledAt,
        Instant attestationExp,
        Instant uvLastVerifiedAt) {

    public AgentInstance {
        requireText(id, "id");
        requireText(platformEntityId, "platformEntityId");
        requireText(cnfJkt, "cnfJkt");
        requireText(deviceId, "deviceId");
        if (status == null) {
            throw new IllegalArgumentException("status must not be null");
        }
    }

    /**
     * Whether user verification happened recently enough.
     *
     * <p>This is the enforcement point for the time-box. The device holds a pre-authenticated
     * {@code LAContext} and stops signing when the app invalidates it — but Apple documents no expiry on
     * that context, so a compromised app could hold it indefinitely. Only this check, evaluated server
     * side at every issuance, bounds the window in a way an attacker on the device cannot extend.
     */
    public boolean userVerificationFreshAt(Instant now, java.time.Duration maxAge) {
        return this.uvLastVerifiedAt != null
                && !this.uvLastVerifiedAt.isBefore(now.minus(maxAge));
    }

    public AgentInstance withStatus(InstanceStatus newStatus) {
        return new AgentInstance(this.id, this.platformEntityId, this.agentBuild, this.cnfJkt,
                newStatus, this.deviceId, this.enrolledAt, this.attestationExp, this.uvLastVerifiedAt);
    }

    public AgentInstance withUserVerifiedAt(Instant when) {
        return new AgentInstance(this.id, this.platformEntityId, this.agentBuild, this.cnfJkt,
                this.status, this.deviceId, this.enrolledAt, this.attestationExp, when);
    }

    public AgentInstance withAttestationExp(Instant when) {
        return new AgentInstance(this.id, this.platformEntityId, this.agentBuild, this.cnfJkt,
                this.status, this.deviceId, this.enrolledAt, when, this.uvLastVerifiedAt);
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }
}
