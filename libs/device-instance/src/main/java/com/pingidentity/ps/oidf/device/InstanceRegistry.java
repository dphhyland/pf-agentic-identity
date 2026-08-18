/*
 * Seam: the authoritative store of agent instances, devices and their owners.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The instance registry — the one place an opaque instance identifier resolves to a device and a human.
 *
 * <p>Everything downstream depends on that being true. The attestation carries a pseudonymous subject;
 * the delegated token carries it as {@code act.sub}; a resource server can risk-assess on it and can
 * learn nothing else from it. Resolution happens here and nowhere else, which is what makes the
 * identifier safe to expose.
 *
 * <p>It is also the revocation point. {@link #revoke} makes the next token request fail without
 * reaching the device, waiting for an attestation to expire, or touching anything downstream — so that
 * path is expected to be fast and is tested as such.
 *
 * <p>Implementations must be safe for concurrent use.
 */
public interface InstanceRegistry {

    /** Records a completed enrolment. The instance is {@link InstanceStatus#ACTIVE} from this moment. */
    AgentInstance register(AgentInstance instance) throws RegistryException;

    /** Records a newly enrolled device. */
    Device registerDevice(Device device) throws RegistryException;

    /** Records the owning user, or returns the existing record for that PingOne subject. */
    OwnerUser upsertOwner(String pingOneSubject) throws RegistryException;

    /** Records the passkey that bound a device to its owner. */
    BoundAuthenticator bindAuthenticator(BoundAuthenticator authenticator) throws RegistryException;

    Optional<AgentInstance> findInstance(String instanceId) throws RegistryException;

    Optional<Device> findDevice(String deviceId) throws RegistryException;

    Optional<OwnerUser> findOwner(String ownerUserId) throws RegistryException;

    /** Every instance on a device — used when a device-wide signal must fan out to all of them. */
    List<AgentInstance> instancesOnDevice(String deviceId) throws RegistryException;

    /**
     * Every device owned by a PingOne subject. A CAEP signal names its subject in one of two ways —
     * a device ({@code opaque.id}) or the human ({@code iss_sub}/{@code email}) — and a
     * {@code session-revoked} for the human must reach every device they enrolled, not just one.
     */
    List<Device> devicesOwnedBy(String pingOneSubject) throws RegistryException;

    /**
     * Bars an instance permanently and writes an audit entry. Idempotent: revoking an already-revoked
     * instance succeeds without a second audit entry, so a retried CAEP event cannot inflate the log.
     */
    void revoke(String instanceId, String reason) throws RegistryException;

    /** Suspends or resumes an instance — reversible, unlike {@link #revoke}. */
    void setStatus(String instanceId, InstanceStatus status, String reason) throws RegistryException;

    /**
     * Records that the owner completed user verification. This timestamp is the server-side time-box:
     * it is checked at every issuance and, unlike the device's authentication context, an attacker on
     * the device cannot extend it.
     */
    void recordUserVerification(String instanceId, Instant when) throws RegistryException;

    /** Records the attestation expiry most recently issued for an instance. */
    void recordAttestationExpiry(String instanceId, Instant expiresAt) throws RegistryException;

    /** Applies a compliance posture to a device, typically from a CAEP {@code device-compliance-change}. */
    void updateCompliance(String deviceId, ComplianceState state, Instant checkedAt) throws RegistryException;

    /** Advances a device's App Attest assertion counter; rejects a counter that has not moved. */
    void recordAppAttestCounter(String deviceId, long counter) throws RegistryException;

    /** Appends to the audit log. Never updates or deletes — the log is the dispute record. */
    void audit(String instanceId, String eventCode, String detail) throws RegistryException;

    /** The audit trail for an instance, oldest first. */
    List<AuditEntry> auditTrail(String instanceId) throws RegistryException;
}
