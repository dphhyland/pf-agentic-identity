/*
 * An in-process InstanceRegistry, for tests and single-node development.
 */
package com.pingidentity.ps.oidf.device;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * An in-memory {@link InstanceRegistry}.
 *
 * <p>Not for production: state dies with the process and is not shared between nodes, so a revocation
 * on one node would leave every other node still issuing. Its purpose is that the registry's
 * <em>semantics</em> — revocation, idempotency, counter monotonicity, audit append-only-ness — can be
 * tested exhaustively without a database, and the JDBC implementation can then be held to the same
 * suite.
 */
public final class InMemoryInstanceRegistry implements InstanceRegistry {

    private final Map<String, AgentInstance> instances = new ConcurrentHashMap<>();
    private final Map<String, Device> devices = new ConcurrentHashMap<>();
    private final Map<String, OwnerUser> owners = new ConcurrentHashMap<>();
    private final Map<String, OwnerUser> ownersBySubject = new ConcurrentHashMap<>();
    private final Map<String, BoundAuthenticator> authenticators = new ConcurrentHashMap<>();
    private final List<AuditEntry> auditLog = new CopyOnWriteArrayList<>();

    @Override
    public AgentInstance register(AgentInstance instance) throws RegistryException {
        if (this.instances.putIfAbsent(instance.id(), instance) != null) {
            throw new RegistryException(RegistryException.DUPLICATE,
                    "instance already registered: " + instance.id());
        }
        audit(instance.id(), AuditEntry.INSTANCE_REGISTERED,
                "device=" + instance.deviceId() + " build=" + instance.agentBuild());
        return instance;
    }

    @Override
    public Device registerDevice(Device device) throws RegistryException {
        if (this.devices.putIfAbsent(device.id(), device) != null) {
            throw new RegistryException(RegistryException.DUPLICATE, "device already registered: " + device.id());
        }
        return device;
    }

    @Override
    public OwnerUser upsertOwner(String pingOneSubject) {
        return this.ownersBySubject.computeIfAbsent(pingOneSubject, subject -> {
            OwnerUser owner = new OwnerUser(InstanceIdentifiers.newOwnerUserId(), subject, Instant.now());
            this.owners.put(owner.id(), owner);
            return owner;
        });
    }

    @Override
    public BoundAuthenticator bindAuthenticator(BoundAuthenticator authenticator) throws RegistryException {
        if (this.authenticators.putIfAbsent(authenticator.id(), authenticator) != null) {
            throw new RegistryException(RegistryException.DUPLICATE,
                    "authenticator already bound: " + authenticator.id());
        }
        return authenticator;
    }

    @Override
    public Optional<AgentInstance> findInstance(String instanceId) {
        return Optional.ofNullable(this.instances.get(instanceId));
    }

    @Override
    public Optional<Device> findDevice(String deviceId) {
        return Optional.ofNullable(this.devices.get(deviceId));
    }

    @Override
    public Optional<OwnerUser> findOwner(String ownerUserId) {
        return Optional.ofNullable(this.owners.get(ownerUserId));
    }

    @Override
    public List<AgentInstance> instancesOnDevice(String deviceId) {
        List<AgentInstance> found = new ArrayList<>();
        for (AgentInstance instance : this.instances.values()) {
            if (instance.deviceId().equals(deviceId)) {
                found.add(instance);
            }
        }
        found.sort(Comparator.comparing(AgentInstance::id));
        return found;
    }

    @Override
    public void revoke(String instanceId, String reason) throws RegistryException {
        AgentInstance instance = require(instanceId);
        if (instance.status() == InstanceStatus.REVOKED) {
            // Idempotent: a retried CAEP event must not inflate the audit log with duplicate entries.
            return;
        }
        this.instances.put(instanceId, instance.withStatus(InstanceStatus.REVOKED));
        audit(instanceId, AuditEntry.INSTANCE_REVOKED, reason);
    }

    @Override
    public void setStatus(String instanceId, InstanceStatus status, String reason) throws RegistryException {
        AgentInstance instance = require(instanceId);
        if (instance.status() == InstanceStatus.REVOKED) {
            throw new RegistryException(RegistryException.STALE_UPDATE,
                    "instance " + instanceId + " is revoked; revocation is permanent");
        }
        if (instance.status() == status) {
            return;
        }
        this.instances.put(instanceId, instance.withStatus(status));
        audit(instanceId, AuditEntry.INSTANCE_STATUS_CHANGED, status + ": " + reason);
    }

    @Override
    public void recordUserVerification(String instanceId, Instant when) throws RegistryException {
        AgentInstance instance = require(instanceId);
        this.instances.put(instanceId, instance.withUserVerifiedAt(when));
        audit(instanceId, AuditEntry.USER_VERIFIED, when.toString());
    }

    @Override
    public void recordAttestationExpiry(String instanceId, Instant expiresAt) throws RegistryException {
        AgentInstance instance = require(instanceId);
        this.instances.put(instanceId, instance.withAttestationExp(expiresAt));
        audit(instanceId, AuditEntry.ATTESTATION_ISSUED, "exp=" + expiresAt);
    }

    @Override
    public void updateCompliance(String deviceId, ComplianceState state, Instant checkedAt)
            throws RegistryException {
        Device device = this.devices.get(deviceId);
        if (device == null) {
            throw new RegistryException(RegistryException.NOT_FOUND, "unknown device: " + deviceId);
        }
        this.devices.put(deviceId, device.withCompliance(state, checkedAt));
        audit(null, AuditEntry.COMPLIANCE_CHANGED, "device=" + deviceId + " state=" + state);
    }

    @Override
    public void recordAppAttestCounter(String deviceId, long counter) throws RegistryException {
        Device device = this.devices.get(deviceId);
        if (device == null) {
            throw new RegistryException(RegistryException.NOT_FOUND, "unknown device: " + deviceId);
        }
        if (counter <= device.appAttestSignCount()) {
            throw new RegistryException(RegistryException.STALE_UPDATE,
                    "App Attest counter " + counter + " did not advance beyond "
                            + device.appAttestSignCount() + " — replay");
        }
        this.devices.put(deviceId, device.withAppAttestSignCount(counter));
    }

    @Override
    public void audit(String instanceId, String eventCode, String detail) {
        this.auditLog.add(new AuditEntry(instanceId, eventCode, detail, Instant.now()));
    }

    @Override
    public List<AuditEntry> auditTrail(String instanceId) {
        List<AuditEntry> found = new ArrayList<>();
        for (AuditEntry entry : this.auditLog) {
            if (instanceId == null ? entry.instanceId() == null : instanceId.equals(entry.instanceId())) {
                found.add(entry);
            }
        }
        return List.copyOf(found);
    }

    private AgentInstance require(String instanceId) throws RegistryException {
        AgentInstance instance = this.instances.get(instanceId);
        if (instance == null) {
            throw new RegistryException(RegistryException.NOT_FOUND, "unknown instance: " + instanceId);
        }
        return instance;
    }
}
