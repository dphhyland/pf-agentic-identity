/*
 * Event -> registry mapping: CAEP signals suspend/revoke the right instances; others are ignored.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.AuditEntry;
import com.pingidentity.ps.oidf.device.BoundAuthenticator;
import com.pingidentity.ps.oidf.device.CaepSignalApplier;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceIdentifiers;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceStatus;
import com.pingidentity.ps.oidf.device.OwnerUser;
import com.pingidentity.ps.oidf.device.RegistryException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class InstanceRegistryReceiverHandlerTest {

    private InstanceRegistry registry;
    private InstanceRegistryReceiverHandler handler;
    private String ownerSubject;
    private String deviceId;
    private String instanceA;
    private String instanceB;

    @BeforeEach
    void setUp() throws Exception {
        registry = new InMemoryInstanceRegistry();
        handler = new InstanceRegistryReceiverHandler(new CaepSignalApplier(registry));

        ownerSubject = "pingone|alice";
        OwnerUser owner = registry.upsertOwner(ownerSubject);
        deviceId = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(deviceId, "ios", "iPhone16,2", "18.5", "keyid",
                "appattest", 0L, ComplianceState.COMPLIANT, Instant.now(), owner.id()));
        instanceA = register();
        instanceB = register();
    }

    private String register() throws Exception {
        String id = InstanceIdentifiers.newInstanceId();
        registry.register(new AgentInstance(id, "https://platform.example.com", "agent/1.0",
                "jkt-" + id, InstanceStatus.ACTIVE, deviceId, Instant.now(), null, Instant.now()));
        return id;
    }

    private ReceivedSet set(String eventType, SubjectId subject, Map<String, Object> payload) {
        return new ReceivedSet("https://tx", "j1", 100L, subject, Map.of(eventType, payload), "jws");
    }

    private InstanceStatus statusOf(String instanceId) throws Exception {
        return registry.findInstance(instanceId).orElseThrow().status();
    }

    @Test
    void deviceComplianceChangeSuspendsActiveInstancesOnTheDevice() throws Exception {
        handler.onSet(set(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, SubjectId.opaque(deviceId),
                Map.of("current_status", "not-compliant")));
        assertEquals(InstanceStatus.SUSPENDED, statusOf(instanceA));
        assertEquals(InstanceStatus.SUSPENDED, statusOf(instanceB));
    }

    @Test
    void deviceComplianceChangeBackToCompliantDoesNotAutoResume() throws Exception {
        handler.onSet(set(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, SubjectId.opaque(deviceId),
                Map.of("current_status", "not-compliant")));
        handler.onSet(set(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, SubjectId.opaque(deviceId),
                Map.of("current_status", "compliant")));
        assertEquals(InstanceStatus.SUSPENDED, statusOf(instanceA), "resumption must be an explicit act");
    }

    @Test
    void deviceComplianceChangeWithNoCurrentStatusIsIgnored() throws Exception {
        handler.onSet(set(SsfEventTypes.CAEP_DEVICE_COMPLIANCE_CHANGE, SubjectId.opaque(deviceId), Map.of()));
        assertEquals(InstanceStatus.ACTIVE, statusOf(instanceA));
    }

    @Test
    void sessionRevokedForADeviceSubjectRevokesEveryInstanceOnIt() throws Exception {
        handler.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.opaque(deviceId), Map.of()));
        assertEquals(InstanceStatus.REVOKED, statusOf(instanceA));
        assertEquals(InstanceStatus.REVOKED, statusOf(instanceB));
    }

    @Test
    void sessionRevokedForTheOwnerFansOutToEveryDeviceTheyOwn() throws Exception {
        handler.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.issSub("https://pingone.example", ownerSubject),
                Map.of()));
        assertEquals(InstanceStatus.REVOKED, statusOf(instanceA));
        assertEquals(InstanceStatus.REVOKED, statusOf(instanceB));
    }

    @Test
    void credentialChangeRevokesOnlyOnAFido2RevokeOrDelete() throws Exception {
        handler.onSet(set(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, SubjectId.opaque(deviceId),
                Map.of("change_type", "create", "credential_type", "fido2-platform")));
        assertEquals(InstanceStatus.ACTIVE, statusOf(instanceA), "a create is a second authenticator, not a loss");

        handler.onSet(set(SsfEventTypes.CAEP_CREDENTIAL_CHANGE, SubjectId.opaque(deviceId),
                Map.of("change_type", "revoke", "credential_type", "fido2-platform")));
        assertEquals(InstanceStatus.REVOKED, statusOf(instanceA));
        assertEquals(InstanceStatus.REVOKED, statusOf(instanceB));
    }

    @Test
    void nonCaepEventsAndMissingSubjectsAreIgnored() throws Exception {
        handler.onSet(set(SsfEventTypes.VERIFICATION, null, Map.of()));                         // no subject
        handler.onSet(set(SsfEventTypes.RISC_ACCOUNT_DISABLED, SubjectId.opaque(deviceId), Map.of())); // not handled here
        assertEquals(InstanceStatus.ACTIVE, statusOf(instanceA));
        assertEquals(InstanceStatus.ACTIVE, statusOf(instanceB));
    }

    @Test
    void registryFailureIsContained() {
        InstanceRegistry broken = new ThrowingRegistry();
        InstanceRegistryReceiverHandler h = new InstanceRegistryReceiverHandler(new CaepSignalApplier(broken));
        h.onSet(set(SsfEventTypes.CAEP_SESSION_REVOKED, SubjectId.opaque(deviceId), Map.of())); // must not throw
        assertTrue(true);
    }

    /** A registry whose lookups always fail, to prove a broken store cannot escape {@link #onSet}. */
    private static final class ThrowingRegistry implements InstanceRegistry {
        @Override
        public AgentInstance register(AgentInstance instance) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public Device registerDevice(Device device) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public OwnerUser upsertOwner(String pingOneSubject) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public BoundAuthenticator bindAuthenticator(BoundAuthenticator authenticator) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public Optional<AgentInstance> findInstance(String instanceId) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public Optional<Device> findDevice(String deviceId) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public Optional<OwnerUser> findOwner(String ownerUserId) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public List<AgentInstance> instancesOnDevice(String deviceId) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public List<Device> devicesOwnedBy(String pingOneSubject) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void revoke(String instanceId, String reason) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void setStatus(String instanceId, InstanceStatus status, String reason) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void recordUserVerification(String instanceId, Instant when) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void recordAttestationExpiry(String instanceId, Instant expiresAt) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void updateCompliance(String deviceId, ComplianceState state, Instant checkedAt)
                throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void recordAppAttestCounter(String deviceId, long counter) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public void audit(String instanceId, String eventCode, String detail) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }

        @Override
        public List<AuditEntry> auditTrail(String instanceId) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "down");
        }
    }
}
