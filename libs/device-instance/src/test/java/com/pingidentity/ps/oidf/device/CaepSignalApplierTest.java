package com.pingidentity.ps.oidf.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link CaepSignalApplier} — the event-to-registry mapping shared by every CAEP receiver
 * ({@code services/device-enrolment}'s direct endpoint and {@code servlets/ssf}'s SSF receiver). Neither
 * caller has its own test of this mapping in isolation: {@code CaepEventHandlerTest} exercises it only
 * through one transport's decoding, and the SSF module's test exercises it only through the other's
 * subject-format parsing. This is the one place the mapping itself — suspend-on-non-compliance,
 * fan-out-by-device-or-owner, and the credential-change filter — is pinned directly.
 */
class CaepSignalApplierTest {

    private InstanceRegistry registry;
    private CaepSignalApplier applier;
    private String deviceId;
    private String instanceA;
    private String instanceB;

    @BeforeEach
    void setUp() throws Exception {
        registry = new InMemoryInstanceRegistry();
        applier = new CaepSignalApplier(registry);

        OwnerUser owner = registry.upsertOwner("pingone|alice");
        deviceId = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(deviceId, "ios", "iPhone16,2", "18.5", "keyid",
                "appattest", 0L, ComplianceState.COMPLIANT, Instant.now(), owner.id()));
        instanceA = register(deviceId);
        instanceB = register(deviceId);
    }

    private String register(String onDevice) throws Exception {
        String id = InstanceIdentifiers.newInstanceId();
        registry.register(new AgentInstance(id, "https://platform.example.com", "agent/1.0",
                "jkt-" + id, InstanceStatus.ACTIVE, onDevice, Instant.now(), null, Instant.now()));
        return id;
    }

    // ---- device-compliance-change ------------------------------------------------------------------

    @Test
    void nonCompliantSuspendsEveryActiveInstanceOnTheDevice() throws Exception {
        List<String> changed = applier.deviceComplianceChange(deviceId, "not-compliant");

        assertEquals(2, changed.size());
        assertTrue(changed.containsAll(List.of(instanceA, instanceB)));
        assertEquals(InstanceStatus.SUSPENDED, registry.findInstance(instanceA).orElseThrow().status());
        assertEquals(InstanceStatus.SUSPENDED, registry.findInstance(instanceB).orElseThrow().status());
        assertEquals(ComplianceState.NOT_COMPLIANT, registry.findDevice(deviceId).orElseThrow().complianceState());
    }

    @Test
    void complianceRestoredDoesNotAutoResumeAnything() throws Exception {
        applier.deviceComplianceChange(deviceId, "not-compliant");
        List<String> changed = applier.deviceComplianceChange(deviceId, "compliant");

        assertTrue(changed.isEmpty(), "returning to compliant must not itself resume anything");
        assertEquals(InstanceStatus.SUSPENDED, registry.findInstance(instanceA).orElseThrow().status());
        assertEquals(ComplianceState.COMPLIANT, registry.findDevice(deviceId).orElseThrow().complianceState());
    }

    @Test
    void anAlreadySuspendedInstanceIsNotReSuspendedOrReAudited() throws Exception {
        registry.setStatus(instanceA, InstanceStatus.SUSPENDED, "already suspended for another reason");

        List<String> changed = applier.deviceComplianceChange(deviceId, "not-compliant");

        // Only instanceB was ACTIVE; instanceA is left alone because it was not ACTIVE going in.
        assertEquals(List.of(instanceB), changed);
    }

    @Test
    void aRevokedInstanceIsNeverTouchedByAComplianceSignal() throws Exception {
        registry.revoke(instanceA, "compromised earlier");

        List<String> changed = applier.deviceComplianceChange(deviceId, "not-compliant");

        assertEquals(List.of(instanceB), changed);
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void anUnrecognisedCaepValueIsTreatedAsUnknownNotCompliant() throws Exception {
        // ComplianceState.fromCaepValue fails closed to UNKNOWN for anything it does not recognise, and
        // UNKNOWN is not COMPLIANT, so it must still suspend.
        List<String> changed = applier.deviceComplianceChange(deviceId, "garbage-value");

        assertEquals(2, changed.size());
        assertEquals(ComplianceState.UNKNOWN, registry.findDevice(deviceId).orElseThrow().complianceState());
    }

    // ---- session-revoked ----------------------------------------------------------------------------

    @Test
    void sessionRevokedForDeviceRevokesEveryInstanceOnThatDeviceOnly() throws Exception {
        String otherDevice = InstanceIdentifiers.newDeviceId();
        OwnerUser other = registry.upsertOwner("pingone|bob");
        registry.registerDevice(new Device(otherDevice, "ios", null, null, "keyid-2", "appattest",
                0L, ComplianceState.COMPLIANT, Instant.now(), other.id()));
        String instanceC = register(otherDevice);

        List<String> revoked = applier.sessionRevokedForDevice(deviceId);

        assertEquals(2, revoked.size());
        assertTrue(revoked.containsAll(List.of(instanceA, instanceB)));
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceB).orElseThrow().status());
        // A different owner's device must not be touched by a signal naming this one.
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceC).orElseThrow().status());
    }

    @Test
    void sessionRevokedForOwnerReachesEveryDeviceThatOwnerEnrolled() throws Exception {
        OwnerUser alice = registry.upsertOwner("pingone|alice");
        String secondDevice = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(secondDevice, "ios", null, null, "keyid-2", "appattest",
                0L, ComplianceState.COMPLIANT, Instant.now(), alice.id()));
        String instanceOnSecondDevice = register(secondDevice);

        // A device belonging to somebody else must not be reached by Alice's session-revoked.
        OwnerUser bob = registry.upsertOwner("pingone|bob");
        String bobsDevice = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(bobsDevice, "ios", null, null, "keyid-3", "appattest",
                0L, ComplianceState.COMPLIANT, Instant.now(), bob.id()));
        String bobsInstance = register(bobsDevice);

        List<String> revoked = applier.sessionRevokedForOwner("pingone|alice");

        assertEquals(3, revoked.size());
        assertTrue(revoked.containsAll(List.of(instanceA, instanceB, instanceOnSecondDevice)));
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceOnSecondDevice).orElseThrow().status());
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(bobsInstance).orElseThrow().status());
    }

    @Test
    void sessionRevokedForAnUnknownOwnerRevokesNothing() throws Exception {
        List<String> revoked = applier.sessionRevokedForOwner("pingone|nobody");
        assertTrue(revoked.isEmpty());
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceA).orElseThrow().status());
    }

    // ---- credential-change ---------------------------------------------------------------------------

    @Test
    void aRevokedFido2CredentialRevokesEveryInstanceItAuthorised() throws Exception {
        List<String> revoked = applier.credentialChange(deviceId, "revoke", "fido2-platform");
        assertEquals(2, revoked.size());
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void aDeletedFido2CredentialAlsoRevokes() throws Exception {
        List<String> revoked = applier.credentialChange(deviceId, "delete", "fido2-roaming");
        assertEquals(2, revoked.size());
    }

    @Test
    void creatingACredentialRevokesNothing() throws Exception {
        List<String> revoked = applier.credentialChange(deviceId, "create", "fido2-platform");
        assertTrue(revoked.isEmpty());
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void updatingACredentialRevokesNothing() throws Exception {
        List<String> revoked = applier.credentialChange(deviceId, "update", "fido2-platform");
        assertTrue(revoked.isEmpty());
    }

    @Test
    void aNonFido2CredentialTypeIsIgnoredEvenIfRevoked() throws Exception {
        List<String> revoked = applier.credentialChange(deviceId, "revoke", "password");
        assertTrue(revoked.isEmpty());
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void aMissingCredentialTypeIsTreatedAsActionableRatherThanIgnored() throws Exception {
        // Only change_type is gated when credential_type is absent — CaepSignalApplier only filters out
        // a credential_type that is present AND not fido2*.
        List<String> revoked = applier.credentialChange(deviceId, "revoke", null);
        assertEquals(2, revoked.size());
    }

    @Test
    void unknownDeviceLeavesNothingToRevoke() throws Exception {
        assertTrue(applier.sessionRevokedForDevice("no-such-device").isEmpty());
        assertTrue(applier.credentialChange("no-such-device", "revoke", "fido2-platform").isEmpty());
    }
}
