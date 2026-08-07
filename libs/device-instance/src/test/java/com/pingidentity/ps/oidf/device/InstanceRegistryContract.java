/*
 * The semantics every InstanceRegistry implementation must satisfy identically.
 */
package com.pingidentity.ps.oidf.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The registry's semantics, which the JDBC implementation must satisfy identically. Revocation,
 * idempotency, counter monotonicity and the append-only audit log are the properties everything
 * downstream relies on.
 */
abstract class InstanceRegistryContract {

    private InstanceRegistry registry;
    private String deviceId;
    private String instanceId;

    /** The implementation under test. Each subclass supplies a freshly-empty one. */
    protected abstract InstanceRegistry newRegistry() throws Exception;

    @BeforeEach
    void setUp() throws Exception {
        registry = newRegistry();
        OwnerUser owner = registry.upsertOwner("pingone|user-123");
        deviceId = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(deviceId, "ios", "iPhone16,2", "18.5",
                "keyid-abc", "appattestdevelop", 0L, ComplianceState.UNKNOWN, null, owner.id()));
        instanceId = InstanceIdentifiers.newInstanceId();
        registry.register(newInstance(instanceId));
    }

    private AgentInstance newInstance(String id) {
        return new AgentInstance(id, "https://platform.example.com", "agent/1.0",
                "thumbprint-" + id, InstanceStatus.ACTIVE, deviceId, Instant.now(), null, Instant.now());
    }

    @Test
    void anInstanceIdentifierResolvesToADeviceAndOnlyThenToAHuman() throws Exception {
        AgentInstance instance = registry.findInstance(instanceId).orElseThrow();
        Device device = registry.findDevice(instance.deviceId()).orElseThrow();
        OwnerUser owner = registry.findOwner(device.ownerUserId()).orElseThrow();
        assertEquals("pingone|user-123", owner.pingOneSubject());
        // Two hops, both inside the registry — which is what makes the identifier safe to expose.
    }

    @Test
    void registeringTheSameInstanceTwiceIsRejected() {
        RegistryException e = assertThrows(RegistryException.class,
                () -> registry.register(newInstance(instanceId)));
        assertEquals(RegistryException.DUPLICATE, e.reason());
    }

    @Test
    void revocationStopsTokenIssuanceImmediately() throws Exception {
        assertTrue(registry.findInstance(instanceId).orElseThrow().status().canObtainTokens());
        registry.revoke(instanceId, "owner reported the phone lost");
        assertFalse(registry.findInstance(instanceId).orElseThrow().status().canObtainTokens());
    }

    @Test
    void revokingTwiceIsIdempotentAndDoesNotDuplicateTheAuditEntry() throws Exception {
        registry.revoke(instanceId, "first");
        registry.revoke(instanceId, "retried delivery of the same signal");

        long revocations = registry.auditTrail(instanceId).stream()
                .filter(e -> AuditEntry.INSTANCE_REVOKED.equals(e.eventCode()))
                .count();
        assertEquals(1L, revocations, "a retried CAEP event must not inflate the audit log");
    }

    @Test
    void aRevokedInstanceCannotBeBroughtBack() throws Exception {
        registry.revoke(instanceId, "compromised");
        RegistryException e = assertThrows(RegistryException.class,
                () -> registry.setStatus(instanceId, InstanceStatus.ACTIVE, "oops"));
        assertEquals(RegistryException.STALE_UPDATE, e.reason());
    }

    @Test
    void suspensionIsReversible() throws Exception {
        registry.setStatus(instanceId, InstanceStatus.SUSPENDED, "device out of compliance");
        assertFalse(registry.findInstance(instanceId).orElseThrow().status().canObtainTokens());
        registry.setStatus(instanceId, InstanceStatus.ACTIVE, "compliance restored");
        assertTrue(registry.findInstance(instanceId).orElseThrow().status().canObtainTokens());
    }

    @Test
    void unknownInstanceIsNotFound() {
        assertEquals(RegistryException.NOT_FOUND,
                assertThrows(RegistryException.class, () -> registry.revoke("nope", "x")).reason());
    }

    // ---- the server-side time-box ----------------------------------------------------------------

    @Test
    void userVerificationRecencyIsTheControlThatActuallyHolds() throws Exception {
        Instant now = Instant.now();
        registry.recordUserVerification(instanceId, now.minus(Duration.ofMinutes(1)));
        AgentInstance fresh = registry.findInstance(instanceId).orElseThrow();
        assertTrue(fresh.userVerificationFreshAt(now, Duration.ofMinutes(5)));

        registry.recordUserVerification(instanceId, now.minus(Duration.ofMinutes(30)));
        AgentInstance stale = registry.findInstance(instanceId).orElseThrow();
        assertFalse(stale.userVerificationFreshAt(now, Duration.ofMinutes(5)),
                "a stale verification must fail even though the device would still sign");
    }

    @Test
    void anInstanceThatHasNeverVerifiedIsNeverFresh() {
        AgentInstance never = new AgentInstance("i", "p", "b", "t", InstanceStatus.ACTIVE,
                deviceId, Instant.now(), null, null);
        assertFalse(never.userVerificationFreshAt(Instant.now(), Duration.ofDays(365)));
    }

    // ---- device state ----------------------------------------------------------------------------

    @Test
    void complianceChangeIsRecordedAgainstTheDevice() throws Exception {
        Instant at = Instant.now();
        registry.updateCompliance(deviceId, ComplianceState.NOT_COMPLIANT, at);
        Device device = registry.findDevice(deviceId).orElseThrow();
        assertEquals(ComplianceState.NOT_COMPLIANT, device.complianceState());
        assertEquals("not-compliant", device.complianceState().caepValue());
    }

    @Test
    void anUnassessedDeviceIsUnknownRatherThanCompliant() throws Exception {
        Device device = registry.findDevice(deviceId).orElseThrow();
        assertEquals(ComplianceState.UNKNOWN, device.complianceState());
        // Distinguishing these is the point: never assessed is not the same as assessed and clean.
        assertFalse(device.complianceState() == ComplianceState.COMPLIANT);
    }

    @Test
    void appAttestCounterMustAdvance() throws Exception {
        registry.recordAppAttestCounter(deviceId, 5L);
        assertEquals(5L, registry.findDevice(deviceId).orElseThrow().appAttestSignCount());

        RegistryException e = assertThrows(RegistryException.class,
                () -> registry.recordAppAttestCounter(deviceId, 5L));
        assertEquals(RegistryException.STALE_UPDATE, e.reason());
        assertThrows(RegistryException.class, () -> registry.recordAppAttestCounter(deviceId, 4L));
    }

    @Test
    void aDevelopmentEnrolmentIsFlaggedSoItCannotLaterPassAsProduction() throws Exception {
        assertTrue(registry.findDevice(deviceId).orElseThrow().isDevelopmentEnrolment());
    }

    // ---- fan-out and audit -------------------------------------------------------------------------

    @Test
    void oneDeviceHostsManyInstances() throws Exception {
        registry.register(newInstance(InstanceIdentifiers.newInstanceId()));
        registry.register(newInstance(InstanceIdentifiers.newInstanceId()));
        assertEquals(3, registry.instancesOnDevice(deviceId).size());
    }

    @Test
    void theAuditLogIsAppendOnlyAndOrdered() throws Exception {
        registry.recordUserVerification(instanceId, Instant.now());
        registry.recordAttestationExpiry(instanceId, Instant.now().plusSeconds(900));
        registry.revoke(instanceId, "done");

        List<AuditEntry> trail = registry.auditTrail(instanceId);
        assertEquals(List.of(
                        AuditEntry.INSTANCE_REGISTERED,
                        AuditEntry.USER_VERIFIED,
                        AuditEntry.ATTESTATION_ISSUED,
                        AuditEntry.INSTANCE_REVOKED),
                trail.stream().map(AuditEntry::eventCode).toList());
    }

    @Test
    void anOwnerIsReusedAcrossDevicesRatherThanDuplicated() throws Exception {
        OwnerUser first = registry.upsertOwner("pingone|user-123");
        OwnerUser again = registry.upsertOwner("pingone|user-123");
        assertEquals(first.id(), again.id());
    }
}
