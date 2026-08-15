package com.pingidentity.ps.oidf.enrolment;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.InMemoryAttestationReplayCache;
import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceIdentifiers;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceStatus;
import com.pingidentity.ps.oidf.device.OwnerUser;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The CAEP loop: a signal arrives and the next token request fails, with nothing reaching the device
 * and no agent re-authentication.
 */
class CaepEventHandlerTest {

    private static final String CAEP = "https://schemas.openid.net/secevent/caep/event-type/";

    private InstanceRegistry registry;
    private CaepEventHandler handler;
    private String deviceId;
    private String instanceA;
    private String instanceB;

    @BeforeEach
    void setUp() throws Exception {
        registry = new InMemoryInstanceRegistry();
        handler = new CaepEventHandler(registry, new InMemoryAttestationReplayCache());

        OwnerUser owner = registry.upsertOwner("pingone|alice");
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

    private String set(String jti, String eventType, String eventBody) {
        return "{\"jti\":\"" + jti + "\",\"iss\":\"https://pingone.example\","
                + "\"iat\":" + Instant.now().getEpochSecond() + ","
                + "\"events\":{\"" + CAEP + eventType + "\":" + eventBody + "}}";
    }

    private CaepEventHandler.Outcome apply(String json) throws Exception {
        return handler.apply(CaepEventHandler.parseClaims(json));
    }

    // ---- the milestone acceptance -----------------------------------------------------------------

    @Test
    void aComplianceFailureSuspendsEveryInstanceOnTheDevice() throws Exception {
        CaepEventHandler.Outcome outcome = apply(set("evt-1", "device-compliance-change",
                "{\"subject\":{\"format\":\"opaque\",\"id\":\"" + deviceId + "\"},"
                        + "\"previous_status\":\"compliant\",\"current_status\":\"not-compliant\"}"));

        assertEquals(2, outcome.affectedInstances().size());
        assertEquals(InstanceStatus.SUSPENDED, registry.findInstance(instanceA).orElseThrow().status());
        assertEquals(InstanceStatus.SUSPENDED, registry.findInstance(instanceB).orElseThrow().status());
        assertEquals(ComplianceState.NOT_COMPLIANT,
                registry.findDevice(deviceId).orElseThrow().complianceState());
        // Nothing was sent to the device, and no agent re-authenticated.
    }

    /**
     * Coming back into compliance does not resume on its own. The device being healthy again says
     * nothing about whether the owner is present, and the user-verification window has very likely
     * lapsed in the meantime.
     */
    @Test
    void comingBackIntoComplianceDoesNotSilentlyResume() throws Exception {
        apply(set("evt-1", "device-compliance-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"previous_status\":\"compliant\","
                        + "\"current_status\":\"not-compliant\"}"));
        apply(set("evt-2", "device-compliance-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"previous_status\":\"not-compliant\","
                        + "\"current_status\":\"compliant\"}"));

        assertEquals(ComplianceState.COMPLIANT,
                registry.findDevice(deviceId).orElseThrow().complianceState());
        assertEquals(InstanceStatus.SUSPENDED, registry.findInstance(instanceA).orElseThrow().status(),
                "resumption must be an explicit act, not a side effect of a compliance signal");
    }

    @Test
    void aMissingCurrentStatusIsRefusedRatherThanAssumedCompliant() throws Exception {
        // CAEP 1.0 makes current_status required; guessing "compliant" would be the dangerous guess.
        CaepEventHandler.Outcome outcome = apply(set("evt-1", "device-compliance-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"previous_status\":\"compliant\"}"));

        assertTrue(outcome.affectedInstances().isEmpty());
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceA).orElseThrow().status());
        assertEquals(ComplianceState.COMPLIANT,
                registry.findDevice(deviceId).orElseThrow().complianceState());
    }

    // ---- redelivery ---------------------------------------------------------------------------------

    /** SSF redelivers by design; recognising it keeps the audit log honest about what happened. */
    @Test
    void aRedeliveredEventIsRecognisedRatherThanReapplied() throws Exception {
        String event = set("evt-same", "device-compliance-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"previous_status\":\"compliant\","
                        + "\"current_status\":\"not-compliant\"}");

        CaepEventHandler.Outcome first = apply(event);
        CaepEventHandler.Outcome second = apply(event);

        assertFalse(first.duplicate());
        assertTrue(second.duplicate());
        assertTrue(second.affectedInstances().isEmpty());

        long suspensions = registry.auditTrail(instanceA).stream()
                .filter(e -> "instance_status_changed".equals(e.eventCode())).count();
        assertEquals(1L, suspensions, "a redelivery must not inflate the audit log");
    }

    // ---- other events --------------------------------------------------------------------------------

    @Test
    void aRevokedSessionRevokesTheInstancesActingForIt() throws Exception {
        apply(set("evt-1", "session-revoked", "{\"subject\":{\"id\":\"" + deviceId + "\"}}"));
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceB).orElseThrow().status());
    }

    @Test
    void aRevokedPasskeyRevokesTheBindingItAuthorised() throws Exception {
        apply(set("evt-1", "credential-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"credential_type\":\"fido2-platform\","
                        + "\"change_type\":\"revoke\"}"));
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void addingAnAuthenticatorDoesNotRevokeAnything() throws Exception {
        apply(set("evt-1", "credential-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"credential_type\":\"fido2-platform\","
                        + "\"change_type\":\"create\"}"));
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void aPasswordChangeDoesNotTouchDeviceBindings() throws Exception {
        apply(set("evt-1", "credential-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"credential_type\":\"password\","
                        + "\"change_type\":\"revoke\"}"));
        assertEquals(InstanceStatus.ACTIVE, registry.findInstance(instanceA).orElseThrow().status());
    }

    @Test
    void anUnhandledEventTypeIsIgnoredWithoutFailingTheWholeToken() throws Exception {
        CaepEventHandler.Outcome outcome = apply(set("evt-1", "risk-level-change",
                "{\"subject\":{\"id\":\"" + deviceId + "\"},\"current_level\":\"HIGH\"}"));
        assertTrue(outcome.affectedInstances().isEmpty());
        assertFalse(outcome.duplicate());
    }

    @Test
    void oneBadEventDoesNotDiscardTheOthersInTheSameToken() throws Exception {
        String json = "{\"jti\":\"evt-mixed\",\"iss\":\"https://pingone.example\",\"events\":{"
                + "\"" + CAEP + "device-compliance-change\":{\"subject\":{\"id\":\"unknown-device\"},"
                + "\"current_status\":\"not-compliant\"},"
                + "\"" + CAEP + "session-revoked\":{\"subject\":{\"id\":\"" + deviceId + "\"}}}}";

        CaepEventHandler.Outcome outcome = apply(json);
        // The compliance event names a device that does not exist and fails; the revocation still runs.
        assertEquals(2, outcome.affectedInstances().size());
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
    }

    // ---- malformed input -------------------------------------------------------------------------------

    @Test
    void aTokenWithNoJtiIsRefused() {
        assertEquals(EnrolmentException.INVALID_REQUEST,
                assertThrows(EnrolmentException.class,
                        () -> apply("{\"events\":{}}")).error());
    }

    @Test
    void aTokenWithNoEventsIsRefused() {
        assertEquals(EnrolmentException.INVALID_REQUEST,
                assertThrows(EnrolmentException.class,
                        () -> apply("{\"jti\":\"x\",\"events\":{}}")).error());
    }

    @Test
    void nonJsonIsRefused() {
        assertThrows(EnrolmentException.class, () -> apply("not json"));
    }

    @Test
    void aSubjectGivenAsAPlainStringIsAccepted() throws Exception {
        apply(set("evt-1", "session-revoked", "{\"subject\":\"" + deviceId + "\"}"));
        assertEquals(InstanceStatus.REVOKED, registry.findInstance(instanceA).orElseThrow().status());
    }
}
