package com.pingidentity.ps.oidf.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.InMemoryInstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceIdentifiers;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceStatus;
import com.pingidentity.ps.oidf.device.OwnerUser;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The issuance-time lookup. Every case here is one PingFederate hits on the token path, and the
 * property under test throughout is that a missing or stale answer reads as <em>false</em>, never as
 * absent — an issuance criterion must refuse rather than pass on a null.
 */
class InstanceLookupTest {

    private static final Duration UV_WINDOW = Duration.ofMinutes(5);

    private InstanceRegistry registry;
    private InstanceLookup lookup;
    private String instanceId;
    private String deviceId;

    @BeforeEach
    void setUp() throws Exception {
        registry = new InMemoryInstanceRegistry();
        lookup = new InstanceLookup(registry, UV_WINDOW);

        OwnerUser owner = registry.upsertOwner("pingone|alice");
        deviceId = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(deviceId, "ios", "iPhone16,2", "18.5",
                "keyid", "appattest", 0L, ComplianceState.COMPLIANT, Instant.now(), owner.id()));
        instanceId = InstanceIdentifiers.newInstanceId();
        registry.register(new AgentInstance(instanceId, "https://platform.example.com", "agent/1.0",
                "jkt-abc", InstanceStatus.ACTIVE, deviceId, Instant.now(), null, Instant.now()));
    }

    @Test
    void aHealthyInstanceResolvesToItsOwnerAndPassesEveryGate() throws Exception {
        Map<String, Object> values = lookup.lookup(instanceId, Instant.now());

        assertEquals("pingone|alice", values.get(InstanceLookup.OWNER_SUBJECT));
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.INSTANCE_ACTIVE));
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.DEVICE_COMPLIANT));
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.UV_FRESH));
        assertEquals("agent/1.0", values.get(InstanceLookup.AGENT_BUILD));
        assertEquals("jkt-abc", values.get(InstanceLookup.CNF_JKT));
    }

    /**
     * The invariant made structural. Device data must not reach a token, so the fields simply do not
     * exist to map — a careless attribute mapping cannot leak what it cannot name.
     */
    @Test
    void noDeviceIdentifierIsExposedToAMapping() throws Exception {
        assertFalse(InstanceLookup.AVAILABLE_FIELDS.contains("device_id"));
        assertFalse(InstanceLookup.AVAILABLE_FIELDS.contains("model"));
        assertFalse(InstanceLookup.AVAILABLE_FIELDS.contains("os_version"));

        Map<String, Object> values = lookup.lookup(instanceId, Instant.now());
        assertFalse(values.containsKey("device_id"));
        assertFalse(values.values().contains(deviceId), "the device id leaked into the value map");
        assertFalse(values.values().contains("iPhone16,2"));
    }

    // ---- revocation, which is the point of reading the registry at all -------------------------

    @Test
    void revocationTakesEffectOnTheNextIssuanceWithoutTouchingTheDevice() throws Exception {
        assertEquals(Boolean.TRUE, lookup.lookup(instanceId, Instant.now()).get(InstanceLookup.INSTANCE_ACTIVE));

        registry.revoke(instanceId, "owner reported the phone stolen");

        Map<String, Object> after = lookup.lookup(instanceId, Instant.now());
        assertEquals(Boolean.FALSE, after.get(InstanceLookup.INSTANCE_ACTIVE));
        assertEquals("REVOKED", after.get(InstanceLookup.INSTANCE_STATUS));
        // The attestation the client holds is still cryptographically valid; this is what stops it.
    }

    @Test
    void suspensionAlsoBlocksIssuance() throws Exception {
        registry.setStatus(instanceId, InstanceStatus.SUSPENDED, "device out of compliance");
        assertEquals(Boolean.FALSE,
                lookup.lookup(instanceId, Instant.now()).get(InstanceLookup.INSTANCE_ACTIVE));
    }

    // ---- the time-box, seen from PingFederate ----------------------------------------------------

    @Test
    void userVerificationWithinTheWindowIsFresh() throws Exception {
        registry.recordUserVerification(instanceId, Instant.now().minus(Duration.ofMinutes(2)));
        Map<String, Object> values = lookup.lookup(instanceId, Instant.now());
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.UV_FRESH));
        assertTrue(((Number) values.get(InstanceLookup.UV_SECONDS_AGO)).longValue() >= 110L);
    }

    @Test
    void onceTheWindowLapsesIssuanceStopsWithNoRevocationInvolved() throws Exception {
        registry.recordUserVerification(instanceId, Instant.now().minus(Duration.ofHours(3)));

        Map<String, Object> values = lookup.lookup(instanceId, Instant.now());
        assertEquals(Boolean.FALSE, values.get(InstanceLookup.UV_FRESH));
        // Still active and compliant — only the human's presence has aged out.
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.INSTANCE_ACTIVE));
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.DEVICE_COMPLIANT));
    }

    @Test
    void anInstanceThatHasNeverVerifiedReportsMinusOneRatherThanZero() throws Exception {
        String neverVerified = InstanceIdentifiers.newInstanceId();
        registry.register(new AgentInstance(neverVerified, "https://platform.example.com", "agent/1.0",
                "jkt", InstanceStatus.ACTIVE, deviceId, Instant.now(), null, null));

        Map<String, Object> values = lookup.lookup(neverVerified, Instant.now());
        assertEquals(-1L, ((Number) values.get(InstanceLookup.UV_SECONDS_AGO)).longValue());
        assertEquals(Boolean.FALSE, values.get(InstanceLookup.UV_FRESH));
        // -1 rather than 0, because zero would read as "verified just now" to a numeric comparison.
    }

    // ---- device compliance ------------------------------------------------------------------------

    @Test
    void anUnassessedDeviceIsNotCompliant() throws Exception {
        registry.updateCompliance(deviceId, ComplianceState.UNKNOWN, Instant.now());
        Map<String, Object> values = lookup.lookup(instanceId, Instant.now());
        assertEquals("UNKNOWN", values.get(InstanceLookup.DEVICE_COMPLIANCE));
        assertEquals(Boolean.FALSE, values.get(InstanceLookup.DEVICE_COMPLIANT),
                "never assessed must not read as compliant");
    }

    @Test
    void aNonCompliantDeviceFailsTheGate() throws Exception {
        registry.updateCompliance(deviceId, ComplianceState.NOT_COMPLIANT, Instant.now());
        assertEquals(Boolean.FALSE,
                lookup.lookup(instanceId, Instant.now()).get(InstanceLookup.DEVICE_COMPLIANT));
    }

    // ---- failing closed ----------------------------------------------------------------------------

    @Test
    void anUnknownInstanceFailsEveryGateRatherThanReturningNothing() throws Exception {
        Map<String, Object> values = lookup.lookup("no-such-instance", Instant.now());

        assertEquals(Boolean.FALSE, values.get(InstanceLookup.INSTANCE_ACTIVE));
        assertEquals(Boolean.FALSE, values.get(InstanceLookup.DEVICE_COMPLIANT));
        assertEquals(Boolean.FALSE, values.get(InstanceLookup.UV_FRESH));
        assertNull(values.get(InstanceLookup.OWNER_SUBJECT));
        // Every advertised field is present, so a criterion referencing any of them evaluates false
        // rather than erroring or passing on an absent value.
        for (String field : InstanceLookup.AVAILABLE_FIELDS) {
            assertTrue(values.containsKey(field), "missing field on the not-found path: " + field);
        }
    }

    @Test
    void aBlankInstanceIdIsTreatedAsNotFound() throws Exception {
        for (String id : new String[]{null, "", "   "}) {
            assertEquals(Boolean.FALSE, lookup.lookup(id, Instant.now()).get(InstanceLookup.INSTANCE_ACTIVE));
        }
    }

    @Test
    void aDeletedInstanceIsIndistinguishableFromOneThatNeverExisted() throws Exception {
        Map<String, Object> neverExisted = lookup.lookup("ghost", Instant.now());
        assertEquals(InstanceLookup.notFound().keySet(), neverExisted.keySet());
        assertEquals(InstanceLookup.notFound().get(InstanceLookup.INSTANCE_STATUS),
                neverExisted.get(InstanceLookup.INSTANCE_STATUS));
    }
}
