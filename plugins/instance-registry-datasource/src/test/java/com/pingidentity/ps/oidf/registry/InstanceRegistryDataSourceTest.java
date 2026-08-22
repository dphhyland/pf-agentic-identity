package com.pingidentity.ps.oidf.registry;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.device.AgentInstance;
import com.pingidentity.ps.oidf.device.AuditEntry;
import com.pingidentity.ps.oidf.device.BoundAuthenticator;
import com.pingidentity.ps.oidf.device.ComplianceState;
import com.pingidentity.ps.oidf.device.Device;
import com.pingidentity.ps.oidf.device.InstanceRegistry;
import com.pingidentity.ps.oidf.device.InstanceStatus;
import com.pingidentity.ps.oidf.device.OwnerUser;
import com.pingidentity.ps.oidf.device.RegistryException;
import com.pingidentity.sources.CustomDataSourceDriverException;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.sourceid.saml20.adapter.conf.Field;
import org.sourceid.saml20.adapter.conf.SimpleFieldList;

/**
 * The SDK shell around {@link InstanceLookup}: {@link InstanceRegistryDataSourceTest} exists because
 * {@code InstanceLookup} itself is already thoroughly covered by {@link InstanceLookupTest}, but nothing
 * exercised the shell's own fail-closed contract — that a registry fault reaches PingFederate as a
 * thrown {@link CustomDataSourceDriverException}, never as a value map an issuance criterion could read
 * as "healthy" (every field null/false, indistinguishable from a real not-found row that just happens to
 * look fine to a criterion that isn't checking the exception path).
 */
class InstanceRegistryDataSourceTest {

    private static final Duration UV_WINDOW = Duration.ofMinutes(5);

    /** An {@link InstanceRegistry} whose {@code findInstance} always faults, everything else unused. */
    private static final class FailingRegistry implements InstanceRegistry {
        @Override
        public AgentInstance register(AgentInstance instance) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Device registerDevice(Device device) {
            throw new UnsupportedOperationException();
        }

        @Override
        public OwnerUser upsertOwner(String pingOneSubject) {
            throw new UnsupportedOperationException();
        }

        @Override
        public BoundAuthenticator bindAuthenticator(BoundAuthenticator authenticator) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<AgentInstance> findInstance(String instanceId) throws RegistryException {
            throw new RegistryException(RegistryException.STORAGE_FAILURE, "registry database unreachable");
        }

        @Override
        public Optional<Device> findDevice(String deviceId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Optional<OwnerUser> findOwner(String ownerUserId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<AgentInstance> instancesOnDevice(String deviceId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<Device> devicesOwnedBy(String pingOneSubject) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void revoke(String instanceId, String reason) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void setStatus(String instanceId, InstanceStatus status, String reason) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void recordUserVerification(String instanceId, Instant when) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void recordAttestationExpiry(String instanceId, Instant expiresAt) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void updateCompliance(String deviceId, ComplianceState state, Instant checkedAt) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void recordAppAttestCounter(String deviceId, long counter) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void audit(String instanceId, String eventCode, String detail) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<AuditEntry> auditTrail(String instanceId) {
            throw new UnsupportedOperationException();
        }
    }

    private static SimpleFieldList filterOn(String instanceId) {
        return new SimpleFieldList(List.of(new Field(InstanceRegistryDataSource.FILTER_INSTANCE_ID, instanceId)));
    }

    private static InstanceRegistryDataSource shellWith(InstanceLookup lookup) {
        InstanceRegistryDataSource ds = new InstanceRegistryDataSource();
        ds.setLookup(lookup);
        return ds;
    }

    // ---- fail closed, not fail silent -----------------------------------------------------------

    @Test
    void aRegistryFaultIsThrownNotSwallowedIntoAHealthyLookingValueMap() {
        InstanceRegistryDataSource ds = shellWith(new InstanceLookup(new FailingRegistry(), UV_WINDOW));

        CustomDataSourceDriverException e = assertThrows(CustomDataSourceDriverException.class,
                () -> ds.retrieveValues(InstanceLookup.AVAILABLE_FIELDS, filterOn("agent-1")));

        assertTrue(e.getMessage().contains("agent instance registry"), e.getMessage());
        // The point of the class: a criterion gating on instance_active/device_compliant/uv_fresh must
        // see PingFederate refuse the issuance outright while the registry is down, never a value map
        // that reads exactly like a legitimately-unknown instance.
    }

    @Test
    void testConnectionFailsWhenTheRegistryFaults() {
        InstanceRegistryDataSource ds = shellWith(new InstanceLookup(new FailingRegistry(), UV_WINDOW));

        assertFalse(ds.testConnection());
    }

    @Test
    void retrievingBeforeConfigurationFailsRatherThanNpeOrPassingSilently() {
        InstanceRegistryDataSource ds = new InstanceRegistryDataSource(); // never configured, no setLookup

        // requireLookup()'s IllegalStateException is caught by retrieveValues' own fail-closed handling
        // and re-wrapped the same way a registry fault is - one consistent thrown-exception contract for
        // PingFederate to refuse issuance on, not a raw NPE and not a partial value map.
        CustomDataSourceDriverException e = assertThrows(CustomDataSourceDriverException.class,
                () -> ds.retrieveValues(InstanceLookup.AVAILABLE_FIELDS, filterOn("agent-1")));
        assertTrue(e.getMessage().contains("not been configured"), e.getMessage());
    }

    // ---- the healthy path: only what was asked for, and an unknown name maps to null -------------

    @Test
    void onlyRequestedAttributesAreReturned() throws Exception {
        InMemoryStyleFixture fixture = InMemoryStyleFixture.withOneHealthyInstance();
        InstanceRegistryDataSource ds = shellWith(fixture.lookup);

        Map<String, Object> values = ds.retrieveValues(
                List.of(InstanceLookup.INSTANCE_ACTIVE, InstanceLookup.DEVICE_COMPLIANT), filterOn(fixture.instanceId));

        assertEquals(2, values.size());
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.INSTANCE_ACTIVE));
        assertEquals(Boolean.TRUE, values.get(InstanceLookup.DEVICE_COMPLIANT));
    }

    @Test
    void anUnadvertisedAttributeNameMapsToNullRatherThanBeingInvented() throws Exception {
        InMemoryStyleFixture fixture = InMemoryStyleFixture.withOneHealthyInstance();
        InstanceRegistryDataSource ds = shellWith(fixture.lookup);

        Map<String, Object> values = ds.retrieveValues(List.of("device_id"), filterOn(fixture.instanceId));

        assertTrue(values.containsKey("device_id"));
        assertNull(values.get("device_id"), "a criterion written against an unknown field must fail, not invent a value");
    }

    @Test
    void emptyAttributeListReturnsEveryAvailableField() throws Exception {
        InMemoryStyleFixture fixture = InMemoryStyleFixture.withOneHealthyInstance();
        InstanceRegistryDataSource ds = shellWith(fixture.lookup);

        Map<String, Object> values = ds.retrieveValues(List.of(), filterOn(fixture.instanceId));

        for (String field : InstanceLookup.AVAILABLE_FIELDS) {
            assertTrue(values.containsKey(field), "missing field: " + field);
        }
    }

    /** A tiny in-memory registry, local to this test so it does not depend on the device module's test double. */
    private static final class InMemoryStyleFixture {
        final InstanceLookup lookup;
        final String instanceId;

        private InMemoryStyleFixture(InstanceLookup lookup, String instanceId) {
            this.lookup = lookup;
            this.instanceId = instanceId;
        }

        static InMemoryStyleFixture withOneHealthyInstance() throws Exception {
            String instanceId = "agent-1";
            String deviceId = "device-1";
            OwnerUser owner = new OwnerUser("owner-1", "pingone|alice", Instant.now());
            Device device = new Device(deviceId, "ios", "iPhone16,2", "18.5", "keyid", "appattest", 0L,
                    ComplianceState.COMPLIANT, Instant.now(), owner.id());
            AgentInstance instance = new AgentInstance(instanceId, "https://platform.example.com", "agent/1.0",
                    "jkt-abc", InstanceStatus.ACTIVE, deviceId, Instant.now(), null, Instant.now());

            InstanceRegistry registry = new InstanceRegistry() {
                @Override
                public AgentInstance register(AgentInstance i) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Device registerDevice(Device d) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public OwnerUser upsertOwner(String s) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public BoundAuthenticator bindAuthenticator(BoundAuthenticator a) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Optional<AgentInstance> findInstance(String id) {
                    return instanceId.equals(id) ? Optional.of(instance) : Optional.empty();
                }

                @Override
                public Optional<Device> findDevice(String id) {
                    return deviceId.equals(id) ? Optional.of(device) : Optional.empty();
                }

                @Override
                public Optional<OwnerUser> findOwner(String id) {
                    return owner.id().equals(id) ? Optional.of(owner) : Optional.empty();
                }

                @Override
                public List<AgentInstance> instancesOnDevice(String d) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public List<Device> devicesOwnedBy(String s) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void revoke(String id, String reason) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void setStatus(String id, InstanceStatus status, String reason) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void recordUserVerification(String id, Instant when) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void recordAttestationExpiry(String id, Instant expiresAt) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void updateCompliance(String id, ComplianceState state, Instant checkedAt) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void recordAppAttestCounter(String id, long counter) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void audit(String id, String eventCode, String detail) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public List<AuditEntry> auditTrail(String id) {
                    throw new UnsupportedOperationException();
                }
            };
            return new InMemoryStyleFixture(new InstanceLookup(registry, UV_WINDOW), instanceId);
        }
    }
}
