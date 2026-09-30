/*
 * The Identity Object Model implementation, held to the same contract — against a real Postgres.
 */
package com.pingidentity.ps.oidf.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.testkit.Migrations;
import com.pingidentity.ps.oidf.testkit.PostgresDatabase;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/**
 * {@link IomInstanceRegistry} against a real PostgreSQL, running the model repo's own migrations
 * (vendored under {@code src/test/resources/idm/} — refresh them from
 * {@code ~/Source/idp-scim-service/migrations} when they change).
 *
 * <p>H2 was the previous implementation's test database and is not an option here: every invariant this
 * registry relies on is a Postgres feature — JSONB operators, partial unique indexes on expressions,
 * {@code ANY(text[])}, plpgsql triggers, and compare-and-set semantics under READ COMMITTED. A suite
 * that ran against a database which cannot enforce the rules would prove nothing about the one that does.
 *
 * <p>The Postgres is a database of this class's own (libs/testkit: {@code OIDF_TEST_JDBC_URL}, else Testcontainers,
 * else skipped - failed under {@code CI=true}), created before the class and dropped after it, so the suite
 * shares nothing with the other classes that use the same server.
 */
class IomInstanceRegistryTest extends InstanceRegistryContract {

    private static final String[] MIGRATIONS = {
        "/idm/0000-base-schema.sql",
        "/idm/002-backfill-may-attrs.sql",
        "/idm/006-add-agent-instance-registry.sql",
    };

    @RegisterExtension
    static final PostgresDatabase POSTGRES = new PostgresDatabase();

    private static DataSource dataSource;

    @BeforeAll
    static void applyModelSchema() throws Exception {
        dataSource = POSTGRES.dataSource();
        Migrations.applyResources(dataSource, IomInstanceRegistryTest.class, MIGRATIONS);
    }

    @Override
    protected InstanceRegistry newRegistry() throws Exception {
        // TRUNCATE bypasses the row triggers, so the append-only ledger does not block a reset between
        // tests; the self-referencing parent_id needs CASCADE.
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute("TRUNCATE idm.entry CASCADE");
            s.execute("ALTER SEQUENCE idm.agent_lifecycle_event_seq RESTART WITH 1");
        }
        return new IomInstanceRegistry(dataSource);
    }

    // ── what only a real Postgres can prove ──────────────────────────────────────────────────────

    /**
     * Two assertions carrying the same counter, racing. The compare-and-set is one statement, so
     * Postgres re-evaluates the predicate against the locked row and exactly one can win — the check
     * the retired JDBC implementation could not make, because it read, decided in Java, then wrote.
     */
    @Test
    void concurrentAppAttestCounterUpdatesLetExactlyOneWin() throws Exception {
        InstanceRegistry registry = newRegistry();
        OwnerUser owner = registry.upsertOwner("pingone|race");
        String deviceId = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(deviceId, "ios", null, null, "keyid-race", "appattest",
                0L, ComplianceState.UNKNOWN, null, owner.id()));

        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();
        for (int i = 0; i < threads; i++) {
            new Thread(() -> {
                try {
                    start.await();
                    registry.recordAppAttestCounter(deviceId, 7L);
                    accepted.incrementAndGet();
                } catch (RegistryException e) {
                    if (RegistryException.STALE_UPDATE.equals(e.reason())) {
                        rejected.incrementAndGet();
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                } finally {
                    done.countDown();
                }
            }).start();
        }
        start.countDown();
        assertTrue(done.await(30, TimeUnit.SECONDS), "threads did not finish");

        assertEquals(1, accepted.get(), "exactly one assertion may advance the counter");
        assertEquals(threads - 1, rejected.get(), "every other assertion is a replay");
        assertEquals(7L, registry.findDevice(deviceId).orElseThrow().appAttestSignCount());
    }

    /** The database refuses a reactivation even if something bypasses the registry's own guard. */
    @Test
    void theDatabaseItselfRefusesToReactivateARevokedInstance() throws Exception {
        InstanceRegistry registry = newRegistry();
        String instanceId = seedInstance(registry, "pingone|permanent");
        registry.revoke(instanceId, "compromised");

        String sql = "UPDATE idm.entry SET record_status = 'active' "
                + "WHERE subject_id = '" + instanceId + "' AND 'agentInstance' = ANY (object_classes)";
        Exception e = assertThrows(Exception.class, () -> execRaw(sql));
        assertTrue(String.valueOf(e.getMessage()).contains("permanent"),
                "expected the revocation-is-permanent trigger, got: " + e.getMessage());
    }

    /** The ledger is append-only in the database, not merely by convention in the code. */
    @Test
    void theDatabaseItselfRefusesToRewriteOrDeleteTheLedger() throws Exception {
        InstanceRegistry registry = newRegistry();
        String instanceId = seedInstance(registry, "pingone|ledger");

        Exception update = assertThrows(Exception.class, () -> execRaw(
                "UPDATE idm.entry SET attrs = attrs || '{\"detail\":\"tampered\"}' "
                        + "WHERE 'agentLifecycleEvent' = ANY (object_classes)"));
        assertTrue(String.valueOf(update.getMessage()).contains("append-only"), update.getMessage());

        Exception delete = assertThrows(Exception.class, () -> execRaw(
                "DELETE FROM idm.entry WHERE 'agentLifecycleEvent' = ANY (object_classes)"));
        assertTrue(String.valueOf(delete.getMessage()).contains("append-only"), delete.getMessage());
    }

    /**
     * The resolution PingFederate performs at every token issuance, as the model sees it: one row
     * joining the pseudonymous instance to its device and, only through that, to the human.
     */
    @Test
    void theViewResolvesInstanceToDeviceToOwner() throws Exception {
        InstanceRegistry registry = newRegistry();
        String instanceId = seedInstance(registry, "pingone|viewer");

        List<String> rows = new ArrayList<>();
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement();
                ResultSet rs = s.executeQuery("SELECT instance_id, instance_status, device_id, "
                        + "owner_pingone_subject FROM idm.v_agent_instance")) {
            while (rs.next()) {
                rows.add(rs.getString(1) + "|" + rs.getString(2) + "|" + rs.getString(3) + "|" + rs.getString(4));
            }
        }
        assertEquals(1, rows.size());
        assertTrue(rows.get(0).startsWith(instanceId + "|active|"), rows.get(0));
        assertTrue(rows.get(0).endsWith("|pingone|viewer"), rows.get(0));
    }

    /** A CAEP signal that names the human must reach every device they enrolled. */
    @Test
    void devicesOwnedByFindsEveryDeviceOfThatSubject() throws Exception {
        InstanceRegistry registry = newRegistry();
        OwnerUser owner = registry.upsertOwner("pingone|multi");
        String first = InstanceIdentifiers.newDeviceId();
        String second = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(first, "ios", null, null, "k1", "appattest", 0L,
                ComplianceState.UNKNOWN, null, owner.id()));
        registry.registerDevice(new Device(second, "ios", null, null, "k2", "appattest", 0L,
                ComplianceState.UNKNOWN, null, owner.id()));
        // a device belonging to someone else must not be returned
        OwnerUser other = registry.upsertOwner("pingone|other");
        registry.registerDevice(new Device(InstanceIdentifiers.newDeviceId(), "ios", null, null, "k3",
                "appattest", 0L, ComplianceState.UNKNOWN, null, other.id()));

        List<Device> owned = registry.devicesOwnedBy("pingone|multi");
        assertEquals(2, owned.size());
        assertTrue(owned.stream().map(Device::id).toList().containsAll(List.of(first, second)));
        assertTrue(registry.devicesOwnedBy("pingone|nobody").isEmpty());
    }

    // ── helpers ──────────────────────────────────────────────────────────────────────────────────

    private static String seedInstance(InstanceRegistry registry, String subject) throws Exception {
        OwnerUser owner = registry.upsertOwner(subject);
        String deviceId = InstanceIdentifiers.newDeviceId();
        registry.registerDevice(new Device(deviceId, "ios", null, null, "keyid", "appattest", 0L,
                ComplianceState.UNKNOWN, null, owner.id()));
        String instanceId = InstanceIdentifiers.newInstanceId();
        registry.register(new AgentInstance(instanceId, "https://platform.example.com", "agent/1.0",
                "thumb-" + instanceId, InstanceStatus.ACTIVE, deviceId, java.time.Instant.now(), null, null));
        return instanceId;
    }

    private static void execRaw(String sql) throws Exception {
        try (Connection c = dataSource.getConnection(); Statement s = c.createStatement()) {
            s.execute(sql);
        }
    }
}
