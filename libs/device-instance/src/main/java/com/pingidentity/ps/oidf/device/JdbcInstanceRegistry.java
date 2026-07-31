/*
 * The durable InstanceRegistry, over JDBC.
 */
package com.pingidentity.ps.oidf.device;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;

/**
 * The production {@link InstanceRegistry}, backed by the schema in
 * {@code db/migration/V1__instance_registry.sql}.
 *
 * <p>Written against {@code javax.sql.DataSource} and plain JDBC rather than an ORM, for two reasons:
 * PingFederate reads this same data through a {@code CustomDataSourceDriver} that has no ORM available,
 * and the queries here are the whole contract — an ORM would hide the one that matters, which is the
 * revocation write on the token-issuance path.
 *
 * <p>Held to the same test suite as {@link InMemoryInstanceRegistry}: the semantics the rest of the
 * platform depends on (idempotent revocation, permanent revocation, counter monotonicity, append-only
 * audit) must not differ between the two.
 */
public final class JdbcInstanceRegistry implements InstanceRegistry {

    private final DataSource dataSource;

    public JdbcInstanceRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public AgentInstance register(AgentInstance instance) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            if (findInstance(c, instance.id()).isPresent()) {
                throw new RegistryException(RegistryException.DUPLICATE,
                        "instance already registered: " + instance.id());
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO agent_instance (id, platform_entity_id, agent_build, cnf_jkt, status,"
                            + " device_id, enrolled_at, attestation_exp, uv_last_verified_at)"
                            + " VALUES (?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, instance.id());
                ps.setString(2, instance.platformEntityId());
                ps.setString(3, instance.agentBuild());
                ps.setString(4, instance.cnfJkt());
                ps.setString(5, instance.status().name());
                ps.setString(6, instance.deviceId());
                ps.setTimestamp(7, timestamp(instance.enrolledAt()));
                ps.setTimestamp(8, timestamp(instance.attestationExp()));
                ps.setTimestamp(9, timestamp(instance.uvLastVerifiedAt()));
                ps.executeUpdate();
            }
            appendAudit(c, instance.id(), AuditEntry.INSTANCE_REGISTERED,
                    "device=" + instance.deviceId() + " build=" + instance.agentBuild());
            return instance;
        } catch (SQLException e) {
            throw storage("register instance", e);
        }
    }

    @Override
    public Device registerDevice(Device device) throws RegistryException {
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO device (id, platform, model, os_version, appattest_key_id,"
                             + " appattest_environment, appattest_sign_count, compliance_state,"
                             + " compliance_checked_at, owner_user_id) VALUES (?,?,?,?,?,?,?,?,?,?)")) {
            ps.setString(1, device.id());
            ps.setString(2, device.platform());
            ps.setString(3, device.model());
            ps.setString(4, device.osVersion());
            ps.setString(5, device.appAttestKeyId());
            ps.setString(6, device.appAttestEnvironment());
            ps.setLong(7, device.appAttestSignCount());
            ps.setString(8, device.complianceState().name());
            ps.setTimestamp(9, timestamp(device.complianceCheckedAt()));
            ps.setString(10, device.ownerUserId());
            ps.executeUpdate();
            return device;
        } catch (SQLException e) {
            throw storage("register device", e);
        }
    }

    @Override
    public OwnerUser upsertOwner(String pingOneSubject) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            try (PreparedStatement ps = c.prepareStatement(
                    "SELECT id, pingone_subject, created_at FROM owner_user WHERE pingone_subject = ?")) {
                ps.setString(1, pingOneSubject);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return new OwnerUser(rs.getString(1), rs.getString(2), instant(rs.getTimestamp(3)));
                    }
                }
            }
            OwnerUser owner = new OwnerUser(
                    InstanceIdentifiers.newOwnerUserId(), pingOneSubject, Instant.now());
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO owner_user (id, pingone_subject, created_at) VALUES (?,?,?)")) {
                ps.setString(1, owner.id());
                ps.setString(2, owner.pingOneSubject());
                ps.setTimestamp(3, timestamp(owner.createdAt()));
                ps.executeUpdate();
            }
            return owner;
        } catch (SQLException e) {
            throw storage("upsert owner", e);
        }
    }

    @Override
    public BoundAuthenticator bindAuthenticator(BoundAuthenticator authenticator) throws RegistryException {
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "INSERT INTO bound_authenticator (id, device_id, credential_id, aaguid,"
                             + " authenticator_type, bound_at) VALUES (?,?,?,?,?,?)")) {
            ps.setString(1, authenticator.id());
            ps.setString(2, authenticator.deviceId());
            ps.setString(3, authenticator.credentialId());
            ps.setString(4, authenticator.aaguid());
            ps.setString(5, authenticator.authenticatorType());
            ps.setTimestamp(6, timestamp(authenticator.boundAt()));
            ps.executeUpdate();
            return authenticator;
        } catch (SQLException e) {
            throw storage("bind authenticator", e);
        }
    }

    @Override
    public Optional<AgentInstance> findInstance(String instanceId) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            return findInstance(c, instanceId);
        } catch (SQLException e) {
            throw storage("find instance", e);
        }
    }

    @Override
    public Optional<Device> findDevice(String deviceId) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            return findDevice(c, deviceId);
        } catch (SQLException e) {
            throw storage("find device", e);
        }
    }

    @Override
    public Optional<OwnerUser> findOwner(String ownerUserId) throws RegistryException {
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT id, pingone_subject, created_at FROM owner_user WHERE id = ?")) {
            ps.setString(1, ownerUserId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next()
                        ? Optional.of(new OwnerUser(rs.getString(1), rs.getString(2), instant(rs.getTimestamp(3))))
                        : Optional.empty();
            }
        } catch (SQLException e) {
            throw storage("find owner", e);
        }
    }

    @Override
    public List<AgentInstance> instancesOnDevice(String deviceId) throws RegistryException {
        List<AgentInstance> found = new ArrayList<>();
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     instanceSelect() + " WHERE device_id = ? ORDER BY id")) {
            ps.setString(1, deviceId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    found.add(readInstance(rs));
                }
            }
            return List.copyOf(found);
        } catch (SQLException e) {
            throw storage("list instances on device", e);
        }
    }

    @Override
    public void revoke(String instanceId, String reason) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            AgentInstance instance = findInstance(c, instanceId).orElseThrow(() -> notFound(instanceId));
            if (instance.status() == InstanceStatus.REVOKED) {
                // Idempotent: a retried CAEP event must not add a second audit entry.
                return;
            }
            updateStatus(c, instanceId, InstanceStatus.REVOKED);
            appendAudit(c, instanceId, AuditEntry.INSTANCE_REVOKED, reason);
        } catch (SQLException e) {
            throw storage("revoke instance", e);
        }
    }

    @Override
    public void setStatus(String instanceId, InstanceStatus status, String reason) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            AgentInstance instance = findInstance(c, instanceId).orElseThrow(() -> notFound(instanceId));
            if (instance.status() == InstanceStatus.REVOKED) {
                throw new RegistryException(RegistryException.STALE_UPDATE,
                        "instance " + instanceId + " is revoked; revocation is permanent");
            }
            if (instance.status() == status) {
                return;
            }
            updateStatus(c, instanceId, status);
            appendAudit(c, instanceId, AuditEntry.INSTANCE_STATUS_CHANGED, status + ": " + reason);
        } catch (SQLException e) {
            throw storage("set instance status", e);
        }
    }

    @Override
    public void recordUserVerification(String instanceId, Instant when) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            requireInstance(c, instanceId);
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE agent_instance SET uv_last_verified_at = ? WHERE id = ?")) {
                ps.setTimestamp(1, timestamp(when));
                ps.setString(2, instanceId);
                ps.executeUpdate();
            }
            appendAudit(c, instanceId, AuditEntry.USER_VERIFIED, when.toString());
        } catch (SQLException e) {
            throw storage("record user verification", e);
        }
    }

    @Override
    public void recordAttestationExpiry(String instanceId, Instant expiresAt) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            requireInstance(c, instanceId);
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE agent_instance SET attestation_exp = ? WHERE id = ?")) {
                ps.setTimestamp(1, timestamp(expiresAt));
                ps.setString(2, instanceId);
                ps.executeUpdate();
            }
            appendAudit(c, instanceId, AuditEntry.ATTESTATION_ISSUED, "exp=" + expiresAt);
        } catch (SQLException e) {
            throw storage("record attestation expiry", e);
        }
    }

    @Override
    public void updateCompliance(String deviceId, ComplianceState state, Instant checkedAt)
            throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            if (findDevice(c, deviceId).isEmpty()) {
                throw new RegistryException(RegistryException.NOT_FOUND, "unknown device: " + deviceId);
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE device SET compliance_state = ?, compliance_checked_at = ? WHERE id = ?")) {
                ps.setString(1, state.name());
                ps.setTimestamp(2, timestamp(checkedAt));
                ps.setString(3, deviceId);
                ps.executeUpdate();
            }
            appendAudit(c, null, AuditEntry.COMPLIANCE_CHANGED, "device=" + deviceId + " state=" + state);
        } catch (SQLException e) {
            throw storage("update compliance", e);
        }
    }

    @Override
    public void recordAppAttestCounter(String deviceId, long counter) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            Device device = findDevice(c, deviceId).orElseThrow(() ->
                    new RegistryException(RegistryException.NOT_FOUND, "unknown device: " + deviceId));
            if (counter <= device.appAttestSignCount()) {
                throw new RegistryException(RegistryException.STALE_UPDATE,
                        "App Attest counter " + counter + " did not advance beyond "
                                + device.appAttestSignCount() + " — replay");
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE device SET appattest_sign_count = ? WHERE id = ?")) {
                ps.setLong(1, counter);
                ps.setString(2, deviceId);
                ps.executeUpdate();
            }
        } catch (SQLException e) {
            throw storage("record App Attest counter", e);
        }
    }

    @Override
    public void audit(String instanceId, String eventCode, String detail) throws RegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            appendAudit(c, instanceId, eventCode, detail);
        } catch (SQLException e) {
            throw storage("append audit", e);
        }
    }

    @Override
    public List<AuditEntry> auditTrail(String instanceId) throws RegistryException {
        List<AuditEntry> trail = new ArrayList<>();
        String sql = "SELECT instance_id, event_code, detail, at FROM audit_log WHERE "
                + (instanceId == null ? "instance_id IS NULL" : "instance_id = ?") + " ORDER BY seq";
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(sql)) {
            if (instanceId != null) {
                ps.setString(1, instanceId);
            }
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    trail.add(new AuditEntry(rs.getString(1), rs.getString(2), rs.getString(3),
                            instant(rs.getTimestamp(4))));
                }
            }
            return List.copyOf(trail);
        } catch (SQLException e) {
            throw storage("read audit trail", e);
        }
    }

    // ---- internals ---------------------------------------------------------------------------

    private static String instanceSelect() {
        return "SELECT id, platform_entity_id, agent_build, cnf_jkt, status, device_id, enrolled_at,"
                + " attestation_exp, uv_last_verified_at FROM agent_instance";
    }

    private static Optional<AgentInstance> findInstance(Connection c, String instanceId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(instanceSelect() + " WHERE id = ?")) {
            ps.setString(1, instanceId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(readInstance(rs)) : Optional.empty();
            }
        }
    }

    private static Optional<Device> findDevice(Connection c, String deviceId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT id, platform, model, os_version, appattest_key_id, appattest_environment,"
                        + " appattest_sign_count, compliance_state, compliance_checked_at, owner_user_id"
                        + " FROM device WHERE id = ?")) {
            ps.setString(1, deviceId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return Optional.empty();
                }
                return Optional.of(new Device(rs.getString(1), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getString(6), rs.getLong(7),
                        ComplianceState.valueOf(rs.getString(8)), instant(rs.getTimestamp(9)),
                        rs.getString(10)));
            }
        }
    }

    private static AgentInstance readInstance(ResultSet rs) throws SQLException {
        return new AgentInstance(rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                InstanceStatus.valueOf(rs.getString(5)), rs.getString(6), instant(rs.getTimestamp(7)),
                instant(rs.getTimestamp(8)), instant(rs.getTimestamp(9)));
    }

    private static void updateStatus(Connection c, String instanceId, InstanceStatus status)
            throws SQLException {
        try (PreparedStatement ps = c.prepareStatement("UPDATE agent_instance SET status = ? WHERE id = ?")) {
            ps.setString(1, status.name());
            ps.setString(2, instanceId);
            ps.executeUpdate();
        }
    }

    private static void appendAudit(Connection c, String instanceId, String eventCode, String detail)
            throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO audit_log (instance_id, event_code, detail, at) VALUES (?,?,?,?)")) {
            ps.setString(1, instanceId);
            ps.setString(2, eventCode);
            ps.setString(3, detail);
            ps.setTimestamp(4, timestamp(Instant.now()));
            ps.executeUpdate();
        }
    }

    private static void requireInstance(Connection c, String instanceId)
            throws SQLException, RegistryException {
        if (findInstance(c, instanceId).isEmpty()) {
            throw notFound(instanceId);
        }
    }

    private static RegistryException notFound(String instanceId) {
        return new RegistryException(RegistryException.NOT_FOUND, "unknown instance: " + instanceId);
    }

    private static RegistryException storage(String operation, SQLException cause) {
        return new RegistryException(RegistryException.STORAGE_FAILURE,
                "could not " + operation + ": " + cause.getMessage(), cause);
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
