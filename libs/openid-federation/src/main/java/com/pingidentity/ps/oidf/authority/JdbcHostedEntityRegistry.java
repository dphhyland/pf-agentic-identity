/*
 * The durable HostedEntityRegistry, over JDBC.
 */
package com.pingidentity.ps.oidf.authority;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.jose4j.json.JsonUtil;

/**
 * The production {@link HostedEntityRegistry}, backed by the schema in
 * {@code db/migration/V100__hosted_entity.sql}.
 *
 * <p>Written against {@code javax.sql.DataSource} and plain JDBC rather than an ORM, matching the same
 * two reasons an instance registry in this codebase would give: the resolution and revocation queries
 * are the whole contract, and an ORM would obscure exactly the one that matters — the status check that
 * gates whether an entity resolves.
 *
 * <p>{@code metadata} and {@code metadataPolicy} are stored as serialized JSON text rather than a
 * database-specific JSON type, so the same schema and queries work unchanged against Postgres (the
 * deployment target) and H2 in PostgreSQL-compatibility mode (the test target).
 */
public final class JdbcHostedEntityRegistry implements HostedEntityRegistry {

    private final DataSource dataSource;

    public JdbcHostedEntityRegistry(DataSource dataSource) {
        this.dataSource = Objects.requireNonNull(dataSource, "dataSource");
    }

    @Override
    public HostedEntity register(HostedEntity entity) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            if (find(c, entity.entityId()).isPresent()) {
                throw new AuthorityRegistryException(AuthorityRegistryException.DUPLICATE,
                        "entity already hosted: " + entity.entityId());
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "INSERT INTO hosted_entity (entity_id, hosting_mode, hosting_key_ref, metadata,"
                            + " metadata_policy, status, listable, owner_ref, registered_at, not_after)"
                            + " VALUES (?,?,?,?,?,?,?,?,?,?)")) {
                ps.setString(1, entity.entityId());
                ps.setString(2, entity.hostingMode().name());
                ps.setString(3, entity.hostingKeyRef());
                ps.setString(4, toJson(entity.metadata()));
                ps.setString(5, toJson(entity.metadataPolicy()));
                ps.setString(6, entity.status().name());
                ps.setBoolean(7, entity.listable());
                ps.setString(8, entity.ownerRef());
                ps.setTimestamp(9, timestamp(entity.registeredAt()));
                ps.setTimestamp(10, timestamp(entity.notAfter()));
                ps.executeUpdate();
            }
            appendAudit(c, entity.entityId(), AuthorityAuditEntry.ENTITY_REGISTERED,
                    "hostingMode=" + entity.hostingMode());
            return entity;
        } catch (SQLException e) {
            throw storage("register hosted entity", e);
        }
    }

    @Override
    public Optional<HostedEntity> find(String entityId) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            return find(c, entityId);
        } catch (SQLException e) {
            throw storage("find hosted entity", e);
        }
    }

    @Override
    public List<HostedEntity> list(String entityType) throws AuthorityRegistryException {
        List<HostedEntity> out = new ArrayList<>();
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     select() + " WHERE status = 'ACTIVE' AND listable = TRUE"
                             + " AND (not_after IS NULL OR not_after > ?) ORDER BY entity_id")) {
            ps.setTimestamp(1, timestamp(Instant.now()));
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    HostedEntity entity = readEntity(rs);
                    if (entityType == null || entity.hasType(entityType)) {
                        out.add(entity);
                    }
                }
            }
            return List.copyOf(out);
        } catch (SQLException e) {
            throw storage("list hosted entities", e);
        }
    }

    @Override
    public void setStatus(String entityId, EntityStatus status, String reason) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            HostedEntity current = find(c, entityId).orElseThrow(() -> notFound(entityId));
            if (current.status() == status) {
                // Idempotent — covers a retried REVOKED -> REVOKED just as much as ACTIVE -> ACTIVE,
                // which is why this must run before the "already revoked" guard below, not after it.
                return;
            }
            if (current.status() == EntityStatus.REVOKED) {
                throw new AuthorityRegistryException(AuthorityRegistryException.STALE_UPDATE,
                        "entity " + entityId + " is revoked; revocation is permanent");
            }
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE hosted_entity SET status = ? WHERE entity_id = ?")) {
                ps.setString(1, status.name());
                ps.setString(2, entityId);
                ps.executeUpdate();
            }
            String code = status == EntityStatus.REVOKED
                    ? AuthorityAuditEntry.ENTITY_REVOKED : AuthorityAuditEntry.ENTITY_STATUS_CHANGED;
            appendAudit(c, entityId, code, status + ": " + reason);
        } catch (SQLException e) {
            throw storage("set hosted entity status", e);
        }
    }

    @Override
    public void updateMetadata(String entityId, Map<String, Object> metadata) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            requireExists(c, entityId);
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE hosted_entity SET metadata = ? WHERE entity_id = ?")) {
                ps.setString(1, toJson(metadata == null ? Map.of() : metadata));
                ps.setString(2, entityId);
                ps.executeUpdate();
            }
            appendAudit(c, entityId, AuthorityAuditEntry.ENTITY_METADATA_UPDATED,
                    "types=" + (metadata == null ? Map.of() : metadata).keySet());
        } catch (SQLException e) {
            throw storage("update hosted entity metadata", e);
        }
    }

    @Override
    public void rotateHostingKey(String entityId, String newHostingKeyRef) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            requireExists(c, entityId);
            try (PreparedStatement ps = c.prepareStatement(
                    "UPDATE hosted_entity SET hosting_key_ref = ? WHERE entity_id = ?")) {
                ps.setString(1, newHostingKeyRef);
                ps.setString(2, entityId);
                ps.executeUpdate();
            }
            appendAudit(c, entityId, AuthorityAuditEntry.ENTITY_KEY_ROTATED, "hostingKeyRef rotated");
        } catch (SQLException e) {
            throw storage("rotate hosted entity key", e);
        }
    }

    @Override
    public void audit(String entityId, String eventCode, String detail) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            appendAudit(c, entityId, eventCode, detail);
        } catch (SQLException e) {
            throw storage("append hosted entity audit", e);
        }
    }

    @Override
    public List<AuthorityAuditEntry> auditTrail(String entityId) throws AuthorityRegistryException {
        List<AuthorityAuditEntry> trail = new ArrayList<>();
        try (Connection c = this.dataSource.getConnection();
             PreparedStatement ps = c.prepareStatement(
                     "SELECT entity_id, event_code, detail, at FROM hosted_entity_audit_log"
                             + " WHERE entity_id = ? ORDER BY seq")) {
            ps.setString(1, entityId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    trail.add(new AuthorityAuditEntry(rs.getString(1), rs.getString(2), rs.getString(3),
                            instant(rs.getTimestamp(4))));
                }
            }
            return List.copyOf(trail);
        } catch (SQLException e) {
            throw storage("read hosted entity audit trail", e);
        }
    }

    // ---- internals ---------------------------------------------------------------------------

    private static String select() {
        return "SELECT entity_id, hosting_mode, hosting_key_ref, metadata, metadata_policy, status,"
                + " listable, owner_ref, registered_at, not_after FROM hosted_entity";
    }

    private static Optional<HostedEntity> find(Connection c, String entityId) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(select() + " WHERE entity_id = ?")) {
            ps.setString(1, entityId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(readEntity(rs)) : Optional.empty();
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static HostedEntity readEntity(ResultSet rs) throws SQLException {
        return new HostedEntity(
                rs.getString(1),
                HostingMode.valueOf(rs.getString(2)),
                rs.getString(3),
                fromJson(rs.getString(4)),
                fromJson(rs.getString(5)),
                EntityStatus.valueOf(rs.getString(6)),
                rs.getBoolean(7),
                rs.getString(8),
                instant(rs.getTimestamp(9)),
                instant(rs.getTimestamp(10)));
    }

    private static void requireExists(Connection c, String entityId) throws SQLException, AuthorityRegistryException {
        if (find(c, entityId).isEmpty()) {
            throw notFound(entityId);
        }
    }

    private static void appendAudit(Connection c, String entityId, String eventCode, String detail)
            throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO hosted_entity_audit_log (entity_id, event_code, detail, at) VALUES (?,?,?,?)")) {
            ps.setString(1, entityId);
            ps.setString(2, eventCode);
            ps.setString(3, detail);
            ps.setTimestamp(4, timestamp(Instant.now()));
            ps.executeUpdate();
        }
    }

    private static AuthorityRegistryException notFound(String entityId) {
        return new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND,
                "unknown hosted entity: " + entityId);
    }

    private static AuthorityRegistryException storage(String operation, SQLException cause) {
        return new AuthorityRegistryException(AuthorityRegistryException.STORAGE_FAILURE,
                "could not " + operation + ": " + cause.getMessage(), cause);
    }

    private static String toJson(Map<String, Object> map) {
        return JsonUtil.toJson(map == null ? Map.of() : map);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> fromJson(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return JsonUtil.parseJson(json);
        } catch (org.jose4j.lang.JoseException e) {
            // The database only ever holds what toJson produced; a parse failure here means the stored
            // value was corrupted out from under us, not a caller error — surface it as such rather
            // than silently returning an empty map and hiding data loss.
            throw new IllegalStateException("stored hosted-entity JSON is not parseable: " + e.getMessage(), e);
        }
    }

    private static Timestamp timestamp(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }

    private static Instant instant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}
