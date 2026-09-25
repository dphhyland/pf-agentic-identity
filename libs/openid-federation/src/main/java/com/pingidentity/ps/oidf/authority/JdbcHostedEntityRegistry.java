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
 * {@code db/migration/V100__hosted_entity.sql} and {@code V101__hosted_entity_actor.sql}.
 *
 * <p>Written against {@code javax.sql.DataSource} and plain JDBC rather than an ORM, matching the same
 * two reasons an instance registry in this codebase would give: the resolution and revocation queries
 * are the whole contract, and an ORM would obscure exactly the one that matters — the status check that
 * gates whether an entity resolves.
 *
 * <p>Every change and its audit line are written in one transaction: the audit log is the record a dispute
 * is settled from, so it must never say something happened that did not, or miss something that did.
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

    /** A unit of work in one transaction. */
    private interface Work<T> {
        T run(Connection c) throws SQLException, AuthorityRegistryException;
    }

    private <T> T inTransaction(String operation, Work<T> work) throws AuthorityRegistryException {
        try (Connection c = this.dataSource.getConnection()) {
            c.setAutoCommit(false);
            try {
                T result = work.run(c);
                c.commit();
                return result;
            } catch (SQLException | AuthorityRegistryException | RuntimeException e) {
                c.rollback();
                throw e;
            }
        } catch (SQLException e) {
            throw storage(operation, e);
        }
    }

    @Override
    public HostedEntity register(HostedEntity entity, String actor) throws AuthorityRegistryException {
        return this.inTransaction("register hosted entity", c -> registerIn(c, entity, actor));
    }

    private static HostedEntity registerIn(Connection c, HostedEntity entity, String actor) throws SQLException, AuthorityRegistryException {
        if (find(c, entity.entityId()).isPresent()) {
            throw new AuthorityRegistryException(AuthorityRegistryException.DUPLICATE, "entity already hosted: " + entity.entityId());
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
        appendAudit(c, entity.entityId(), AuthorityAuditEntry.ENTITY_REGISTERED, "hostingMode=" + entity.hostingMode(), actor);
        return entity;
    }

    @Override
    public Optional<HostedEntity> find(String entityId) throws AuthorityRegistryException {
        return this.inTransaction("find hosted entity", c -> find(c, entityId));
    }

    @Override
    public List<HostedEntity> list(String entityType) throws AuthorityRegistryException {
        return this.inTransaction("list hosted entities", c -> listIn(c, entityType));
    }

    private static List<HostedEntity> listIn(Connection c, String entityType) throws SQLException {
        List<HostedEntity> out = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(select() + " WHERE status = 'ACTIVE' AND listable = TRUE"
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
        }
        return List.copyOf(out);
    }

    @Override
    public List<HostedEntity> all() throws AuthorityRegistryException {
        return this.inTransaction("list hosted entities", JdbcHostedEntityRegistry::allIn);
    }

    private static List<HostedEntity> allIn(Connection c) throws SQLException {
        List<HostedEntity> out = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(select() + " ORDER BY entity_id"); ResultSet rs = ps.executeQuery()) {
            while (rs.next()) {
                out.add(readEntity(rs));
            }
        }
        return List.copyOf(out);
    }

    @Override
    public void setStatus(String entityId, EntityStatus status, String reason, String actor) throws AuthorityRegistryException {
        this.inTransaction("set hosted entity status", c -> setStatusIn(c, entityId, status, reason, actor));
    }

    private static Void setStatusIn(Connection c, String entityId, EntityStatus status, String reason, String actor)
            throws SQLException, AuthorityRegistryException {
        HostedEntity current = find(c, entityId).orElseThrow(() -> notFound(entityId));
        if (current.status() == status) {
            // Idempotent — covers a retried REVOKED -> REVOKED just as much as ACTIVE -> ACTIVE,
            // which is why this must run before the "already revoked" guard below, not after it.
            return null;
        }
        if (current.status() == EntityStatus.REVOKED) {
            throw new AuthorityRegistryException(AuthorityRegistryException.STALE_UPDATE,
                    "entity " + entityId + " is revoked; revocation is permanent");
        }
        update(c, "UPDATE hosted_entity SET status = ? WHERE entity_id = ?", status.name(), entityId);
        String code = status == EntityStatus.REVOKED ? AuthorityAuditEntry.ENTITY_REVOKED : AuthorityAuditEntry.ENTITY_STATUS_CHANGED;
        appendAudit(c, entityId, code, status + ": " + reason, actor);
        return null;
    }

    @Override
    public void updateMetadata(String entityId, Map<String, Object> metadata, String actor) throws AuthorityRegistryException {
        Map<String, Object> value = Objects.requireNonNull(metadata, "metadata");
        this.inTransaction("update hosted entity metadata", c -> {
            requireExists(c, entityId);
            update(c, "UPDATE hosted_entity SET metadata = ? WHERE entity_id = ?", toJson(value), entityId);
            appendAudit(c, entityId, AuthorityAuditEntry.ENTITY_METADATA_UPDATED, "types=" + value.keySet(), actor);
            return null;
        });
    }

    @Override
    public void updateMetadataPolicy(String entityId, Map<String, Object> metadataPolicy, String actor) throws AuthorityRegistryException {
        Map<String, Object> value = Objects.requireNonNull(metadataPolicy, "metadataPolicy");
        this.inTransaction("update hosted entity metadata policy", c -> {
            requireExists(c, entityId);
            update(c, "UPDATE hosted_entity SET metadata_policy = ? WHERE entity_id = ?", toJson(value), entityId);
            appendAudit(c, entityId, AuthorityAuditEntry.ENTITY_METADATA_POLICY_UPDATED, "types=" + value.keySet(), actor);
            return null;
        });
    }

    @Override
    public void rotateHostingKey(String entityId, String newHostingKeyRef, String actor) throws AuthorityRegistryException {
        this.inTransaction("rotate hosted entity key", c -> {
            requireExists(c, entityId);
            update(c, "UPDATE hosted_entity SET hosting_key_ref = ? WHERE entity_id = ?", newHostingKeyRef, entityId);
            appendAudit(c, entityId, AuthorityAuditEntry.ENTITY_KEY_ROTATED, "hostingKeyRef rotated", actor);
            return null;
        });
    }

    @Override
    public void audit(String entityId, String eventCode, String detail) throws AuthorityRegistryException {
        this.inTransaction("append hosted entity audit", c -> {
            appendAudit(c, entityId, eventCode, detail, null);
            return null;
        });
    }

    @Override
    public List<AuthorityAuditEntry> auditTrail(String entityId) throws AuthorityRegistryException {
        return this.inTransaction("read hosted entity audit trail", c -> auditTrailIn(c, entityId));
    }

    private static List<AuthorityAuditEntry> auditTrailIn(Connection c, String entityId) throws SQLException {
        List<AuthorityAuditEntry> trail = new ArrayList<>();
        try (PreparedStatement ps = c.prepareStatement(
                "SELECT entity_id, event_code, detail, at, actor FROM hosted_entity_audit_log WHERE entity_id = ? ORDER BY seq")) {
            ps.setString(1, entityId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    trail.add(new AuthorityAuditEntry(rs.getString(1), rs.getString(2), rs.getString(3), instant(rs.getTimestamp(4)),
                            rs.getString(5)));
                }
            }
        }
        return List.copyOf(trail);
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

    private static void update(Connection c, String sql, String... parameters) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                ps.setString(i + 1, parameters[i]);
            }
            ps.executeUpdate();
        }
    }

    private static void appendAudit(Connection c, String entityId, String eventCode, String detail, String actor) throws SQLException {
        try (PreparedStatement ps = c.prepareStatement(
                "INSERT INTO hosted_entity_audit_log (entity_id, event_code, detail, at, actor) VALUES (?,?,?,?,?)")) {
            ps.setString(1, entityId);
            ps.setString(2, eventCode);
            ps.setString(3, detail);
            ps.setTimestamp(4, timestamp(Instant.now()));
            ps.setString(5, actor);
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
