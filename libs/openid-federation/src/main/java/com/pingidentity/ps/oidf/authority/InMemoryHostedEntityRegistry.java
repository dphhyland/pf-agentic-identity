/*
 * A per-process HostedEntityRegistry. Development and tests only.
 */
package com.pingidentity.ps.oidf.authority;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory {@link HostedEntityRegistry}. State does not survive a restart, which is fine for tests and
 * a single-node demo but wrong for anything the authority is meant to serve durably — a restart would
 * silently un-host every entity. Production deployments use {@link JdbcHostedEntityRegistry}.
 */
public final class InMemoryHostedEntityRegistry implements HostedEntityRegistry {

    private final Map<String, HostedEntity> entities = new ConcurrentHashMap<>();
    private final Map<String, List<AuthorityAuditEntry>> audit = new ConcurrentHashMap<>();

    @Override
    public synchronized HostedEntity register(HostedEntity entity) throws AuthorityRegistryException {
        if (this.entities.containsKey(entity.entityId())) {
            throw new AuthorityRegistryException(AuthorityRegistryException.DUPLICATE,
                    "entity already hosted: " + entity.entityId());
        }
        this.entities.put(entity.entityId(), entity);
        appendAudit(entity.entityId(), AuthorityAuditEntry.ENTITY_REGISTERED, "hostingMode=" + entity.hostingMode());
        return entity;
    }

    @Override
    public Optional<HostedEntity> find(String entityId) {
        return Optional.ofNullable(this.entities.get(entityId));
    }

    @Override
    public List<HostedEntity> list(String entityType) {
        Instant now = Instant.now();
        List<HostedEntity> out = new ArrayList<>();
        for (HostedEntity e : this.entities.values()) {
            if (!e.listable() || !e.resolvable(now)) {
                continue;
            }
            if (entityType != null && !e.hasType(entityType)) {
                continue;
            }
            out.add(e);
        }
        return List.copyOf(out);
    }

    @Override
    public synchronized void setStatus(String entityId, EntityStatus status, String reason)
            throws AuthorityRegistryException {
        HostedEntity current = require(entityId);
        if (current.status() == status) {
            // Idempotent — covers a retried REVOKED -> REVOKED just as much as ACTIVE -> ACTIVE, which
            // is why this check must run before the "already revoked" guard below, not after it.
            return;
        }
        if (current.status() == EntityStatus.REVOKED) {
            throw new AuthorityRegistryException(AuthorityRegistryException.STALE_UPDATE,
                    "entity " + entityId + " is revoked; revocation is permanent");
        }
        this.entities.put(entityId, current.withStatus(status));
        String code = status == EntityStatus.REVOKED
                ? AuthorityAuditEntry.ENTITY_REVOKED : AuthorityAuditEntry.ENTITY_STATUS_CHANGED;
        appendAudit(entityId, code, status + ": " + reason);
    }

    @Override
    public synchronized void updateMetadata(String entityId, Map<String, Object> metadata)
            throws AuthorityRegistryException {
        HostedEntity current = require(entityId);
        this.entities.put(entityId, current.withMetadata(metadata));
        appendAudit(entityId, AuthorityAuditEntry.ENTITY_METADATA_UPDATED, "types=" + metadata.keySet());
    }

    @Override
    public synchronized void rotateHostingKey(String entityId, String newHostingKeyRef)
            throws AuthorityRegistryException {
        HostedEntity current = require(entityId);
        this.entities.put(entityId, current.withHostingKeyRef(newHostingKeyRef));
        appendAudit(entityId, AuthorityAuditEntry.ENTITY_KEY_ROTATED, "hostingKeyRef rotated");
    }

    @Override
    public synchronized void audit(String entityId, String eventCode, String detail) {
        appendAudit(entityId, eventCode, detail);
    }

    @Override
    public synchronized List<AuthorityAuditEntry> auditTrail(String entityId) {
        List<AuthorityAuditEntry> trail = this.audit.get(entityId);
        return trail == null ? List.of() : List.copyOf(trail);
    }

    private HostedEntity require(String entityId) throws AuthorityRegistryException {
        HostedEntity current = this.entities.get(entityId);
        if (current == null) {
            throw new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND,
                    "unknown hosted entity: " + entityId);
        }
        return current;
    }

    /** Callers hold the instance monitor (every public method here is {@code synchronized}). */
    private void appendAudit(String entityId, String eventCode, String detail) {
        this.audit.computeIfAbsent(entityId, ignored -> new ArrayList<>())
                .add(new AuthorityAuditEntry(entityId, eventCode, detail, Instant.now()));
    }
}
