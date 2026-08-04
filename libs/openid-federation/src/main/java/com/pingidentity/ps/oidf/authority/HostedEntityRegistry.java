/*
 * Seam: the authoritative store of federation entities this authority hosts on behalf of.
 */
package com.pingidentity.ps.oidf.authority;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The hosted-entity registry — the durable record behind the entity configurations and subordinate
 * statements the authority serves for entities that cannot host their own. A sibling of, and
 * deliberately not coupled to, an instance registry such as {@code libs/device-instance}'s: this is a
 * publishing concern (what metadata does the federation see for this entity), not an identity-resolution
 * concern (which human does this opaque id resolve to). {@code libs/openid-federation} must not depend
 * on a device- or instance-specific module.
 *
 * <p>Implementations must be safe for concurrent use.
 */
public interface HostedEntityRegistry {

    /** Records a new hosted entity. The entity resolves from this moment (subject to its status). */
    HostedEntity register(HostedEntity entity) throws AuthorityRegistryException;

    Optional<HostedEntity> find(String entityId) throws AuthorityRegistryException;

    /**
     * Hosted entities of one metadata type, active, resolvable now, and marked {@code listable}. Passing
     * {@code null} for {@code entityType} returns every listable active entity regardless of type.
     */
    List<HostedEntity> list(String entityType) throws AuthorityRegistryException;

    /**
     * Changes an entity's status. Idempotent when the requested status already holds. Reviving a
     * {@link EntityStatus#REVOKED} entity is refused — revocation is permanent, matching
     * {@link EntityStatus}'s own contract.
     */
    void setStatus(String entityId, EntityStatus status, String reason) throws AuthorityRegistryException;

    /** Replaces an entity's published {@code metadata}, without changing its id, key, or status. */
    void updateMetadata(String entityId, Map<String, Object> metadata) throws AuthorityRegistryException;

    /** Points an {@link HostingMode#AUTHORITY_SIGNED} entity at a new hosting key (key rotation). */
    void rotateHostingKey(String entityId, String newHostingKeyRef) throws AuthorityRegistryException;

    /** Appends to the audit log. Never updates or deletes — the log is the dispute record. */
    void audit(String entityId, String eventCode, String detail) throws AuthorityRegistryException;

    /** The audit trail for one entity, oldest first. */
    List<AuthorityAuditEntry> auditTrail(String entityId) throws AuthorityRegistryException;
}
