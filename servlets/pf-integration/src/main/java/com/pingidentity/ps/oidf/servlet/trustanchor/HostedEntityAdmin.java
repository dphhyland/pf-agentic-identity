/*
 * The operator's routes for the entities this authority hosts.
 */
package com.pingidentity.ps.oidf.servlet.trustanchor;

import com.pingidentity.ps.oidf.authority.AuthorityAuditEntry;
import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.authority.AuthoritySupport;
import com.pingidentity.ps.oidf.authority.EntityStatus;
import com.pingidentity.ps.oidf.authority.HostedEntity;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The hosted-entity half of {@link FederationAdminServlet}: every entity whatever its status, one entity with its
 * metadata and policy, its history; and the lifecycle - suspend, reactivate, revoke (permanent), replace the metadata,
 * replace the entity's own {@code metadata_policy} (checked against the domain default first, since it may only narrow
 * it), and move it to a new hosting key (checked to sign first). Every change names its actor in the entity's audit
 * trail and PingFederate's audit log.
 */
final class HostedEntityAdmin {

    /** What a route answers: a status and a JSON body, or an error. */
    record Answer(int status, Object body, String error, String description) {
        static Answer ok(Object body) {
            return new Answer(200, body, null, null);
        }

        static Answer error(int status, String error, String description) {
            return new Answer(status, null, error, description);
        }
    }

    private HostedEntityAdmin() {
    }

    static Answer list(String entityId) throws AuthorityRegistryException {
        if (!AuthoritySupport.isHostingConfigured()) {
            return notHosting();
        }
        if (entityId == null) {
            return Answer.ok(AuthoritySupport.registry().all().stream().map(HostedEntityAdmin::summary).toList());
        }
        Optional<HostedEntity> found = AuthoritySupport.registry().find(entityId);
        if (found.isEmpty()) {
            return Answer.error(404, "not_found", "no hosted entity has that id");
        }
        Map<String, Object> detail = summary(found.get());
        detail.put("metadata", found.get().metadata());
        detail.put("metadata_policy", found.get().metadataPolicy());
        return Answer.ok(detail);
    }

    static Answer audit(String entityId) throws AuthorityRegistryException {
        if (!AuthoritySupport.isHostingConfigured()) {
            return notHosting();
        }
        if (entityId == null) {
            return Answer.error(400, "invalid_request", "name the entity_id");
        }
        return Answer.ok(AuthoritySupport.registry().auditTrail(entityId).stream().map(HostedEntityAdmin::line).toList());
    }

    /** One of the routes that change an entity, by the last segment of its path. */
    static Answer change(String action, Map<String, Object> body, String actor) throws AuthorityRegistryException {
        if (!AuthoritySupport.isHostingConfigured()) {
            return notHosting();
        }
        String entityId = text(body, "entity_id");
        if (entityId == null) {
            return Answer.error(400, "invalid_request", "name the entity_id");
        }
        Optional<HostedEntity> found = AuthoritySupport.registry().find(entityId);
        if (found.isEmpty()) {
            return Answer.error(404, "not_found", "no hosted entity has that id");
        }
        String reason = Optional.ofNullable(text(body, "reason")).orElse("by the operator");
        return switch (action) {
            case "suspend" -> status(found.get(), EntityStatus.SUSPENDED, reason, actor, FederationEvents.HOSTED_ENTITY_SUSPENDED);
            case "reactivate" -> status(found.get(), EntityStatus.ACTIVE, reason, actor, FederationEvents.HOSTED_ENTITY_REACTIVATED);
            case "revoke" -> status(found.get(), EntityStatus.REVOKED, reason, actor, FederationEvents.HOSTED_ENTITY_REVOKED);
            case "metadata" -> metadata(found.get(), body.get("metadata"), actor);
            case "metadata-policy" -> metadataPolicy(found.get(), body.get("metadata_policy"), actor);
            case "rotate-key" -> rotateKey(found.get(), text(body, "hosting_key_ref"), actor);
            default -> Answer.error(404, "not_found", "no such endpoint");
        };
    }

    private static Answer status(HostedEntity entity, EntityStatus status, String reason, String actor, String event)
            throws AuthorityRegistryException {
        if (entity.status() == status) {
            // Nothing changes, so nothing is recorded.
            return changed(entity.entityId());
        }
        if (entity.status() == EntityStatus.REVOKED) {
            return Answer.error(409, "invalid_request", "the entity is revoked, and revocation is permanent");
        }
        AuthoritySupport.registry().setStatus(entity.entityId(), status, reason, actor);
        FederationEvents.event(event).subject(entity.entityId()).role("authority").audit().field("actor", actor).description(reason).emit();
        return changed(entity.entityId());
    }

    @SuppressWarnings("unchecked")
    private static Answer metadata(HostedEntity entity, Object metadata, String actor) throws AuthorityRegistryException {
        if (!isObjectOfObjects(metadata)) {
            return Answer.error(400, "invalid_request", "'metadata' must be an object, one block per entity type");
        }
        AuthoritySupport.registry().updateMetadata(entity.entityId(), (Map<String, Object>) metadata, actor);
        FederationEvents.event(FederationEvents.HOSTED_ENTITY_UPDATED).subject(entity.entityId()).role("authority").audit()
                .field("actor", actor).field("changed", "metadata").emit();
        return changed(entity.entityId());
    }

    @SuppressWarnings("unchecked")
    private static Answer metadataPolicy(HostedEntity entity, Object policy, String actor) throws AuthorityRegistryException {
        if (!isObjectOfObjects(policy)) {
            return Answer.error(400, "invalid_request", "'metadata_policy' must be an object, one block per entity type");
        }
        try {
            AuthoritySupport.requireComposable(entity.withMetadataPolicy((Map<String, Object>) policy));
        } catch (IllegalArgumentException e) {
            return Answer.error(400, "invalid_metadata", e.getMessage());
        }
        AuthoritySupport.registry().updateMetadataPolicy(entity.entityId(), (Map<String, Object>) policy, actor);
        FederationEvents.event(FederationEvents.HOSTED_ENTITY_UPDATED).subject(entity.entityId()).role("authority").audit()
                .field("actor", actor).field("changed", "metadata_policy").emit();
        return changed(entity.entityId());
    }

    private static Answer rotateKey(HostedEntity entity, String hostingKeyRef, String actor) throws AuthorityRegistryException {
        if (hostingKeyRef == null) {
            return Answer.error(400, "invalid_request", "name the hosting_key_ref to move to");
        }
        try {
            // The new key must sign before the entity is moved to it, or its configuration stops resolving.
            AuthoritySupport.hostedEntitySigner().signerFor(entity.withHostingKeyRef(hostingKeyRef)).publicJwk();
        } catch (RuntimeException e) {
            return Answer.error(400, "invalid_request", "that hosting key cannot sign for this authority");
        }
        AuthoritySupport.registry().rotateHostingKey(entity.entityId(), hostingKeyRef, actor);
        FederationEvents.event(FederationEvents.HOSTED_ENTITY_ROTATED).subject(entity.entityId()).role("authority").audit()
                .field("actor", actor).emit();
        return changed(entity.entityId());
    }

    private static Answer changed(String entityId) throws AuthorityRegistryException {
        return Answer.ok(summary(AuthoritySupport.registry().find(entityId).orElseThrow()));
    }

    private static Answer notHosting() {
        return Answer.error(404, "not_found", "this deployment hosts no entities (OIDF_AUTHORITY_ENTITY_ID)");
    }

    private static boolean isObjectOfObjects(Object value) {
        return value instanceof Map<?, ?> map && map.values().stream().allMatch(v -> v instanceof Map);
    }

    private static Map<String, Object> summary(HostedEntity entity) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("entity_id", entity.entityId());
        out.put("status", entity.status().name().toLowerCase(java.util.Locale.ROOT));
        out.put("listable", entity.listable());
        out.put("hosting_key_ref", entity.hostingKeyRef());
        out.put("entity_types", List.copyOf(entity.metadata().keySet()));
        out.put("registered_at", entity.registeredAt().getEpochSecond());
        if (entity.notAfter() != null) {
            out.put("not_after", entity.notAfter().getEpochSecond());
        }
        if (entity.ownerRef() != null) {
            out.put("owner_ref", entity.ownerRef());
        }
        return out;
    }

    private static Map<String, Object> line(AuthorityAuditEntry entry) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("event", entry.eventCode());
        out.put("at", entry.at().getEpochSecond());
        if (entry.detail() != null) {
            out.put("detail", entry.detail());
        }
        if (entry.actor() != null) {
            out.put("actor", entry.actor());
        }
        return out;
    }

    private static String text(Map<String, Object> body, String name) {
        return body.get(name) instanceof String s && !s.isBlank() ? s.trim() : null;
    }
}
