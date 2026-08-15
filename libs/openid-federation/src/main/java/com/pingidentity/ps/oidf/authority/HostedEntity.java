/*
 * A federation entity the authority hosts metadata for, on the entity's behalf.
 */
package com.pingidentity.ps.oidf.authority;

import java.time.Instant;
import java.util.Map;

/**
 * One entity the authority hosts: an agent type (registered once per OAuth client — see the Domain
 * Authority plan's identity model, where an <em>instance</em> is a claim inside an attestation, not a
 * separately hosted entity) or a protected resource that cannot publish its own federation metadata.
 *
 * <p>{@code metadata} is the entity's full {@code metadata} claim exactly as it will be published —
 * one block per entity type, keyed by type name (e.g. {@code oauth_client}, {@code oauth_resource},
 * {@code oauth_client_attestation}), the same shape
 * {@link com.pingidentity.ps.oidf.federation.TrustChainValidationResult#resolvedMetadata()} surfaces
 * on the resolving side. An entity holding more
 * than one type at once (an agent is typically both {@code oauth_client} and {@code oauth_resource}) is
 * exactly the case Phase 0.1 made resolvable — this hosts it, rather than merely resolving it.
 *
 * <p>{@code metadataPolicy} is this specific entity's {@code metadata_policy}, narrowed against the
 * domain-wide default at statement-issuance time and emitted on the subordinate statement the authority
 * issues about this entity (composed via {@link com.pingidentity.ps.oidf.federation.MetadataPolicy}, the
 * same fail-closed composition Phase 0.2 wired into chain validation). Independent of, and not applied
 * to, this entity's own {@code metadata} — it constrains what a relying party may trust the entity for,
 * it is not a filter on what is stored here.
 *
 * @param entityId       the entity's federation identifier — an HTTPS URL under the authority's own
 *                        domain (e.g. {@code https://as.example.com/agents/<id>}), permanent for the
 *                        life of this row
 * @param hostingMode     how the entity's configuration is signed
 * @param hostingKeyRef   an opaque reference to the signing key (an OpenBao transit key name) —
 *                        required when {@code hostingMode} is {@link HostingMode#AUTHORITY_SIGNED},
 *                        must be {@code null} otherwise
 * @param metadata        the entity's {@code metadata} claim, one block per entity type
 * @param metadataPolicy  this entity's {@code metadata_policy}, one block per entity type; empty if none
 * @param status          whether the entity currently resolves
 * @param listable        whether this entity appears in {@code /federation/list}. Defaults to
 *                        {@code false} at construction via {@link #hosted}: listing an agent publishes
 *                        an inventory of pseudonymous identifiers keyed by exactly the value whose whole
 *                        purpose is being uncorrelatable without the registry.
 * @param ownerRef        free-form: who or what registered this entity (an operator id, a CI job, the
 *                        client id it was registered for) — accountability, not an access-control field
 * @param registeredAt    when this row was created
 * @param notAfter        an optional hard expiry; {@code null} means no expiry beyond {@code status}
 */
public record HostedEntity(
        String entityId,
        HostingMode hostingMode,
        String hostingKeyRef,
        Map<String, Object> metadata,
        Map<String, Object> metadataPolicy,
        EntityStatus status,
        boolean listable,
        String ownerRef,
        Instant registeredAt,
        Instant notAfter) {

    public HostedEntity {
        if (entityId == null || entityId.isBlank()) {
            throw new IllegalArgumentException("entityId must not be blank");
        }
        if (hostingMode == null) {
            throw new IllegalArgumentException("hostingMode must not be null");
        }
        if (hostingMode == HostingMode.AUTHORITY_SIGNED && (hostingKeyRef == null || hostingKeyRef.isBlank())) {
            throw new IllegalArgumentException("hostingKeyRef is required when hostingMode is AUTHORITY_SIGNED");
        }
        if (hostingMode == HostingMode.SELF_SIGNED && hostingKeyRef != null) {
            throw new IllegalArgumentException("hostingKeyRef must be null when hostingMode is SELF_SIGNED — "
                    + "the authority holds no key for a self-signed entity");
        }
        if (status == null) {
            throw new IllegalArgumentException("status must not be null");
        }
        if (registeredAt == null) {
            throw new IllegalArgumentException("registeredAt must not be null");
        }
        metadata = metadata == null ? Map.of() : Map.copyOf(metadata);
        metadataPolicy = metadataPolicy == null ? Map.of() : Map.copyOf(metadataPolicy);
    }

    /** Convenience constructor for the common case: authority-signed, not listable, no expiry. */
    public static HostedEntity hosted(String entityId, String hostingKeyRef, Map<String, Object> metadata,
            String ownerRef) {
        return new HostedEntity(entityId, HostingMode.AUTHORITY_SIGNED, hostingKeyRef, metadata, Map.of(),
                EntityStatus.ACTIVE, false, ownerRef, Instant.now(), null);
    }

    public HostedEntity withStatus(EntityStatus newStatus) {
        return new HostedEntity(this.entityId, this.hostingMode, this.hostingKeyRef, this.metadata,
                this.metadataPolicy, newStatus, this.listable, this.ownerRef, this.registeredAt, this.notAfter);
    }

    public HostedEntity withMetadata(Map<String, Object> newMetadata) {
        return new HostedEntity(this.entityId, this.hostingMode, this.hostingKeyRef, newMetadata,
                this.metadataPolicy, this.status, this.listable, this.ownerRef, this.registeredAt, this.notAfter);
    }

    public HostedEntity withHostingKeyRef(String newHostingKeyRef) {
        return new HostedEntity(this.entityId, this.hostingMode, newHostingKeyRef, this.metadata,
                this.metadataPolicy, this.status, this.listable, this.ownerRef, this.registeredAt, this.notAfter);
    }

    /** Whether the entity holds the named metadata type at all (e.g. {@code "oauth_client"}). */
    public boolean hasType(String entityType) {
        return this.metadata.containsKey(entityType);
    }

    /** Whether this entity currently resolves: active status and, if set, not past {@code notAfter}. */
    public boolean resolvable(Instant now) {
        return this.status.canResolve() && (this.notAfter == null || now.isBefore(this.notAfter));
    }
}
