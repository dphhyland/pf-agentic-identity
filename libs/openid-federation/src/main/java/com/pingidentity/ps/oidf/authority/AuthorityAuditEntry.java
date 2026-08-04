/*
 * One append-only audit record for a hosted entity.
 */
package com.pingidentity.ps.oidf.authority;

import java.time.Instant;

/**
 * One entry of a {@link HostedEntity}'s audit trail. The log is append-only — no update or delete path
 * exists on any implementation — because it is the record a dispute about "who could resolve this
 * entity, and when" is settled from.
 */
public record AuthorityAuditEntry(String entityId, String eventCode, String detail, Instant at) {

    public static final String ENTITY_REGISTERED = "entity_registered";
    public static final String ENTITY_STATUS_CHANGED = "entity_status_changed";
    public static final String ENTITY_REVOKED = "entity_revoked";
    public static final String ENTITY_METADATA_UPDATED = "entity_metadata_updated";
    public static final String ENTITY_KEY_ROTATED = "entity_key_rotated";
}
