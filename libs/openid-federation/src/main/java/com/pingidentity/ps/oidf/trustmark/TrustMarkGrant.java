/*
 * The right of one entity to Trust Marks of one type.
 */
package com.pingidentity.ps.oidf.trustmark;

import java.time.Instant;
import java.util.Objects;

/**
 * That this entity issues Trust Marks of {@code type} to {@code subject}. A mark is only ever minted under an active
 * grant, and a grant given again after it was revoked starts afresh: marks minted before {@code grantedAt} belong to
 * the grant that was revoked.
 *
 * @param type      the Trust Mark type identifier
 * @param subject   the entity it is granted to
 * @param status    whether it stands
 * @param grantedAt when it was (last) granted
 * @param notAfter  when it ends by itself; {@code null} for when it is revoked
 * @param revokedAt when it was revoked; {@code null} while it stands
 * @param reason    why it was revoked; {@code null} while it stands
 * @param actor     who granted it, or who revoked it
 */
public record TrustMarkGrant(String type, String subject, Status status, Instant grantedAt, Instant notAfter, Instant revokedAt,
                             String reason, String actor) {

    public enum Status {
        ACTIVE, REVOKED
    }

    public TrustMarkGrant {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(grantedAt, "grantedAt");
    }

    /** Whether it stands at {@code now}: not revoked, and not past its end. */
    public boolean activeAt(Instant now) {
        return this.status == Status.ACTIVE && (this.notAfter == null || now.isBefore(this.notAfter));
    }
}
