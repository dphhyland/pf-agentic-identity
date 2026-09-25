/*
 * One line of the Trust Mark grant history.
 */
package com.pingidentity.ps.oidf.trustmark;

import java.time.Instant;

/**
 * What happened to a grant, when and by whom: {@code granted} or {@code revoked}.
 *
 * @param type      the Trust Mark type identifier
 * @param subject   the entity
 * @param eventCode {@code granted} or {@code revoked}
 * @param detail    the grant's end, or the reason it was revoked; may be {@code null}
 * @param actor     who did it; may be {@code null}
 * @param at        when
 */
public record TrustMarkAuditEntry(String type, String subject, String eventCode, String detail, String actor, Instant at) {
    public static final String GRANTED = "granted";
    public static final String REVOKED = "revoked";
}
