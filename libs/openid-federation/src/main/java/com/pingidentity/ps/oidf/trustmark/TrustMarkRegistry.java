/*
 * Where Trust Mark grants are kept.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * The grants this entity issues Trust Marks under, and their history. One grant per type and subject: granting again
 * replaces it, revoking keeps it, marked revoked. Every change writes its audit line in the same transaction.
 */
public interface TrustMarkRegistry {

    /**
     * Grants {@code type} to {@code subject} until {@code notAfter} ({@code null}: until revoked), or grants it again -
     * which starts it afresh, so marks minted under an earlier grant stay revoked.
     */
    TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) throws AuthorityRegistryException;

    Optional<TrustMarkGrant> find(String type, String subject) throws AuthorityRegistryException;

    /** Every grant to {@code subject}, whatever its status. */
    List<TrustMarkGrant> grantsTo(String subject) throws AuthorityRegistryException;

    /** Every grant of {@code type}, whatever its status. */
    List<TrustMarkGrant> grantsOf(String type) throws AuthorityRegistryException;

    /**
     * Revokes the grant. Revoking a revoked grant changes nothing.
     *
     * @throws AuthorityRegistryException {@link AuthorityRegistryException#NOT_FOUND} when there is no such grant
     */
    TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException;

    /** The history of one grant, oldest first. */
    List<TrustMarkAuditEntry> auditTrail(String type, String subject) throws AuthorityRegistryException;
}
