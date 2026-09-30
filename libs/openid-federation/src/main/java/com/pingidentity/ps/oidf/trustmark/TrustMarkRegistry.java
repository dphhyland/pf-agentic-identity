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
     *
     * @throws AuthorityRegistryException {@link AuthorityRegistryException#STALE_UPDATE} when the grant changed between
     *                                    being read and being written, which then writes nothing
     */
    TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) throws AuthorityRegistryException;

    Optional<TrustMarkGrant> find(String type, String subject) throws AuthorityRegistryException;

    /** Every grant to {@code subject}, whatever its status. */
    List<TrustMarkGrant> grantsTo(String subject) throws AuthorityRegistryException;

    /** Every grant of {@code type}, whatever its status. */
    List<TrustMarkGrant> grantsOf(String type) throws AuthorityRegistryException;

    /**
     * The grants of {@code type} that stand at {@code now} ({@link TrustMarkGrant#activeAt}) - to {@code subject}, in
     * either spelling {@link com.pingidentity.ps.oidf.federation.EntityId#same} equates, or to anyone when it is null -
     * in one read of the store (plan item H-FED-9), ordered by subject.
     */
    List<TrustMarkGrant> standing(String type, String subject, Instant now) throws AuthorityRegistryException;

    /**
     * Revokes the grant. Revoking a revoked grant changes nothing.
     *
     * @throws AuthorityRegistryException {@link AuthorityRegistryException#NOT_FOUND} when there is no such grant;
     *                                    {@link AuthorityRegistryException#STALE_UPDATE} when the grant changed between
     *                                    being read and being revoked, which then writes nothing
     */
    TrustMarkGrant revoke(String type, String subject, String reason, String actor) throws AuthorityRegistryException;

    /** The history of one grant, oldest first. */
    List<TrustMarkAuditEntry> auditTrail(String type, String subject) throws AuthorityRegistryException;
}
