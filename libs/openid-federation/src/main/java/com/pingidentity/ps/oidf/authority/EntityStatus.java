/*
 * Lifecycle state of a hosted federation entity.
 */
package com.pingidentity.ps.oidf.authority;

/**
 * Whether a hosted entity still resolves.
 *
 * <p>Setting an entity to {@link #REVOKED} makes the next resolution against it fail — a fetch for the
 * entity's subordinate statement, and a chain validation that reaches it — with no per-request
 * revocation infrastructure at the resolving party. That is the whole point of the authority hosting
 * the entity's metadata rather than the entity itself: it is a single, immediate revocation lever.
 */
public enum EntityStatus {

    /** Resolves normally, subject to {@code notAfter}. */
    ACTIVE,

    /** Temporarily barred — reversible. */
    SUSPENDED,

    /** Permanently barred. Re-registration under a new entity id creates a distinct entity. */
    REVOKED;

    /** Only an active entity may be resolved; everything else fails closed. */
    public boolean canResolve() {
        return this == ACTIVE;
    }
}
