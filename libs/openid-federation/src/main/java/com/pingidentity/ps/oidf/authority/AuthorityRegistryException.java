/*
 * A hosted-entity registry operation failed.
 */
package com.pingidentity.ps.oidf.authority;

/**
 * Signals that a {@link HostedEntityRegistry} operation could not be completed — a duplicate entity id,
 * an unknown entity, an invalid state transition, or a storage fault.
 *
 * <p>Carries a stable {@code reason} so a caller (and a servlet mapping this to an HTTP status) can
 * attribute the failure without inspecting the message string.
 */
public class AuthorityRegistryException extends Exception {
    private static final long serialVersionUID = 1L;

    /** The entity id named does not exist. */
    public static final String NOT_FOUND = "not_found";
    /** An entity id that must be unique already exists. */
    public static final String DUPLICATE = "duplicate";
    /** The requested change is invalid for the entity's current state — e.g. reviving a revoked entity. */
    public static final String STALE_UPDATE = "stale_update";
    /** The underlying store failed. */
    public static final String STORAGE_FAILURE = "storage_failure";

    private final String reason;

    public AuthorityRegistryException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public AuthorityRegistryException(String reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public String reason() {
        return this.reason;
    }
}
