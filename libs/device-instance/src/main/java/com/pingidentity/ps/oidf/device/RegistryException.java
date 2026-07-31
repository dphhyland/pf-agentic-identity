/*
 * A registry operation failed.
 */
package com.pingidentity.ps.oidf.device;

/**
 * Signals that a registry operation could not be completed — a duplicate registration, an unknown
 * identifier, or a storage fault.
 *
 * <p>Carries a stable {@code reason} for the same purpose as the audit event codes: a refusal must be
 * attributable to a cause without reading the stack trace.
 */
public class RegistryException extends Exception {
    private static final long serialVersionUID = 1L;

    /** The identifier named does not exist. */
    public static final String NOT_FOUND = "not_found";
    /** An identifier that must be unique already exists. */
    public static final String DUPLICATE = "duplicate";
    /** A counter went backwards, or another monotonicity rule was broken. */
    public static final String STALE_UPDATE = "stale_update";
    /** The underlying store failed. */
    public static final String STORAGE_FAILURE = "storage_failure";

    private final String reason;

    public RegistryException(String reason, String message) {
        super(message);
        this.reason = reason;
    }

    public RegistryException(String reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public String reason() {
        return this.reason;
    }
}
