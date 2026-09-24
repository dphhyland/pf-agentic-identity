/*
 * A federation failure that already knows how it is answered.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.Objects;

/**
 * A failure carrying the OpenID Federation 1.0 §8.9 {@link FederationError} it is answered with, and a
 * description that is safe to put in {@code error_description}: written by this code, never copied from
 * a token or a library message.
 */
public class FederationException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final FederationError error;

    public FederationException(FederationError error, String description) {
        super(description);
        this.error = Objects.requireNonNull(error, "error");
    }

    public FederationException(FederationError error, String description, Throwable cause) {
        super(description, cause);
        this.error = Objects.requireNonNull(error, "error");
    }

    public FederationError error() {
        return this.error;
    }

    /** The description for {@code error_description}. */
    public String description() {
        return this.getMessage();
    }
}
