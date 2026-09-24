package com.pingidentity.ps.oidf.servlet.clientregistration;

import com.pingidentity.ps.oidf.federation.FederationException;

/**
 * A registration request that was understood and validated but must not proceed - carries the HTTP
 * status and OAuth-style error code the servlet returns, and what kind of failure it was. Distinct from
 * {@link IllegalArgumentException} (malformed / unverifiable input → 400) so the servlet can say
 * <em>why</em>: a 409 for a client id this module does not own is a different answer from a 400 for a bad
 * JWT. The token endpoint needs the {@link Kind}: a federation it could not reach is not a federation that
 * said no.
 */
final class RegistrationRejectedException extends Exception {
    private static final long serialVersionUID = 1L;

    /** What refused the registration. */
    enum Kind {
        /** The trust chain did not validate, or no longer does. */
        TRUST,
        /** The resolved metadata cannot become a client here. */
        METADATA,
        /** A policy of this deployment refused it. */
        POLICY,
        /** An entity in the chain could not be reached: worth retrying, and no evidence against the client. */
        TRANSPORT,
        /** A fault of ours. */
        INTERNAL
    }

    private final int status;
    private final String error;
    private final Kind kind;

    RegistrationRejectedException(int status, String error, String description) {
        this(status, error, description, Kind.METADATA, null);
    }

    RegistrationRejectedException(int status, String error, String description, Kind kind, Throwable cause) {
        super(description, cause);
        this.status = status;
        this.error = error;
        this.kind = kind;
    }

    /** A refusal from the federation layer, keeping its §8.9 code and status. */
    static RegistrationRejectedException from(FederationException e) {
        Kind kind = switch (e.error()) {
            case TEMPORARILY_UNAVAILABLE -> Kind.TRANSPORT;
            case INVALID_METADATA -> Kind.METADATA;
            case SERVER_ERROR -> Kind.INTERNAL;
            default -> Kind.TRUST;
        };
        return new RegistrationRejectedException(e.error().httpStatus(), e.error().code(), e.description(), kind, e);
    }

    int status() {
        return this.status;
    }

    String error() {
        return this.error;
    }

    Kind kind() {
        return this.kind;
    }

    /** True for a federation that could not be reached, as against one that refused. */
    boolean isTransport() {
        return this.kind == Kind.TRANSPORT;
    }
}
