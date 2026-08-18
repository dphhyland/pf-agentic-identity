package com.pingidentity.ps.oidf.servlet.clientregistration;

/**
 * A registration request that was understood and validated but must not proceed - carries the HTTP
 * status and OAuth-style error code the servlet returns. Distinct from {@link IllegalArgumentException}
 * (malformed / unverifiable input → 400) so the servlet can say <em>why</em>: a 409 for a client id
 * this module does not own is a different answer from a 400 for a bad JWT.
 */
final class RegistrationRejectedException extends Exception {
    private static final long serialVersionUID = 1L;
    private final int status;
    private final String error;

    RegistrationRejectedException(int status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    int status() {
        return this.status;
    }

    String error() {
        return this.error;
    }
}
