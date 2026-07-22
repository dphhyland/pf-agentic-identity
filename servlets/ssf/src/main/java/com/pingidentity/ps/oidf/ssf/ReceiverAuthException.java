/*
 * Thrown when a receiver's bearer token could not be validated (transport/config failure, not "invalid token").
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * Signals that receiver authentication could not be performed — an introspection transport error or a
 * misconfiguration — as distinct from a well-formed "token is inactive" answer (which is a valid
 * {@link AuthContext#inactive()}). Servlets map this to {@code 503}, an inactive token to {@code 401}.
 */
public class ReceiverAuthException extends Exception {

    private static final long serialVersionUID = 1L;

    public ReceiverAuthException(String message) {
        super(message);
    }

    public ReceiverAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
