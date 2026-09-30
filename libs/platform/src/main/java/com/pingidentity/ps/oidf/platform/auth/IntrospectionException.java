/*
 * No usable answer from an introspection endpoint.
 */
package com.pingidentity.ps.oidf.platform.auth;

/**
 * The introspection endpoint gave no usable answer: it could not be reached in time, answered with a status other
 * than 200, or with a body {@link TokenIntrospector} could not read. The caller refuses the request as unavailable
 * (503): the token is neither accepted nor called inactive when the authorisation server has not said which it is.
 */
public final class IntrospectionException extends Exception {
    private static final long serialVersionUID = 1L;

    public IntrospectionException(String message) {
        super(message);
    }

    public IntrospectionException(String message, Throwable cause) {
        super(message, cause);
    }
}
