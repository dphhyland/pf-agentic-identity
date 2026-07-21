/*
 * Raised when an SD-JWT presentation is malformed or a disclosure does not match the issuer JWT.
 */
package com.pingidentity.ps.oidf.common;

/** Unchecked failure decoding / reconstructing an SD-JWT (draft-ietf-oauth-selective-disclosure-jwt). */
public final class SdJwtException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public SdJwtException(String message) {
        super(message);
    }

    public SdJwtException(String message, Throwable cause) {
        super(message, cause);
    }
}
