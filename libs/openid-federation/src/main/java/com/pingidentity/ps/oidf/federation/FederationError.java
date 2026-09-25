/*
 * The error codes a federation endpoint answers with.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.Locale;

/**
 * OpenID Federation 1.0 §8.9: the error codes a federation endpoint uses, each with the HTTP status the
 * specification says it SHOULD carry. One place, so every servlet answers the same failure the same way.
 */
public enum FederationError {
    /** "The request is incomplete or does not comply with current specifications." 400. */
    INVALID_REQUEST(400),
    /** "The server encountered an unexpected condition." 500. */
    SERVER_ERROR(500),
    /** "The server ... is currently unable to handle the request due to temporary overloading or maintenance." 503. */
    TEMPORARILY_UNAVAILABLE(503),
    /** "The Client cannot be authorized or is not a valid participant of the federation." 401. */
    INVALID_CLIENT(401),
    /** "The endpoint cannot serve the requested issuer." 404. */
    INVALID_ISSUER(404),
    /** "The endpoint cannot serve the requested subject." 404. */
    INVALID_SUBJECT(404),
    /** "The Trust Anchor cannot be found or used." 404. */
    INVALID_TRUST_ANCHOR(404),
    /** "The Trust Chain cannot be validated." 400. */
    INVALID_TRUST_CHAIN(400),
    /** "Metadata or Metadata Policy values are invalid or conflict." 400. */
    INVALID_METADATA(400),
    /** "The requested Entity Identifier cannot be found." 404. */
    NOT_FOUND(404),
    /** "The server does not support the requested parameter." 400. */
    UNSUPPORTED_PARAMETER(400);

    private final int httpStatus;

    FederationError(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    /** The HTTP status §8.9 says this error SHOULD carry. */
    public int httpStatus() {
        return this.httpStatus;
    }

    /** The wire code, e.g. {@code invalid_trust_chain}. */
    public String code() {
        return this.name().toLowerCase(Locale.ROOT);
    }
}
