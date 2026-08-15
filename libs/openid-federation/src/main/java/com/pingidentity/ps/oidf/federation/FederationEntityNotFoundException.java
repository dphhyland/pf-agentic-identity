package com.pingidentity.ps.oidf.federation;

/**
 * The requested entity is not one this federation authority knows about — an unrecognised subordinate,
 * for instance. OpenID Federation's {@code /fetch} endpoint models this as "the entity does not exist
 * here", which is a 404, distinct from a malformed or missing request parameter (400 {@code
 * invalid_request}). A plain {@link IllegalArgumentException} previously covered both cases, so
 * {@link OpenIdFederationServlet} could not tell them apart and returned {@code invalid_request} for
 * both.
 */
public final class FederationEntityNotFoundException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    FederationEntityNotFoundException(String message) {
        super(message);
    }
}
