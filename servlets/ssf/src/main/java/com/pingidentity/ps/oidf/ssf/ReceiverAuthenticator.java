/*
 * Validates the OAuth bearer token a receiver presents to the SSF endpoints.
 */
package com.pingidentity.ps.oidf.ssf;

/**
 * Authenticates a receiver by validating its OAuth bearer token against PingFederate (the token is one PF
 * itself issued via client_credentials with the configured {@code receiverScope}). This is deliberately not
 * a bespoke scheme — the runtime implementation is {@link PfIntrospectionReceiverAuthenticator}, and tests
 * substitute a fake. Returns an {@link AuthContext}; scope enforcement is the caller's.
 */
public interface ReceiverAuthenticator {

    /**
     * Validate a bearer token.
     *
     * @param bearerToken the raw token from the {@code Authorization: Bearer} header (never null/blank)
     * @return the token's {@link AuthContext} (inactive if the token is invalid/expired/unknown)
     * @throws ReceiverAuthException if validation could not be performed (e.g. the introspection call failed)
     */
    AuthContext authenticate(String bearerToken) throws ReceiverAuthException;
}
