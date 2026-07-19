/*
 * The result of authenticating a receiver's OAuth bearer token.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.Set;

/**
 * The outcome of validating the bearer token a receiver presents to the SSF management/poll endpoints:
 * whether the token is active, and (if so) the client it identifies and the scopes it carries. Scope
 * enforcement (e.g. {@code ssf.manage}) is applied by the caller via {@link #hasScope}.
 */
public final class AuthContext {

    private final boolean active;
    private final String clientId;
    private final Set<String> scopes;

    private AuthContext(boolean active, String clientId, Set<String> scopes) {
        this.active = active;
        this.clientId = clientId;
        this.scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
    }

    public static AuthContext active(String clientId, Set<String> scopes) {
        return new AuthContext(true, clientId, scopes);
    }

    public static AuthContext inactive() {
        return new AuthContext(false, null, Set.of());
    }

    public boolean isActive() {
        return this.active;
    }

    public String clientId() {
        return this.clientId;
    }

    public Set<String> scopes() {
        return this.scopes;
    }

    public boolean hasScope(String scope) {
        return this.active && this.scopes.contains(scope);
    }
}
