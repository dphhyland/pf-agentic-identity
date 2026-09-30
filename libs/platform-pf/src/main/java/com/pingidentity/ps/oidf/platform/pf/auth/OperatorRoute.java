/*
 * One operator API route: its name, the scope it needs, and whether it changes anything.
 */
package com.pingidentity.ps.oidf.platform.pf.auth;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * An operator API route as the authenticator sees it.
 *
 * @param name     what events and logs call it, lower-case words joined by dots and hyphens
 *                 ({@code hosted-entities.update})
 * @param scope    the scope a token must carry to use it, one of {@link OperatorScopes}
 * @param mutation whether it changes anything: a mutation counts against the operator's limit of changes a minute
 */
public record OperatorRoute(String name, String scope, boolean mutation) {
    private static final Pattern NAME = Pattern.compile("[a-z][a-z0-9-]*(\\.[a-z][a-z0-9-]*)*");

    public OperatorRoute {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("a route name is lower-case words joined by dots, not " + name);
        }
        if (!OperatorScopes.ALL.contains(Objects.requireNonNull(scope, "scope"))) {
            throw new IllegalArgumentException("a route needs one of the operator scopes " + OperatorScopes.ALL
                    + ", not " + scope);
        }
    }

    /** A route that reads. */
    public static OperatorRoute read(String name, String scope) {
        return new OperatorRoute(name, scope, false);
    }

    /** A route that changes something. */
    public static OperatorRoute mutation(String name, String scope) {
        return new OperatorRoute(name, scope, true);
    }
}
