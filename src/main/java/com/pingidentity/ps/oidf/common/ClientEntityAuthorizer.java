package com.pingidentity.ps.oidf.common;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * AS-side federation client authentication.
 *
 * <p>When a client authenticates to PingFederate and the client is itself an OpenID Federation
 * entity, PF resolves the client's entity record through the trust controller and authenticates it
 * only if every gate holds:
 * <ul>
 *   <li><b>member</b> — the client's chain resolves to the configured trust anchor;</li>
 *   <li><b>statusActive</b> — it is a resolvable subordinate (suspend/revoke == it no longer
 *       resolves), so status collapses onto membership here;</li>
 *   <li><b>withinPolicy</b> — its {@code oauth_client} metadata permits automatic client
 *       registration;</li>
 *   <li><b>scopeOk</b> — the requested scopes are within the scopes registered to the entity.</li>
 * </ul>
 *
 * <p>Resolution + chain verification is the caller's job (e.g. via {@link TrustChainValidator}
 * against a {@link TrustControllerGateway}); this class is the pure decision so it is trivially
 * testable and free of I/O.
 */
public final class ClientEntityAuthorizer {
    private ClientEntityAuthorizer() {}

    public static final class Decision {
        public final boolean authenticated;
        public final boolean member;
        public final boolean statusActive;
        public final boolean withinPolicy;
        public final boolean scopeOk;
        public final Set<String> registeredScopes;
        public final Set<String> grantedScopes;
        public final String reason;

        Decision(boolean member, boolean statusActive, boolean withinPolicy, boolean scopeOk,
                 Set<String> registeredScopes, Set<String> grantedScopes, String reason) {
            this.member = member;
            this.statusActive = statusActive;
            this.withinPolicy = withinPolicy;
            this.scopeOk = scopeOk;
            this.authenticated = member && statusActive && withinPolicy && scopeOk;
            this.registeredScopes = registeredScopes;
            this.grantedScopes = grantedScopes;
            this.reason = reason;
        }
    }

    /**
     * @param resolved        whether the client entity resolved (chained) to the configured trust anchor
     * @param leafMetadata    the resolved entity metadata (expects an {@code oauth_client} block); may be null
     * @param requestedScopes the scopes the client is requesting
     */
    @SuppressWarnings("unchecked")
    public static Decision authorize(boolean resolved, Map<String, Object> leafMetadata,
                                     Collection<String> requestedScopes) {
        Set<String> requested = new LinkedHashSet<>(requestedScopes == null ? List.of() : requestedScopes);
        if (!resolved) {
            return new Decision(false, false, false, false, Set.of(), Set.of(),
                "not an active federation member — the client does not resolve to the configured trust anchor "
                    + "(suspended, revoked, or never enrolled)");
        }
        Map<String, Object> oauthClient = leafMetadata == null ? null
            : (Map<String, Object>) leafMetadata.get("oauth_client");
        if (oauthClient == null) {
            return new Decision(true, true, false, false, Set.of(), Set.of(),
                "resolved entity has no oauth_client metadata — cannot authenticate as an OAuth client");
        }
        Object regTypes = oauthClient.get("client_registration_types");
        boolean withinPolicy = regTypes instanceof Collection && ((Collection<?>) regTypes).contains("automatic");
        Set<String> registered = splitScope(oauthClient.get("scope"));
        boolean scopeOk = registered.containsAll(requested);
        Set<String> granted = new TreeSet<>(requested);
        granted.retainAll(registered);

        String reason;
        if (withinPolicy && scopeOk) {
            reason = "authenticated — federation member, within policy, requested scopes registered to the entity";
        } else if (!withinPolicy) {
            reason = "within-policy check failed: the entity is not permitted for automatic client registration "
                + "(client_registration_types=" + regTypes + ")";
        } else {
            Set<String> excess = new TreeSet<>(requested);
            excess.removeAll(registered);
            reason = "requested scope exceeds the scopes registered to the entity: " + excess;
        }
        return new Decision(true, true, withinPolicy, scopeOk, new TreeSet<>(registered), granted, reason);
    }

    private static Set<String> splitScope(Object scope) {
        Set<String> out = new LinkedHashSet<>();
        if (scope instanceof String) {
            for (String s : ((String) scope).trim().split("\\s+")) {
                if (!s.isEmpty()) out.add(s);
            }
        } else if (scope instanceof Collection) {
            for (Object o : (Collection<?>) scope) {
                if (o != null) out.add(o.toString());
            }
        }
        return out;
    }
}
