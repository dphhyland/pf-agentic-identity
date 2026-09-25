/*
 * What a registration would give a client, before it is stored.
 */
package com.pingidentity.ps.oidf.federation.policy;

import java.util.List;
import java.util.Set;

/**
 * The parts of a registration a policy decision can narrow: the scopes, grant types and response types the client may
 * use, and when the registration ends. What the registration would be with every default applied - so narrowing it
 * can only take away.
 *
 * @param scopes        the scopes it may request
 * @param grantTypes    the grant types it may use
 * @param responseTypes the response types it may use
 * @param expiresAt     when the registration ends, in epoch seconds
 */
public record ClientDraft(List<String> scopes, Set<String> grantTypes, List<String> responseTypes, long expiresAt) {
    public ClientDraft {
        scopes = List.copyOf(scopes);
        grantTypes = Set.copyOf(grantTypes);
        responseTypes = List.copyOf(responseTypes);
    }
}
