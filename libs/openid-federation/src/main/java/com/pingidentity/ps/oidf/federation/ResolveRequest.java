/*
 * A resolve request.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.List;

/**
 * The parameters of an OpenID Federation 1.0 §8.3.1 resolve request.
 *
 * @param subject      {@code sub}: the entity whose resolved data is asked for
 * @param trustAnchors {@code trust_anchor}, which "MAY occur multiple times"; at least one is required
 * @param entityTypes  {@code entity_type}; empty means every Entity Type
 */
public record ResolveRequest(String subject, List<String> trustAnchors, List<String> entityTypes) {

    public ResolveRequest {
        trustAnchors = ListRequest.nonBlank(trustAnchors);
        entityTypes = ListRequest.nonBlank(entityTypes);
    }
}
