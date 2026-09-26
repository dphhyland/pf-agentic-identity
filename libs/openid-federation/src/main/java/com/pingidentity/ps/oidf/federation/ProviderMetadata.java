/*
 * What a deployment's own discovery documents say about it.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.Map;

/**
 * This entity's metadata as its own discovery documents publish it - OpenID Connect Discovery for
 * {@code openid_provider}, RFC 8414 for {@code oauth_authorization_server} - so its Entity Configuration describes it
 * the same way (OpenID Federation 1.0 §5.1.3, §5.1.4). Empty when it isn't known; the Entity Configuration then carries
 * only what this module can say for itself.
 */
@FunctionalInterface
public interface ProviderMetadata {
    /** Nothing known: the Entity Configuration carries the endpoints this module derives from the issuer, and its own additions. */
    ProviderMetadata NONE = (entityType, issuer) -> Map.of();

    /**
     * @param entityType {@code openid_provider} or {@code oauth_authorization_server}
     * @param issuer     the issuer the Entity Configuration is for
     * @return the discovery document's members, or an empty map
     */
    Map<String, Object> of(String entityType, String issuer);
}
