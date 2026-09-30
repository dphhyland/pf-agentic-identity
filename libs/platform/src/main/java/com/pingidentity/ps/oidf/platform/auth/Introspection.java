/*
 * What an authorisation server said about an access token (RFC 7662 §2.2).
 */
package com.pingidentity.ps.oidf.platform.auth;

import java.util.List;
import java.util.Map;

/**
 * An introspection answer, as {@link TokenIntrospector} read it. Only {@link #active()} is always meaningful; every
 * other member is what the server returned for an active token, or null (an empty list for {@code scope} and
 * {@code aud}) when it returned none. An inactive answer carries nothing else: RFC 7662 §2.2 says of an inactive
 * token that the server "SHOULD NOT include any additional information".
 *
 * @param active    RFC 7662 §2.2 {@code active}
 * @param scopes    {@code scope}, split on spaces
 * @param clientId  {@code client_id}: the client the token was issued to
 * @param subject   {@code sub}
 * @param audience  {@code aud}, a string read as a list of one
 * @param issuer    {@code iss}
 * @param exp       {@code exp}, seconds since the epoch
 * @param iat       {@code iat}
 * @param nbf       {@code nbf}
 * @param tokenType {@code token_type}: {@code DPoP} for a DPoP-bound token (RFC 9449 §6.2)
 * @param jkt       {@code cnf.jkt}: the thumbprint of the key a DPoP-bound token is bound to (RFC 9449 §6.2)
 * @param x5tS256   {@code cnf.x5t#S256}: the certificate an mTLS-bound token is bound to (RFC 8705 §3.2)
 * @param members   every member of the answer, as JSON values, for a caller that needs one not listed here
 */
public record Introspection(boolean active, List<String> scopes, String clientId, String subject, List<String> audience,
                            String issuer, Long exp, Long iat, Long nbf, String tokenType, String jkt, String x5tS256,
                            Map<String, Object> members) {

    /** The answer for a token that is not active. */
    public static final Introspection INACTIVE = new Introspection(false, List.of(), null, null, List.of(), null, null,
            null, null, null, null, null, Map.of("active", Boolean.FALSE));

    public Introspection {
        scopes = List.copyOf(scopes);
        audience = List.copyOf(audience);
        members = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(members));
    }

    /** Whether the token is bound to a key or a certificate: it carries {@code cnf.jkt} or {@code cnf.x5t#S256}. */
    public boolean bound() {
        return this.jkt != null || this.x5tS256 != null;
    }
}
