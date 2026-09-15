package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.jose.JwtCodec;

/**
 * The explicit-typing rule for inbound Entity Statements. OpenID Federation 1.0 §3: "Entity Statement
 * JWTs MUST be explicitly typed, by setting the typ header parameter to entity-statement+jwt ...
 * Entity Statements without a typ header parameter or with a different typ value MUST be rejected."
 *
 * <p>One place, so every read that feeds a trust decision - a chain entry about to be verified, an
 * Entity Configuration whose keys or fetch endpoint are about to be used - applies the same check.
 * {@link JwtCodec#requireType} accepts the {@code application/}-prefixed spelling RFC 7515 §4.1.9
 * allows, which names the same type.
 */
final class EntityStatementType {
    static final String TYP = "entity-statement+jwt";

    private EntityStatementType() {
    }

    /**
     * @param jwt  a compact JWS already known to parse
     * @param what names the statement in the rejection, e.g. {@code iss=... sub=...}
     * @throws IllegalArgumentException if {@code typ} is missing or is not {@code entity-statement+jwt}
     */
    static void require(String jwt, String what) throws Exception {
        try {
            JwtCodec.requireType(JwtCodec.getJwtHeaders(jwt), TYP);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Entity statement " + what + " rejected (OpenID Federation 1.0 §3): " + e.getMessage(), e);
        }
    }
}
