/*
 * Builds and signs the Entity Configuration the authority publishes on a hosted entity's behalf.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.common.Claims;
import com.pingidentity.ps.oidf.common.CompactJws;
import com.pingidentity.ps.oidf.common.JwsSigner;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Builds a {@link HostedEntity}'s Entity Configuration — {@code iss == sub == entityId}, signed by the
 * entity's own hosting key (resolved via a {@link HostedEntitySigner}) so it satisfies OpenID
 * Federation's self-signed requirement even though the authority, not the entity, holds the private
 * key. See {@link HostingMode#AUTHORITY_SIGNED}'s javadoc for why the entity's own instance/runtime key
 * never appears here at all.
 */
public final class HostedEntityConfigurationBuilder {

    private static final String ENTITY_STATEMENT_TYP = "entity-statement+jwt";
    /** Matches FederationService's own createEntityConfigurationJwt lifetime (60 minutes). */
    private static final long CONFIGURATION_LIFETIME_SECONDS = 3600L;

    private final HostedEntitySigner signer;
    private final String authorityEntityId;

    public HostedEntityConfigurationBuilder(HostedEntitySigner signer, String authorityEntityId) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.authorityEntityId = Claims.requireNonBlank(authorityEntityId, "authorityEntityId");
    }

    /** Builds and signs {@code entity}'s Entity Configuration JWT. */
    public String buildEntityConfiguration(HostedEntity entity) {
        JwsSigner jwsSigner = this.signer.signerFor(entity);

        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", jwsSigner.algorithm());
        header.put("typ", ENTITY_STATEMENT_TYP);
        header.put("kid", jwsSigner.keyId());

        long now = Instant.now().getEpochSecond();
        LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", entity.entityId());
        claims.put("sub", entity.entityId());
        claims.put("iat", now);
        claims.put("exp", now + CONFIGURATION_LIFETIME_SECONDS);
        claims.put("jwks", Map.of("keys", List.of(jwsSigner.publicJwk())));
        // The authority is this entity's sole superior in Phase 1's model — a hosted entity is never
        // itself an intermediate with its own subordinates.
        claims.put("authority_hints", List.of(this.authorityEntityId));
        claims.put("metadata", entity.metadata());

        return CompactJws.sign(header, claims, jwsSigner);
    }
}
