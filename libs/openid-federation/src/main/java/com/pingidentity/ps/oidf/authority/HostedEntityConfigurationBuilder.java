/*
 * Builds and signs the Entity Configuration the authority publishes on a hosted entity's behalf.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.jose.Claims;
import com.pingidentity.ps.oidf.jose.CompactJws;
import com.pingidentity.ps.oidf.jose.JwsSigner;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

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
    private final Function<String, List<Map<String, Object>>> trustMarks;

    public HostedEntityConfigurationBuilder(HostedEntitySigner signer, String authorityEntityId) {
        this(signer, authorityEntityId, entityId -> List.of());
    }

    /** @param trustMarks entity id -> the {@code trust_marks} (§3.1.2) this authority issues it, empty for none */
    public HostedEntityConfigurationBuilder(HostedEntitySigner signer, String authorityEntityId,
                                            Function<String, List<Map<String, Object>>> trustMarks) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.authorityEntityId = Claims.requireNonBlank(authorityEntityId, "authorityEntityId");
        this.trustMarks = Objects.requireNonNull(trustMarks, "trustMarks");
    }

    /** A SELF_SIGNED entity that has not published (or whose publication expired): nothing to serve. */
    public static final class NotPublishedException extends IllegalStateException {
        private static final long serialVersionUID = 1L;

        NotPublishedException(String message) {
            super(message);
        }
    }

    /**
     * Builds and signs {@code entity}'s Entity Configuration JWT - or, for a SELF_SIGNED entity, returns the
     * configuration the entity signed itself, verbatim.
     */
    public String buildEntityConfiguration(HostedEntity entity) {
        if (entity.hostingMode() == HostingMode.SELF_SIGNED) {
            String stored = entity.entityConfiguration();
            if (stored == null) {
                throw new NotPublishedException("entity " + entity.entityId() + " has not published its configuration");
            }
            if (SelfSignedEntityConfigurations.expired(stored, Instant.now())) {
                throw new NotPublishedException("entity " + entity.entityId() + "'s published configuration has expired");
            }
            return stored;
        }
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
        List<Map<String, Object>> marks = this.trustMarks.apply(entity.entityId());
        if (!marks.isEmpty()) {
            claims.put("trust_marks", marks);
        }

        return CompactJws.sign(header, claims, jwsSigner);
    }
}
