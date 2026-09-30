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
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;

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
    /** Where signed configurations are kept until due for renewal; null signs every time. */
    private final HostedEntityConfigurationCache cache;

    public HostedEntityConfigurationBuilder(HostedEntitySigner signer, String authorityEntityId) {
        this(signer, authorityEntityId, entityId -> List.of());
    }

    /** @param trustMarks entity id -> the {@code trust_marks} (§3.1.2) this authority issues it, empty for none */
    public HostedEntityConfigurationBuilder(HostedEntitySigner signer, String authorityEntityId,
                                            Function<String, List<Map<String, Object>>> trustMarks) {
        this(signer, authorityEntityId, trustMarks, null);
    }

    /**
     * @param cache where an authority-signed configuration is kept until it is due for renewal (plan item H-FED-9); null
     *              signs it on every call
     */
    public HostedEntityConfigurationBuilder(HostedEntitySigner signer, String authorityEntityId,
                                            Function<String, List<Map<String, Object>>> trustMarks,
                                            HostedEntityConfigurationCache cache) {
        this.signer = Objects.requireNonNull(signer, "signer");
        this.authorityEntityId = Claims.requireNonBlank(authorityEntityId, "authorityEntityId");
        this.trustMarks = Objects.requireNonNull(trustMarks, "trustMarks");
        this.cache = cache;
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
     * configuration the entity signed itself, verbatim. With a cache, an authority-signed one signed earlier from this
     * same record is returned while it has more than {@link HostedEntityConfigurationCache#KEEP_WHILE_REMAINING} of its
     * lifetime left - counted to the earlier of its own {@code exp} and that of the first Trust Mark it carries to expire.
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
        String kept = this.cache == null ? null : this.cache.get(entity);
        if (kept != null) {
            return kept;
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

        String jwt = CompactJws.sign(header, claims, jwsSigner);
        if (this.cache != null) {
            long freshUntil = earliestExpiry(marks, now + CONFIGURATION_LIFETIME_SECONDS, now);
            this.cache.put(entity, jwt, Instant.ofEpochSecond(now), Instant.ofEpochSecond(freshUntil));
        }
        return jwt;
    }

    /**
     * The earlier of {@code configurationExp} and the {@code exp} of every Trust Mark embedded in the configuration, so
     * a kept configuration is renewed before a mark it carries expires. A mark whose {@code exp} cannot be read gives
     * {@code now}: the configuration is then not kept at all.
     */
    static long earliestExpiry(List<Map<String, Object>> marks, long configurationExp, long now) {
        long earliest = configurationExp;
        for (Map<String, Object> mark : marks) {
            long exp;
            try {
                JsonWebSignature jws = new JsonWebSignature();
                jws.setCompactSerialization((String) mark.get("trust_mark"));
                exp = JwtClaims.parse(jws.getUnverifiedPayload()).getExpirationTime().getValue();
            } catch (Exception e) {
                exp = now;
            }
            earliest = Math.min(earliest, exp);
        }
        return earliest;
    }
}
