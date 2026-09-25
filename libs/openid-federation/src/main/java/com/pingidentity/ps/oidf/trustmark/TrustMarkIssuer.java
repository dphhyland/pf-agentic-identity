/*
 * Decides which Trust Marks this entity issues, and what their status is.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.TrustMarkIssuing;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;

/**
 * The Trust Mark Issuer's decisions (OpenID Federation 1.0 §7, §8.4-§8.6), apart from signing: a mark of a configured
 * type is issued to a subject only under a grant that stands, and - for a type issued to hosted entities only - while
 * the subject is an active hosted entity.
 *
 * <p>No mark is recorded. A mark's status (§8.4.2) is worked out from the mark and its grant: a grant revoked, or given
 * again after the mark was minted, makes it {@code revoked}; its own {@code exp} or its grant's end passing makes it
 * {@code expired}; no grant makes it unknown.
 */
public final class TrustMarkIssuer implements TrustMarkIssuing {

    /** A mark's status (§8.4.2), or {@link #UNKNOWN} for one this issuer has no grant for. */
    public enum Status {
        ACTIVE, EXPIRED, REVOKED, UNKNOWN;

        public String code() {
            return this.name().toLowerCase(Locale.ROOT);
        }
    }

    private final Map<String, TrustMarkType> types;
    private final TrustMarkRegistry registry;
    private final Predicate<String> activeHostedEntity;
    private final Clock clock;

    /**
     * @param types              the types this entity issues, by identifier
     * @param activeHostedEntity whether an entity id is an active entity this authority hosts
     */
    public TrustMarkIssuer(Map<String, TrustMarkType> types, TrustMarkRegistry registry, Predicate<String> activeHostedEntity, Clock clock) {
        this.types = Collections.unmodifiableMap(new LinkedHashMap<>(types));
        this.registry = Objects.requireNonNull(registry, "registry");
        this.activeHostedEntity = Objects.requireNonNull(activeHostedEntity, "activeHostedEntity");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Set<String> types() {
        return this.types.keySet();
    }

    public Optional<TrustMarkType> type(String id) {
        return Optional.ofNullable(id == null ? null : this.types.get(id));
    }

    /** The grant under which a mark of {@code type} may be issued to {@code subject} now. */
    public Optional<TrustMarkGrant> issuable(String type, String subject) {
        TrustMarkType configured = this.types.get(type);
        if (configured == null) {
            return Optional.empty();
        }
        Optional<TrustMarkGrant> grant = this.grant(type, subject);
        if (grant.isEmpty() || !grant.get().activeAt(this.clock.instant()) || !this.subjectMayHold(configured, subject)) {
            return Optional.empty();
        }
        return grant;
    }

    private boolean subjectMayHold(TrustMarkType type, String subject) {
        return type.subjects() == TrustMarkType.Subjects.ANY || this.activeHostedEntity.test(subject);
    }

    @Override
    public Optional<Mintable> mintable(String issuerId, String type, String subject) {
        return this.issuable(type, subject).map(grant -> new Mintable(this.claims(issuerId, this.types.get(type), grant), grant.grantedAt()));
    }

    /**
     * The claims of a new mark of {@code type} for the grant's subject (§7.1): {@code exp} is the type's lifetime from
     * now, or the grant's end if that is sooner.
     */
    JwtClaims claims(String issuerId, TrustMarkType type, TrustMarkGrant grant) {
        long now = this.clock.instant().getEpochSecond();
        long exp = now + type.lifetimeSeconds();
        if (grant.notAfter() != null) {
            exp = Math.min(exp, grant.notAfter().getEpochSecond());
        }
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuerId);
        claims.setSubject(grant.subject());
        claims.setClaim("trust_mark_type", type.id());
        claims.setIssuedAt(NumericDate.fromSeconds(now));
        claims.setExpirationTime(NumericDate.fromSeconds(exp));
        claims.setJwtId(UUID.randomUUID().toString());
        if (type.delegation() != null) {
            claims.setClaim("delegation", type.delegation());
        }
        if (type.ref() != null) {
            claims.setClaim("ref", type.ref());
        }
        if (type.logoUri() != null) {
            claims.setClaim("logo_uri", type.logoUri());
        }
        return claims;
    }

    /** The types {@code subject} holds a mark of now, in configuration order. */
    List<String> typesHeldBy(String subject) {
        List<String> held = new ArrayList<>();
        for (String type : this.types.keySet()) {
            if (this.issuable(type, subject).isPresent()) {
                held.add(type);
            }
        }
        return held;
    }

    @Override
    public List<String> marked(String type, String subject) {
        TrustMarkType configured = this.types.get(type);
        if (configured == null) {
            return List.of();
        }
        Instant now = this.clock.instant();
        List<String> marked = new ArrayList<>();
        for (TrustMarkGrant grant : this.read(() -> this.registry.grantsOf(type))) {
            if (grant.activeAt(now) && (subject == null || EntityId.same(grant.subject(), subject)) && this.subjectMayHold(configured, grant.subject())) {
                marked.add(grant.subject());
            }
        }
        return marked;
    }

    @Override
    public boolean isMarked(String subject, String type) {
        return type == null ? !this.typesHeldBy(subject).isEmpty() : this.issuable(type, subject).isPresent();
    }

    @Override
    public Optional<String> status(JwtClaims mark) {
        Status status = this.statusOf(mark);
        return status == Status.UNKNOWN ? Optional.empty() : Optional.of(status.code());
    }

    /** The status of a mark whose signature and type the caller has already checked as this issuer's (§8.4.2). */
    Status statusOf(JwtClaims mark) {
        String type = mark.getClaimValue("trust_mark_type") instanceof String t ? t : null;
        String subject = mark.getClaimValue("sub") instanceof String s ? s : null;
        if (type == null || subject == null) {
            return Status.UNKNOWN;
        }
        Optional<TrustMarkGrant> found = this.grant(type, subject);
        if (found.isEmpty()) {
            return Status.UNKNOWN;
        }
        TrustMarkGrant grant = found.get();
        Instant now = this.clock.instant();
        long issuedAt = mark.getClaimValue("iat") instanceof Number n ? n.longValue() : Long.MIN_VALUE;
        TrustMarkType configured = this.types.get(type);
        if (grant.status() == TrustMarkGrant.Status.REVOKED || issuedAt < grant.grantedAt().getEpochSecond() || configured == null
                || !this.subjectMayHold(configured, subject)) {
            return Status.REVOKED;
        }
        Object exp = mark.getClaimValue("exp");
        if (exp instanceof Number n && now.getEpochSecond() >= n.longValue() || !grant.activeAt(now)) {
            return Status.EXPIRED;
        }
        return Status.ACTIVE;
    }

    private Optional<TrustMarkGrant> grant(String type, String subject) {
        return this.read(() -> this.registry.find(type, subject));
    }

    /** A registry read; a registry that fails is this server's fault, answered as §8.9 {@code server_error}. */
    private <T> T read(Read<T> read) {
        try {
            return read.get();
        } catch (AuthorityRegistryException e) {
            throw new FederationException(FederationError.SERVER_ERROR, "the Trust Mark registry could not be read");
        }
    }

    private interface Read<T> {
        T get() throws AuthorityRegistryException;
    }
}
