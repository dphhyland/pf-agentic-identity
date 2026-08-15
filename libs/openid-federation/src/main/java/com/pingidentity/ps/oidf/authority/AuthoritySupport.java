/*
 * Process-wide singletons shared between every servlet that reads or writes the hosted-entity registry.
 */
package com.pingidentity.ps.oidf.authority;

import com.pingidentity.ps.oidf.jose.JwsSigner;
import com.pingidentity.ps.oidf.federation.MetadataPolicy;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link HostedEntityRegistry}, {@link HostedEntitySigner} and
 * {@link HostedEntityConfigurationBuilder} so every servlet that touches hosted entities (the
 * resolution endpoint, and the enrolment API that will follow it) shares the same state.
 *
 * <p>This exists because of a bug this codebase already made once: {@code AttestationSupport}
 * (the equivalent holder for the attestation challenge/replay stores) was added after the challenge
 * servlet and the token-endpoint hook turned out to be loaded by two different classloaders and so held
 * two independent stores — a challenge issued by one was invisible to the other. Any deployment that
 * loads this module's servlets from more than one classloader would hit the identical failure here
 * without a single shared holder to configure explicitly.
 *
 * <p>Lazily initialized to an in-memory registry if nothing configures one first — workable for tests
 * and a single-node demo, wrong for anything meant to host entities durably (see
 * {@link InMemoryHostedEntityRegistry}'s own javadoc).
 */
public final class AuthoritySupport {
    private static final Log LOGGER = LogFactory.getLog(AuthoritySupport.class);
    private static final Object LOCK = new Object();

    private static volatile HostedEntityRegistry registry;
    private static volatile HostedEntitySigner signer;
    private static volatile String authorityEntityId;
    private static volatile HostedEntityConfigurationBuilder configurationBuilder;
    /** One block per entity type, the same shape as {@link HostedEntity#metadataPolicy()}. Empty (no
     *  domain-wide constraint) unless {@link #configureDomainDefaultMetadataPolicy} is called. */
    private static volatile Map<String, Object> domainDefaultMetadataPolicy = Map.of();

    private AuthoritySupport() {
    }

    /**
     * Configures the shared registry against a durable store. Call once, before {@link #registry()} is
     * first used — subsequent calls are ignored with a warning, matching the "first configuration wins,
     * everything after is a caller bug" contract the equivalent attestation holder uses.
     */
    public static void configureJdbcRegistry(DataSource dataSource) {
        synchronized (LOCK) {
            if (registry != null) {
                LOGGER.warn("AuthoritySupport registry already configured; ignoring a second configuration");
                return;
            }
            registry = new JdbcHostedEntityRegistry(Objects.requireNonNull(dataSource, "dataSource"));
        }
    }

    /** Configures the shared signer and the authority's own fixed entity id (never derived per-request). */
    public static void configureSigning(HostedEntitySigner hostedEntitySigner, String configuredAuthorityEntityId) {
        synchronized (LOCK) {
            if (signer != null) {
                LOGGER.warn("AuthoritySupport signer already configured; ignoring a second configuration");
                return;
            }
            signer = Objects.requireNonNull(hostedEntitySigner, "hostedEntitySigner");
            authorityEntityId = com.pingidentity.ps.oidf.jose.Claims.requireNonBlank(
                    configuredAuthorityEntityId, "authorityEntityId");
            configurationBuilder = new HostedEntityConfigurationBuilder(signer, authorityEntityId);
        }
    }

    public static HostedEntityRegistry registry() {
        HostedEntityRegistry local = registry;
        if (local == null) {
            synchronized (LOCK) {
                if (registry == null) {
                    LOGGER.warn("DEV MODE: no durable hosted-entity registry configured — "
                            + "using an in-memory registry that will not survive a restart");
                    registry = new InMemoryHostedEntityRegistry();
                }
                local = registry;
            }
        }
        return local;
    }

    public static HostedEntityConfigurationBuilder configurationBuilder() {
        HostedEntityConfigurationBuilder local = configurationBuilder;
        if (local == null) {
            throw new IllegalStateException(
                    "AuthoritySupport.configureSigning(...) must be called before configurationBuilder() — "
                            + "unlike the registry, there is no safe default signer to fall back to");
        }
        return local;
    }

    /** The authority's own fixed entity id, as configured — never derived from a request's Host header. */
    public static String authorityEntityId() {
        String local = authorityEntityId;
        if (local == null) {
            throw new IllegalStateException("AuthoritySupport.configureSigning(...) must be called before authorityEntityId()");
        }
        return local;
    }

    /**
     * Sets the domain-wide default {@code metadata_policy} — one block per entity type, composed as the
     * superior against every hosted entity's own {@link HostedEntity#metadataPolicy()} (the subordinate)
     * each time a subordinate statement about it is issued. Unlike {@link #configureJdbcRegistry} and
     * {@link #configureSigning}, this may be called more than once and the latest call always wins: it is
     * plain policy data, not a stateful resource with connection or classloader identity, so there is no
     * hazard in an operator updating it without a restart.
     */
    public static void configureDomainDefaultMetadataPolicy(Map<String, Object> policy) {
        domainDefaultMetadataPolicy = policy == null ? Map.of() : Map.copyOf(policy);
    }

    public static HostedEntitySigner hostedEntitySigner() {
        HostedEntitySigner local = signer;
        if (local == null) {
            throw new IllegalStateException("AuthoritySupport.configureSigning(...) must be called before hostedEntitySigner()");
        }
        return local;
    }

    /**
     * Entity ids of hosted entities visible via {@code /federation/list} — {@link HostedEntityRegistry#list}
     * already restricts this to entities that are active, resolvable now, and marked
     * {@link HostedEntity#listable()}, optionally narrowed to one metadata type. Agents default to
     * {@code listable=false} at registration (see {@link HostedEntity#hosted}): listing an agent publishes
     * an inventory of pseudonymous identifiers keyed by exactly the value whose whole purpose is being
     * uncorrelatable without the registry, so nothing here overrides that default.
     *
     * @throws IllegalStateException if the registry itself is unavailable
     */
    public static List<String> hostedEntityIds(String entityType) {
        try {
            return registry().list(entityType).stream().map(HostedEntity::entityId).toList();
        } catch (AuthorityRegistryException e) {
            throw new IllegalStateException("hosted-entity listing failed for entity_type=" + entityType, e);
        }
    }

    /**
     * The subordinate-statement claims fragment for a resolvable hosted entity — {@code "jwks"} (wrapped
     * as {@code {"keys": [...]}}, the shape a subordinate statement's own {@code jwks} claim uses) and,
     * when a domain default or a per-entity policy applies, {@code "metadata_policy"} — or {@code null}
     * if {@code subject} is not, or is no longer, a hosted entity here. {@code null} rather than an
     * exception on "not found" is deliberate: this is meant to be wired straight into
     * {@code FederationService}'s subordinate-statement path as a lookup function it falls through past
     * when a subject isn't hosted here at all, and a subject that plainly isn't a hosted entity is the
     * overwhelmingly common case, not an error.
     *
     * @throws IllegalStateException if the registry itself is unavailable, signing fails, or the
     *                                composed policy is internally inconsistent (e.g. the domain default
     *                                and the entity's own policy disagree on a fixed value) — all genuine
     *                                faults, not "subject not hosted"
     */
    public static Map<String, Object> hostedSubordinateClaims(String subject) {
        Optional<HostedEntity> found;
        try {
            found = registry().find(subject);
        } catch (AuthorityRegistryException e) {
            throw new IllegalStateException("hosted-entity lookup failed for " + subject, e);
        }
        if (found.isEmpty() || !found.get().resolvable(Instant.now())) {
            return null;
        }
        HostedEntity entity = found.get();

        JwsSigner jwsSigner;
        try {
            jwsSigner = hostedEntitySigner().signerFor(entity);
        } catch (RuntimeException e) {
            throw new IllegalStateException("could not resolve signer for hosted entity " + subject, e);
        }

        LinkedHashMap<String, Object> claims = new LinkedHashMap<>();
        claims.put("jwks", Map.of("keys", List.of(jwsSigner.publicJwk())));
        Map<String, Object> policy = composedMetadataPolicyFor(entity);
        if (!policy.isEmpty()) {
            claims.put("metadata_policy", policy);
        }
        return claims;
    }

    /**
     * Composes {@link #domainDefaultMetadataPolicy} (the superior) with {@code entity}'s own
     * {@link HostedEntity#metadataPolicy()} (the subordinate) per entity type, via
     * {@link MetadataPolicy#composeWith} — the same fail-closed, narrow-only composition Phase 0.2 wired
     * into chain validation, reused here for emission instead of application.
     */
    /** Package-private (not private) specifically so this pure, signer-free composition logic is
     *  directly testable without needing a registry or a working signer configured. */
    static Map<String, Object> composedMetadataPolicyFor(HostedEntity entity) {
        Set<String> types = new LinkedHashSet<>(domainDefaultMetadataPolicy.keySet());
        types.addAll(entity.metadataPolicy().keySet());
        if (types.isEmpty()) {
            return Map.of();
        }
        LinkedHashMap<String, Object> composed = new LinkedHashMap<>();
        for (String type : types) {
            try {
                MetadataPolicy domainPolicy = MetadataPolicy.parse(asPolicyMap(domainDefaultMetadataPolicy.get(type)), null);
                MetadataPolicy entityPolicy = MetadataPolicy.parse(asPolicyMap(entity.metadataPolicy().get(type)), null);
                MetadataPolicy result = domainPolicy.composeWith(entityPolicy);
                if (!result.isEmpty()) {
                    composed.put(type, asRawMap(result));
                }
            } catch (MetadataPolicy.PolicyException e) {
                throw new IllegalStateException("metadata_policy composition failed for hosted entity "
                        + entity.entityId() + ", type '" + type + "': " + e.getMessage(), e);
            }
        }
        return composed;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asPolicyMap(Object raw) {
        return raw instanceof Map ? (Map<String, Object>) raw : Map.of();
    }

    /** Reconstructs the raw {@code metadata_policy.<type>} shape from a composed {@link MetadataPolicy}. */
    private static Map<String, Object> asRawMap(MetadataPolicy policy) {
        LinkedHashMap<String, Object> out = new LinkedHashMap<>();
        for (String parameter : policy.parameters()) {
            out.put(parameter, policy.operatorsFor(parameter));
        }
        return out;
    }
}
