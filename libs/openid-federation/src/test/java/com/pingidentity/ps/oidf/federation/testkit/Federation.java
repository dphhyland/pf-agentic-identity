/*
 * A whole federation for a test: entities, their keys, their statements, served where they belong.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.TrustAnchor;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import org.jose4j.jwk.PublicJsonWebKey;

/**
 * Builds a federation of anchors, intermediates and leaves, signs every Entity Configuration and
 * Subordinate Statement correctly, and serves them through a {@link ServingMap} exactly where the gateway
 * looks for them. A negative test starts from this correct federation and breaks one statement:
 *
 * <pre>{@code
 * Federation f = Federation.builder()
 *     .anchor(TA)
 *     .intermediate(INT, TA)
 *     .leaf(RP, INT).metadata(RP, "openid_relying_party", Map.of("client_name", "rp"))
 *     .subordinate(INT, RP, s -> s.typ(null))          // break one statement
 *     .build();
 * TrustChainValidationResult r = f.validator(TA).validate(f.chain(RP, TA), RP, OP);
 * }</pre>
 *
 * <p>Each entity signs with one EC P-256 key whose {@code kid} is derived from its identifier, unless the
 * test supplies keys. Entities with subordinates publish {@code federation_entity} metadata with
 * {@code federation_fetch_endpoint} at {@code <id>/fetch} and {@code federation_list_endpoint} at
 * {@code <id>/list}.
 */
public final class Federation {

    /** The part an entity plays; an entity's statements follow from it. */
    public enum Role { ANCHOR, INTERMEDIATE, LEAF }

    private final Clock clock;
    private final Map<String, Entity> entities;
    private final Map<String, String> entityConfigurations;
    private final Map<String, String> subordinateStatements;
    private final ServingMap http;

    private Federation(Clock clock, Map<String, Entity> entities, Map<String, String> entityConfigurations,
                       Map<String, String> subordinateStatements, ServingMap http) {
        this.clock = clock;
        this.entities = entities;
        this.entityConfigurations = entityConfigurations;
        this.subordinateStatements = subordinateStatements;
        this.http = http;
    }

    public static Builder builder() {
        return new Builder(Clock.systemUTC());
    }

    public static Builder builder(Clock clock) {
        return new Builder(clock);
    }

    // ---- after build -----------------------------------------------------------------------------

    public Clock clock() {
        return this.clock;
    }

    public String entityConfiguration(String id) {
        return require(this.entityConfigurations.get(id), "no entity configuration for " + id);
    }

    public String subordinateStatement(String issuer, String subject) {
        return require(this.subordinateStatements.get(key(issuer, subject)), "no statement by " + issuer + " about " + subject);
    }

    /** The signing key (with private part) of an entity. */
    public PublicJsonWebKey key(String id) {
        return this.entity(id).keys.get(0);
    }

    public List<PublicJsonWebKey> keys(String id) {
        return List.copyOf(this.entity(id).keys);
    }

    /** {@code {"keys":[...]}} of an entity's public keys, as its statements carry them. */
    public Map<String, Object> publicJwks(String id) {
        return Keys.publicJwks(this.entity(id).keys);
    }

    public String fetchEndpoint(String id) {
        return ServingMap.stripSlash(id) + "/fetch";
    }

    public String listEndpoint(String id) {
        return ServingMap.stripSlash(id) + "/list";
    }

    /**
     * The chain a caller presents: the leaf's Entity Configuration, then the Subordinate Statements up the
     * first path from {@code leaf} to {@code anchor} (breadth-first, superiors in declaration order).
     */
    public List<String> chain(String leaf, String anchor) {
        List<String> path = this.path(leaf, anchor);
        List<String> chain = new ArrayList<>();
        chain.add(this.entityConfiguration(leaf));
        for (int i = 0; i + 1 < path.size(); i++) {
            chain.add(this.subordinateStatement(path.get(i + 1), path.get(i)));
        }
        return chain;
    }

    /** {@link #chain} plus the anchor's own Entity Configuration: the §4 shape. */
    public List<String> chainWithAnchor(String leaf, String anchor) {
        List<String> chain = new ArrayList<>(this.chain(leaf, anchor));
        chain.add(this.entityConfiguration(anchor));
        return chain;
    }

    /** The entity identifiers from {@code leaf} up to {@code anchor}, both included. */
    public List<String> path(String leaf, String anchor) {
        Map<String, String> cameFrom = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(leaf);
        cameFrom.put(leaf, null);
        while (!queue.isEmpty()) {
            String current = queue.poll();
            if (current.equals(anchor)) {
                List<String> path = new ArrayList<>();
                for (String step = anchor; step != null; step = cameFrom.get(step)) {
                    path.add(0, step);
                }
                return path;
            }
            for (String superior : this.entity(current).superiors) {
                if (!cameFrom.containsKey(superior)) {
                    cameFrom.put(superior, current);
                    queue.add(superior);
                }
            }
        }
        throw new IllegalArgumentException("no path from " + leaf + " to " + anchor);
    }

    /** The anchor as a validator pins it: its identifier and its public keys. */
    public TrustAnchor trustAnchor(String anchor) {
        return TrustAnchor.of(anchor, this.publicJwks(anchor));
    }

    /** Every anchor in the federation, in declaration order. */
    public TrustAnchorSet trustAnchors() {
        List<TrustAnchor> anchors = new ArrayList<>();
        for (Entity entity : this.entities.values()) {
            if (entity.role == Role.ANCHOR) {
                anchors.add(this.trustAnchor(entity.id));
            }
        }
        return TrustAnchorSet.of(anchors);
    }

    /** Serves every statement in the federation; tests may add or override entries. */
    public ServingMap http() {
        return this.http;
    }

    public HttpTrustControllerGateway gateway(String anchor) {
        return new HttpTrustControllerGateway(this.http, anchor);
    }

    /** A validator pinned to {@code anchor}, fetching through {@link #http()}. */
    public TrustChainValidator validator(String anchor) {
        return new TrustChainValidator(this.gateway(anchor), this.trustAnchor(anchor));
    }

    public TrustChainValidator validator(String anchor, Set<String> acceptedAlgorithms) {
        return new TrustChainValidator(this.gateway(anchor), this.trustAnchor(anchor), acceptedAlgorithms);
    }

    /** A validator pinned to several anchors (in the given order), with the given options. */
    public TrustChainValidator validator(ValidatorOptions options, String... anchors) {
        List<TrustAnchor> pinned = new ArrayList<>();
        for (String anchor : anchors) {
            pinned.add(this.trustAnchor(anchor));
        }
        return new TrustChainValidator(this.gateway(anchors[0]), TrustAnchorSet.of(pinned), Set.of(), options);
    }

    public Role role(String id) {
        return this.entity(id).role;
    }

    public List<String> superiors(String id) {
        return List.copyOf(this.entity(id).superiors);
    }

    private Entity entity(String id) {
        return require(this.entities.get(id), "no entity " + id);
    }

    private static <T> T require(T value, String message) {
        if (value == null) {
            throw new IllegalArgumentException(message);
        }
        return value;
    }

    static String key(String issuer, String subject) {
        return issuer + "\u0000" + subject;
    }

    // ---- building --------------------------------------------------------------------------------

    private static final class Entity {
        final String id;
        final Role role;
        final List<String> superiors;
        final List<PublicJsonWebKey> keys = new ArrayList<>();
        final Map<String, Map<String, Object>> metadata = new LinkedHashMap<>();
        final List<Consumer<Statements.Spec>> configurationChanges = new ArrayList<>();

        Entity(String id, Role role, List<String> superiors) {
            this.id = id;
            this.role = role;
            this.superiors = new ArrayList<>(superiors);
        }
    }

    /** Declares the federation; {@link #build()} signs and serves it. */
    public static final class Builder {
        private final Clock clock;
        private final Map<String, Entity> entities = new LinkedHashMap<>();
        private final Map<String, List<Consumer<Statements.Spec>>> subordinateChanges = new HashMap<>();
        private final List<String[]> extraEdges = new ArrayList<>();

        private Builder(Clock clock) {
            this.clock = Objects.requireNonNull(clock, "clock");
        }

        public Builder anchor(String id) {
            return this.add(id, Role.ANCHOR, List.of());
        }

        public Builder intermediate(String id, String... superiors) {
            return this.add(id, Role.INTERMEDIATE, List.of(superiors));
        }

        public Builder leaf(String id, String... superiors) {
            return this.add(id, Role.LEAF, List.of(superiors));
        }

        private Builder add(String id, Role role, List<String> superiors) {
            if (this.entities.containsKey(id)) {
                throw new IllegalArgumentException(id + " declared twice");
            }
            Entity entity = new Entity(id, role, superiors);
            entity.keys.add(Keys.ec(kidFor(id)));
            this.entities.put(id, entity);
            return this;
        }

        /** Replaces the entity's keys; the first signs its statements. */
        public Builder keys(String id, PublicJsonWebKey... keys) {
            Entity entity = this.entity(id);
            entity.keys.clear();
            entity.keys.addAll(List.of(keys));
            return this;
        }

        /** Sets one metadata block in the entity's own Entity Configuration. */
        public Builder metadata(String id, String entityType, Map<String, Object> block) {
            this.entity(id).metadata.put(entityType, new LinkedHashMap<>(block));
            return this;
        }

        /** Changes the entity's Entity Configuration before it is signed. */
        public Builder entityConfiguration(String id, Consumer<Statements.Spec> change) {
            this.entity(id).configurationChanges.add(change);
            return this;
        }

        /** Changes the statement {@code issuer} makes about {@code subject} before it is signed. */
        public Builder subordinate(String issuer, String subject, Consumer<Statements.Spec> change) {
            this.subordinateChanges.computeIfAbsent(key(issuer, subject), k -> new ArrayList<>()).add(change);
            return this;
        }

        /** Adds a {@code metadata_policy} block for {@code entityType} to the statement about {@code subject}. */
        @SuppressWarnings("unchecked")
        public Builder metadataPolicy(String issuer, String subject, String entityType, Map<String, Object> policy) {
            return this.subordinate(issuer, subject, s -> {
                Map<String, Object> all = s.hasClaim("metadata_policy")
                        ? new LinkedHashMap<>((Map<String, Object>) s.claimValue("metadata_policy")) : new LinkedHashMap<>();
                all.put(entityType, policy);
                s.claim("metadata_policy", all);
            });
        }

        /** Adds a {@code constraints} claim to the statement about {@code subject}. */
        public Builder constraints(String issuer, String subject, Map<String, Object> constraints) {
            return this.subordinate(issuer, subject, s -> s.claim("constraints", constraints));
        }

        private Entity entity(String id) {
            Entity entity = this.entities.get(id);
            if (entity == null) {
                throw new IllegalArgumentException("declare " + id + " before configuring it");
            }
            return entity;
        }

        public Federation build() {
            Map<String, Set<String>> subordinatesOf = new HashMap<>();
            for (Entity entity : this.entities.values()) {
                for (String superior : entity.superiors) {
                    if (!this.entities.containsKey(superior)) {
                        throw new IllegalArgumentException(entity.id + " names an undeclared superior " + superior);
                    }
                    subordinatesOf.computeIfAbsent(superior, k -> new java.util.LinkedHashSet<>()).add(entity.id);
                }
            }
            ServingMap http = new ServingMap();
            Map<String, String> configurations = new LinkedHashMap<>();
            Map<String, String> statements = new LinkedHashMap<>();
            for (Entity entity : this.entities.values()) {
                Statements.Spec spec = Statements.spec(Statements.ENTITY_STATEMENT_TYP)
                        .claim("iss", entity.id)
                        .claim("sub", entity.id)
                        .claim("jwks", Keys.publicJwks(entity.keys));
                if (!entity.superiors.isEmpty()) {
                    spec.claim("authority_hints", List.copyOf(entity.superiors));
                }
                Map<String, Object> metadata = new LinkedHashMap<>();
                for (Map.Entry<String, Map<String, Object>> block : entity.metadata.entrySet()) {
                    metadata.put(block.getKey(), block.getValue());
                }
                if (subordinatesOf.containsKey(entity.id)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> federationEntity = metadata.containsKey("federation_entity")
                            ? new LinkedHashMap<>((Map<String, Object>) metadata.get("federation_entity")) : new LinkedHashMap<>();
                    federationEntity.putIfAbsent("federation_fetch_endpoint", ServingMap.stripSlash(entity.id) + "/fetch");
                    federationEntity.putIfAbsent("federation_list_endpoint", ServingMap.stripSlash(entity.id) + "/list");
                    metadata.put("federation_entity", federationEntity);
                }
                if (!metadata.isEmpty()) {
                    spec.claim("metadata", metadata);
                }
                for (Consumer<Statements.Spec> change : entity.configurationChanges) {
                    change.accept(spec);
                }
                String configuration = spec.sign(entity.keys.get(0), this.clock);
                configurations.put(entity.id, configuration);
                http.entityConfiguration(entity.id, configuration);
            }
            for (Entity subordinate : this.entities.values()) {
                for (String superiorId : subordinate.superiors) {
                    Entity superior = this.entities.get(superiorId);
                    Statements.Spec spec = Statements.spec(Statements.ENTITY_STATEMENT_TYP)
                            .claim("iss", superior.id)
                            .claim("sub", subordinate.id)
                            .claim("jwks", Keys.publicJwks(subordinate.keys));
                    for (Consumer<Statements.Spec> change : this.subordinateChanges.getOrDefault(key(superior.id, subordinate.id), List.of())) {
                        change.accept(spec);
                    }
                    String statement = spec.sign(superior.keys.get(0), this.clock);
                    statements.put(key(superior.id, subordinate.id), statement);
                    http.subordinateStatement(ServingMap.stripSlash(superior.id) + "/fetch", subordinate.id, statement);
                }
            }
            return new Federation(this.clock, new LinkedHashMap<>(this.entities), configurations, statements, http);
        }

        private static String kidFor(String id) {
            String host = id.replaceFirst("^https?://", "").replaceAll("[^A-Za-z0-9]+", "-");
            return host + "-1";
        }
    }
}
