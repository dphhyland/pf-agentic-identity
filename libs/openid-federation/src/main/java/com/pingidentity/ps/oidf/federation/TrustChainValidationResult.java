package com.pingidentity.ps.oidf.federation;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.jose.Claims;

/**
 * Immutable outcome of a successful trust-chain validation: the trust anchor it resolved to, the validated
 * leaf's subject and resolved metadata, the chain in OpenID Federation 1.0 §4 shape, when that chain expires,
 * and the leaf's verified entity statement. Collections are defensively copied and never {@code null}.
 *
 * <p>An entity's {@code metadata} claim carries one block per entity type it holds — an agent is
 * commonly both {@code oauth_client} and {@code oauth_resource} at once. {@link #resolvedMetadata()}
 * surfaces every block; {@link #metadataFor(String)} is the single-type accessor. Earlier this class surfaced
 * only the {@code openid_relying_party} block under {@link #leafMetadata()} (now deprecated in favour of
 * {@code metadataFor}), which meant a consumer that needed a different type — e.g.
 * {@link ClientEntityAuthorizer}, which reads {@code oauth_client} — never actually received it.
 */
public final class TrustChainValidationResult {
    private final String trustAnchorIssuer;
    private final String leafSubject;
    private final Map<String, Object> resolvedMetadata;
    private final List<String> trustChain;
    private final List<String> presentedTrustChain;
    private final JwtClaims leafEntityStatement;
    private final Set<String> policedEntityTypes;
    private final Set<String> entityTypesRemovedByConstraint;
    private final long expEpochSeconds;
    private final int fetchesUsed;
    private final TrustChainValidationResult peerChain;

    /**
     * @param resolvedMetadata the leaf's resolved {@code metadata} claim — one block per entity type it holds
     *                         (e.g. {@code openid_relying_party}, {@code oauth_client}, {@code oauth_resource}),
     *                         keyed by entity type. Loosely typed ({@code Map<String,Object>}) to match this
     *                         codebase's claim-map convention ({@link Claims#optionalMap}) and so it can be
     *                         handed directly to a consumer such as {@link ClientEntityAuthorizer}.
     */
    public TrustChainValidationResult(String trustAnchorIssuer, String leafSubject, Map<String, Object> resolvedMetadata, List<String> trustChain, JwtClaims leafEntityStatement) {
        this(trustAnchorIssuer, leafSubject, resolvedMetadata, trustChain, leafEntityStatement, Set.of());
    }

    /**
     * @param policedEntityTypes the entity types for which a superior in the chain actually declared a
     *                           non-empty {@code metadata_policy} that was composed and applied. An
     *                           entity type ABSENT here was resolved from the leaf's own self-published
     *                           metadata with nothing constraining it — see {@link #policedEntityTypes()}.
     */
    public TrustChainValidationResult(String trustAnchorIssuer, String leafSubject, Map<String, Object> resolvedMetadata, List<String> trustChain, JwtClaims leafEntityStatement, Set<String> policedEntityTypes) {
        this(new Builder().trustAnchorIssuer(trustAnchorIssuer).leafSubject(leafSubject).resolvedMetadata(resolvedMetadata)
                .trustChain(trustChain).presentedTrustChain(trustChain).leafEntityStatement(leafEntityStatement)
                .policedEntityTypes(policedEntityTypes));
    }

    private TrustChainValidationResult(Builder b) {
        this.trustAnchorIssuer = b.trustAnchorIssuer;
        this.leafSubject = b.leafSubject;
        this.resolvedMetadata = b.resolvedMetadata != null ? Map.copyOf(b.resolvedMetadata) : Map.of();
        this.trustChain = b.trustChain != null ? List.copyOf(b.trustChain) : List.of();
        this.presentedTrustChain = b.presentedTrustChain != null ? List.copyOf(b.presentedTrustChain) : List.of();
        this.leafEntityStatement = b.leafEntityStatement;
        this.policedEntityTypes = b.policedEntityTypes != null ? Set.copyOf(b.policedEntityTypes) : Set.of();
        this.entityTypesRemovedByConstraint = b.entityTypesRemovedByConstraint != null
                ? Set.copyOf(b.entityTypesRemovedByConstraint) : Set.of();
        this.expEpochSeconds = b.expEpochSeconds;
        this.fetchesUsed = b.fetchesUsed;
        this.peerChain = b.peerChain;
    }

    public String trustAnchorIssuer() {
        return this.trustAnchorIssuer;
    }

    public String leafSubject() {
        return this.leafSubject;
    }

    /** The leaf's resolved {@code metadata} claim, one block per entity type it holds. Never {@code null}. */
    public Map<String, Object> resolvedMetadata() {
        return this.resolvedMetadata;
    }

    /** The metadata block for one entity type (e.g. {@code "oauth_client"}), or empty if the leaf does not hold that type (or holds it as something other than an object). */
    public Map<String, Object> metadataFor(String entityType) {
        return Claims.optionalNestedMap(this.resolvedMetadata, entityType);
    }

    /**
     * @deprecated the leaf's {@code openid_relying_party} block only — a leaf holding other entity
     *             types (e.g. an agent's {@code oauth_client} metadata) is invisible here. Use
     *             {@link #resolvedMetadata()} or {@link #metadataFor(String)} instead.
     */
    @Deprecated
    public Map<String, Object> leafMetadata() {
        return this.metadataFor("openid_relying_party");
    }

    /**
     * The validated chain in OpenID Federation 1.0 §4 shape: the subject's Entity Configuration, the
     * Subordinate Statements from its immediate superior's up to the Trust Anchor's, then the anchor's Entity
     * Configuration when it was presented or asked for (§4 lets a chain omit it). Intermediates' own Entity
     * Configurations, used to find the route, are not part of it.
     */
    public List<String> trustChain() {
        return this.trustChain;
    }

    /** The statements the caller presented, exactly as handed in (possibly empty, possibly in any order). */
    public List<String> presentedTrustChain() {
        return this.presentedTrustChain;
    }

    public JwtClaims leafEntityStatement() {
        return this.leafEntityStatement;
    }

    /**
     * The entity types a superior actually constrained: those for which some statement above the leaf
     * declared a non-empty {@code metadata_policy}, composed down the chain and applied here.
     *
     * <p>A type <em>not</em> in this set passed through from the leaf's own Entity Configuration (and its
     * immediate superior's {@code metadata}, if any). That is legal OpenID Federation — a chain need declare no
     * policy at all — but it means nothing above the leaf limited what it asked for: an entity can
     * self-publish any {@code scope}, {@code grant_types} or {@code response_types} it likes and be resolved
     * with them intact. A caller that turns resolved metadata into a client should decide deliberately whether
     * an unconstrained type is acceptable, rather than discovering later that it was.
     */
    public Set<String> policedEntityTypes() {
        return this.policedEntityTypes;
    }

    /** True when a superior in the chain constrained {@code entityType}. See {@link #policedEntityTypes()}. */
    public boolean isPoliced(String entityType) {
        return this.policedEntityTypes.contains(entityType);
    }

    /** The entity types an {@code allowed_entity_types} constraint removed from the leaf's metadata (§6.2.3). */
    public Set<String> entityTypesRemovedByConstraint() {
        return this.entityTypesRemovedByConstraint;
    }

    /**
     * When the chain expires: the least {@code exp} of its statements (§10.4), in epoch seconds, or -1 when
     * unknown (a result not built by the validator).
     */
    public long expEpochSeconds() {
        return this.expEpochSeconds;
    }

    /** {@link #expEpochSeconds()} as an instant, when known. */
    public Optional<Instant> expiresAt() {
        return this.expEpochSeconds < 0 ? Optional.empty() : Optional.of(Instant.ofEpochSecond(this.expEpochSeconds));
    }

    /** How many fetches the validation spent, cached ones included. */
    public int fetchesUsed() {
        return this.fetchesUsed;
    }

    /** The validated {@code peer_trust_chain} about the OP, when one was presented (§4.4). */
    public Optional<TrustChainValidationResult> peerChain() {
        return Optional.ofNullable(this.peerChain);
    }

    /** For the validator, and for tests that need a result with particular values. */
    public static final class Builder {
        private String trustAnchorIssuer;
        private String leafSubject;
        private Map<String, Object> resolvedMetadata;
        private List<String> trustChain;
        private List<String> presentedTrustChain;
        private JwtClaims leafEntityStatement;
        private Set<String> policedEntityTypes;
        private Set<String> entityTypesRemovedByConstraint;
        private long expEpochSeconds = -1L;
        private int fetchesUsed;
        private TrustChainValidationResult peerChain;

        public Builder trustAnchorIssuer(String value) {
            this.trustAnchorIssuer = value;
            return this;
        }

        public Builder leafSubject(String value) {
            this.leafSubject = value;
            return this;
        }

        public Builder resolvedMetadata(Map<String, Object> value) {
            this.resolvedMetadata = value;
            return this;
        }

        public Builder trustChain(List<String> value) {
            this.trustChain = value;
            return this;
        }

        public Builder presentedTrustChain(List<String> value) {
            this.presentedTrustChain = value;
            return this;
        }

        public Builder leafEntityStatement(JwtClaims value) {
            this.leafEntityStatement = value;
            return this;
        }

        public Builder policedEntityTypes(Set<String> value) {
            this.policedEntityTypes = value;
            return this;
        }

        public Builder entityTypesRemovedByConstraint(Set<String> value) {
            this.entityTypesRemovedByConstraint = value;
            return this;
        }

        public Builder expEpochSeconds(long value) {
            this.expEpochSeconds = value;
            return this;
        }

        public Builder fetchesUsed(int value) {
            this.fetchesUsed = value;
            return this;
        }

        public Builder peerChain(TrustChainValidationResult value) {
            this.peerChain = value;
            return this;
        }

        public TrustChainValidationResult build() {
            return new TrustChainValidationResult(this);
        }
    }
}
