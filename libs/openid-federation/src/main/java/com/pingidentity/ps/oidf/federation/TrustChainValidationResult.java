package com.pingidentity.ps.oidf.federation;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.jose.Claims;

/**
 * Immutable outcome of a successful trust-chain validation: the trust anchor it resolved to,
 * the validated leaf's subject and metadata, the ordered chain of statements, and the leaf's
 * verified entity statement. Metadata and chain are defensively copied and never {@code null}.
 *
 * <p>An entity's {@code metadata} claim carries one block per entity type it holds — an agent is
 * commonly both {@code oauth_client} and {@code oauth_resource} at once. {@link #resolvedMetadata()}
 * surfaces every block the leaf's verified entity statement carried; {@link #metadataFor(String)} is
 * the single-type accessor. Earlier this class surfaced only the {@code openid_relying_party} block
 * under {@link #leafMetadata()} (now deprecated in favour of {@code metadataFor}), which meant a
 * consumer that needed a different type — e.g. {@link ClientEntityAuthorizer}, which reads
 * {@code oauth_client} — never actually received it.
 */
public final class TrustChainValidationResult {
    private final String trustAnchorIssuer;
    private final String leafSubject;
    private final Map<String, Object> resolvedMetadata;
    private final List<String> trustChain;
    private final JwtClaims leafEntityStatement;
    private final Set<String> policedEntityTypes;

    /**
     * @param resolvedMetadata the leaf's full {@code metadata} claim, exactly as verified — one block
     *                         per entity type it holds (e.g. {@code openid_relying_party},
     *                         {@code oauth_client}, {@code oauth_resource}), keyed by entity type.
     *                         Loosely typed ({@code Map<String,Object>}, not
     *                         {@code Map<String,Map<String,Object>>}) to match this codebase's usual
     *                         claim-map convention ({@link Claims#optionalMap}) and so it can be
     *                         handed directly to a consumer such as {@link ClientEntityAuthorizer}
     *                         without a type conversion.
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
        this.policedEntityTypes = policedEntityTypes != null ? Set.copyOf(policedEntityTypes) : Set.of();
        this.trustAnchorIssuer = trustAnchorIssuer;
        this.leafSubject = leafSubject;
        this.resolvedMetadata = resolvedMetadata != null ? Map.copyOf(resolvedMetadata) : Map.of();
        this.trustChain = trustChain != null ? List.copyOf(trustChain) : List.of();
        this.leafEntityStatement = leafEntityStatement;
    }

    public String trustAnchorIssuer() {
        return this.trustAnchorIssuer;
    }

    public String leafSubject() {
        return this.leafSubject;
    }

    /** The leaf's full {@code metadata} claim, one block per entity type it holds. Never {@code null}. */
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

    public List<String> trustChain() {
        return this.trustChain;
    }

    public JwtClaims leafEntityStatement() {
        return this.leafEntityStatement;
    }

    /**
     * The entity types a superior actually constrained: those for which some statement above the leaf
     * declared a non-empty {@code metadata_policy}, composed down the chain and applied here.
     *
     * <p>A type <em>not</em> in this set passed through <em>verbatim</em> from the leaf's own Entity
     * Configuration. That is legal OpenID Federation — a chain need declare no policy at all — but it
     * means nothing above the leaf limited what it asked for: an entity can self-publish any
     * {@code scope}, {@code grant_types} or {@code response_types} it likes and be resolved with them
     * intact. A caller that turns resolved metadata into a client should decide deliberately whether
     * an unconstrained type is acceptable, rather than discovering later that it was.
     */
    public Set<String> policedEntityTypes() {
        return this.policedEntityTypes;
    }

    /** True when a superior in the chain constrained {@code entityType}. See {@link #policedEntityTypes()}. */
    public boolean isPoliced(String entityType) {
        return this.policedEntityTypes.contains(entityType);
    }
}

