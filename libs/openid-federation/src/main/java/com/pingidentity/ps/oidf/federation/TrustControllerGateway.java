package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.jose.UnverifiedClaims;
import java.util.List;
import com.pingidentity.ps.oidf.jose.JwtCodec;

/**
 * Read-only access to a federation trust controller: fetching an entity's own configuration,
 * its listed members, entity configurations of other entities, and subordinate statements.
 * Default methods layer optional max-age freshness bounds and cache-write batching
 * ({@link SubordinateStatementCache.PendingWrites}) over the three abstract fetch operations.
 *
 * <h2>The resolution budget</h2>
 * A trust chain resolution spends from one {@link ResolutionBudget} (plan item S5b), and the overloads that take
 * one are the ones {@link TrustChainValidator} calls. The validator spends one request before each call - the
 * statement it asks for, whether the gateway answers it from a cache or not - and passes the budget in. A gateway
 * that makes further requests to answer (an authority's Entity Configuration, to find its fetch endpoint; a second
 * retrieval of an anchor's, OpenID Federation 1.0 §11.3) spends one request from the budget for each before making
 * it, and makes every request, the one already paid for included, by the budget's deadline. So no request goes on
 * the network that the budget has not paid for, and none outlives the resolution's wall clock.
 *
 * <p>The budget travels as a trailing parameter rather than in a request object: the interface already layers its
 * optional arguments as overloads with defaults, and a default that forwards to the overload without the budget
 * keeps every existing gateway, and every caller outside a resolution, compiling and behaving as before. Such a
 * gateway is still held to one request of the budget per statement asked for, by the validator; the requests it
 * makes inside a call are its own to bound.
 */
public interface TrustControllerGateway {
    public static final long DEFAULT_MAX_AGE_LIMIT = -1L;
    public static final long DEFAULT_REQUEST_MAX_AGE_LIMIT = 60L;

    public UnverifiedClaims fetchEntityConfiguration() throws Exception;

    public List<String> fetchMembers() throws Exception;

    public String fetchEntityStatement(String var1) throws Exception;

    default public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds) throws Exception {
        return this.fetchEntityStatement(issuer);
    }

    default public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return this.fetchEntityStatement(issuer, maxAgeFromIatSeconds);
    }

    /**
     * The overload a resolution calls: {@code budget} has paid for the statement, and pays for any further request
     * the gateway makes to answer (see the class comment). This default ignores it.
     */
    default public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites,
            ResolutionBudget budget) throws Exception {
        return this.fetchEntityStatement(issuer, maxAgeFromIatSeconds, pendingWrites);
    }

    /** Rejects a configuration that is not typed {@code entity-statement+jwt} (OpenID Federation 1.0 §3). */
    default public UnverifiedClaims fetchEntityConfigurationOf(String issuer) throws Exception {
        String jwt = this.fetchEntityStatement(issuer);
        EntityStatementType.require(jwt, "iss=sub=" + issuer);
        return JwtCodec.parseUnverifiedClaims(jwt);
    }

    /** Rejects a configuration that is not typed {@code entity-statement+jwt} (OpenID Federation 1.0 §3). */
    default public UnverifiedClaims fetchEntityConfigurationOf(String issuer, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        String jwt = this.fetchEntityStatement(issuer, -1L, pendingWrites);
        EntityStatementType.require(jwt, "iss=sub=" + issuer);
        return JwtCodec.parseUnverifiedClaims(jwt);
    }

    public String fetchSubordinateStatement(String var1, String var2) throws Exception;

    default public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject);
    }

    default public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject, maxAgeFromIatSeconds);
    }

    /**
     * The overload a resolution calls: {@code budget} has paid for the statement, and pays for any further request
     * the gateway makes to answer, such as the authority's Entity Configuration (see the class comment). This
     * default ignores it.
     */
    default public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds,
            SubordinateStatementCache.PendingWrites pendingWrites, ResolutionBudget budget) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject, maxAgeFromIatSeconds, pendingWrites);
    }

    /**
     * Tells the gateway which Trust Anchor its chains end at, so that whenever it has to read that
     * anchor's Entity Configuration (to find its fetch endpoint) it verifies it with the anchor's
     * out-of-band keys first, as OpenID Federation 1.0 §10.2 requires of ES[i]. Called by
     * {@link TrustChainValidator}'s constructor, so no call site can build a validator whose gateway
     * skips the check. A gateway that never reads Entity Configurations over the network may ignore it.
     */
    default public void bindTrustAnchor(TrustAnchor trustAnchor, java.util.Set<String> acceptedSigningAlgorithms) {
    }

    /**
     * {@link #bindTrustAnchor} for every anchor of a validator's set. Keys are always chosen by the issuer a
     * configuration claims, so binding several anchors never lets one verify another's statements.
     */
    default public void bindTrustAnchors(TrustAnchorSet trustAnchors, java.util.Set<String> acceptedSigningAlgorithms) {
        for (TrustAnchor anchor : trustAnchors.anchors()) {
            this.bindTrustAnchor(anchor, acceptedSigningAlgorithms);
        }
    }

    /**
     * An anchor's Entity Configuration, for a chain that should end with it (OpenID Federation 1.0 §4). The
     * caller verifies it against the anchor's configured keys; a gateway that already does (retrying once
     * on a mismatch, §11.3) may say so, but must never return a configuration it could not verify.
     */
    default public String anchorConfiguration(TrustAnchor anchor, java.util.Set<String> acceptedSigningAlgorithms,
            SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return this.fetchEntityStatement(anchor.entityId(), -1L, pendingWrites);
    }

    /**
     * The overload a resolution calls: {@code budget} has paid for the configuration, and pays for a second
     * retrieval (§11.3) or any other further request (see the class comment). This default ignores it.
     */
    default public String anchorConfiguration(TrustAnchor anchor, java.util.Set<String> acceptedSigningAlgorithms,
            SubordinateStatementCache.PendingWrites pendingWrites, ResolutionBudget budget) throws Exception {
        return this.anchorConfiguration(anchor, acceptedSigningAlgorithms, pendingWrites);
    }

    default public SubordinateStatementCache.PendingWrites newPendingWrites() {
        return SubordinateStatementCache.disabledPendingWrites();
    }

    default public void evictCachedStatement(String issuer, String subject) {
    }
}
