package com.pingidentity.ps.oidf.federation;

import java.util.List;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.jose.JwtCodec;

/**
 * Read-only access to a federation trust controller: fetching an entity's own configuration,
 * its listed members, entity configurations of other entities, and subordinate statements.
 * Default methods layer optional max-age freshness bounds and cache-write batching
 * ({@link SubordinateStatementCache.PendingWrites}) over the three abstract fetch operations.
 */
public interface TrustControllerGateway {
    public static final long DEFAULT_MAX_AGE_LIMIT = -1L;
    public static final long DEFAULT_REQUEST_MAX_AGE_LIMIT = 60L;

    public JwtClaims fetchEntityConfiguration() throws Exception;

    public List<String> fetchMembers() throws Exception;

    public String fetchEntityStatement(String var1) throws Exception;

    default public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds) throws Exception {
        return this.fetchEntityStatement(issuer);
    }

    default public String fetchEntityStatement(String issuer, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return this.fetchEntityStatement(issuer, maxAgeFromIatSeconds);
    }

    default public JwtClaims fetchEntityConfigurationOf(String issuer) throws Exception {
        return JwtCodec.parseUnverifiedClaims(this.fetchEntityStatement(issuer));
    }

    default public JwtClaims fetchEntityConfigurationOf(String issuer, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return JwtCodec.parseUnverifiedClaims(this.fetchEntityStatement(issuer, -1L, pendingWrites));
    }

    public String fetchSubordinateStatement(String var1, String var2) throws Exception;

    default public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject);
    }

    default public String fetchSubordinateStatement(String authorityIssuer, String subject, long maxAgeFromIatSeconds, SubordinateStatementCache.PendingWrites pendingWrites) throws Exception {
        return this.fetchSubordinateStatement(authorityIssuer, subject, maxAgeFromIatSeconds);
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

    default public SubordinateStatementCache.PendingWrites newPendingWrites() {
        return SubordinateStatementCache.disabledPendingWrites();
    }

    default public void evictCachedStatement(String issuer, String subject) {
    }
}
