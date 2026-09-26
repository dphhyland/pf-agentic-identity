/*
 * Where this entity's key history is kept.
 */
package com.pingidentity.ps.oidf.keyhistory;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The key this entity signs with now, and the keys it signed with before (OpenID Federation 1.0 §8.7).
 */
public interface KeyHistoryStore {

    /**
     * Records that this entity signs with {@code publicJwk} as of {@code now}. When the key recorded before it has another
     * {@code kid}, that key is retired - valid until {@code retiredUntil} - in the same step.
     *
     * @return the key retired, if one was
     */
    Optional<HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant retiredUntil) throws AuthorityRegistryException;

    /**
     * Revokes a retired key. A key may be revoked after it expired; revoking a revoked key changes nothing.
     *
     * @throws AuthorityRegistryException {@link AuthorityRegistryException#NOT_FOUND} for a key that was never retired
     */
    HistoricalKey revoke(String kid, Instant revokedAt, String reason) throws AuthorityRegistryException;

    /** The retired keys, oldest first. */
    List<HistoricalKey> retired() throws AuthorityRegistryException;
}
