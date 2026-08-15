/*
 * Replay protection for attestation proof-of-possession JWTs.
 */
package com.pingidentity.ps.oidf.clientattestation;

/**
 * Time-bounded {@code jti} store used to detect replay of Client Attestation PoP / DPoP proofs
 * (draft-ietf-oauth-attestation-based-client-auth Section 11.1).
 *
 * <p>Implementations: {@link InMemoryAttestationReplayCache} (per-node) and
 * {@link RedisAttestationStore} (shared, cluster-safe). {@link AttestationSupport} selects between
 * them based on configuration.
 */
public interface AttestationReplayCache {
    int DEFAULT_MAX_ENTRIES = 8192;
    int UNBOUNDED = -1;

    /**
     * Records the {@code (clientId, jti)} pair and reports whether it is being seen for the first time.
     *
     * @return {@code true} if this is the first time the jti is seen within its TTL; {@code false} on replay
     */
    boolean firstSeen(String clientId, String jti, long ttlSeconds);
}
