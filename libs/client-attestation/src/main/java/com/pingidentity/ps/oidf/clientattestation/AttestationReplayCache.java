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
 *
 * <p>The verdict is three-valued. A store that cannot answer says so, and the caller refuses the request as
 * unavailable (503 {@code temporarily_unavailable}); it is never reported as a replay, because a replay is a
 * finding about the client and an outage is a finding about us, and the two must not share a log line.
 */
public interface AttestationReplayCache {
    int DEFAULT_MAX_ENTRIES = 8192;
    int UNBOUNDED = -1;

    /** What the store found when asked to record a {@code (clientId, jti)} pair. */
    enum Verdict {
        /** The pair was not on record and is now; the proof may be used. */
        FIRST_USE,
        /** The pair was already on record within its TTL: a replay. */
        REPLAY,
        /** The store could not be asked or did not answer; nothing was recorded. */
        STORE_UNAVAILABLE
    }

    /**
     * Records the {@code (clientId, jti)} pair and reports whether it is being seen for the first time.
     *
     * @throws IllegalArgumentException if {@code jti} is blank
     */
    Verdict record(String clientId, String jti, long ttlSeconds);

    /**
     * The boolean view of {@link #record}: {@code true} on {@link Verdict#FIRST_USE}, {@code false} on
     * {@link Verdict#REPLAY}. A store outage is not a boolean and throws instead.
     *
     * @throws StoreUnavailableException on {@link Verdict#STORE_UNAVAILABLE}
     */
    default boolean firstSeen(String clientId, String jti, long ttlSeconds) {
        Verdict verdict = this.record(clientId, jti, ttlSeconds);
        if (verdict == Verdict.STORE_UNAVAILABLE) {
            throw new StoreUnavailableException("the replay store is unavailable; the proof was not checked");
        }
        return verdict == Verdict.FIRST_USE;
    }
}
