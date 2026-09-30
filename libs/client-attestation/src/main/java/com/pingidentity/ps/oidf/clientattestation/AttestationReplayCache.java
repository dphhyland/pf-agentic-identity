/*
 * Replay protection for attestation proof-of-possession JWTs.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.time.Instant;

/**
 * Time-bounded {@code jti} store used to detect replay of Client Attestation PoP / DPoP proofs
 * (draft-ietf-oauth-attestation-based-client-auth Section 11.1) and of the attester's instance-key proofs.
 *
 * <p>Implementations: {@link InMemoryAttestationReplayCache} (per-node) and
 * {@link RedisAttestationStore} (shared, cluster-safe). {@link AttestationSupport} selects between
 * them based on configuration.
 *
 * <p><b>Retention is an absolute time, derived from the proof's acceptance window</b> (plan item S4c, finding
 * F-0036). A {@code jti} has to be remembered for as long as the proof that carries it could still be accepted,
 * and that is a property of the proof - its {@code iat} and {@code exp} and the verifier's clock skew - not of the
 * moment this store first saw it. Retention counted from first use forgets a proof that is still acceptable
 * whenever the proof's own window is longer than the store's TTL, or has no end at all, and the same proof then
 * authenticates a second time. {@link #recordUntil} is the form to use; the relative {@link #record(String, String,
 * long)} remains for callers whose window is not a proof's.
 *
 * <p>The verdict is three-valued for an answer, plus {@link Verdict#STALE} for a question that should not have
 * been asked. A store that cannot answer says so, and the caller refuses the request as unavailable (503
 * {@code temporarily_unavailable}); it is never reported as a replay, because a replay is a finding about the
 * client and an outage is a finding about us, and the two must not share a log line.
 */
public interface AttestationReplayCache {
    int DEFAULT_MAX_ENTRIES = 8192;
    int UNBOUNDED = -1;

    /** What the store found when asked to record a {@code (clientId, jti)} pair. */
    enum Verdict {
        /** The pair was not on record and is now; the proof may be used. */
        FIRST_USE,
        /** The pair was already on record within its retention: a replay. */
        REPLAY,
        /** The store could not be asked or did not answer; nothing was recorded. */
        STORE_UNAVAILABLE,
        /**
         * The retention asked for had already passed, so the proof can no longer be accepted and nothing was
         * recorded or asked of the store. A caller refuses the proof as stale; one that treats every verdict but
         * {@link #FIRST_USE} as a refusal needs no change for it.
         */
        STALE
    }

    /**
     * Records the {@code (clientId, jti)} pair until {@code retainUntilEpochSeconds} and reports whether it is being
     * seen for the first time. The pair is remembered through the whole of that second: a proof accepted in the
     * last second of its window is still refused as a replay within that second.
     *
     * <p>Named apart from {@link #record(String, String, long)} because the two take a {@code long} each and Java
     * cannot tell an absolute time from a duration by its type.
     *
     * @param retainUntilEpochSeconds the last second, in epoch seconds, at which the proof carrying {@code jti}
     *                                could still be accepted; a time already past answers {@link Verdict#STALE}
     *                                without asking the store
     * @throws IllegalArgumentException if {@code jti} is blank
     */
    Verdict recordUntil(String clientId, String jti, long retainUntilEpochSeconds);

    /**
     * Records the pair for {@code ttlSeconds} from now (at least one second), the retention the stores used before
     * S4c. It survives for the callers outside the attestation proofs - a request object, a federation endpoint's
     * client assertion, the device-enrolment service - whose own windows this package did not re-derive.
     *
     * @deprecated retention counted from first use can be shorter than the proof's acceptance window; derive the
     *             retention from the window and call {@link #recordUntil}
     * @throws IllegalArgumentException if {@code jti} is blank
     */
    @Deprecated
    default Verdict record(String clientId, String jti, long ttlSeconds) {
        long now = Instant.now().getEpochSecond();
        return this.recordUntil(clientId, jti, now + Math.max(1L, ttlSeconds));
    }

    /**
     * The boolean view of {@link #record}: {@code true} on {@link Verdict#FIRST_USE}, {@code false} on
     * {@link Verdict#REPLAY} or {@link Verdict#STALE}. A store outage is not a boolean and throws instead.
     *
     * @deprecated as {@link #record(String, String, long)}: retention counted from first use
     * @throws StoreUnavailableException on {@link Verdict#STORE_UNAVAILABLE}
     */
    @Deprecated
    default boolean firstSeen(String clientId, String jti, long ttlSeconds) {
        Verdict verdict = this.record(clientId, jti, ttlSeconds);
        if (verdict == Verdict.STORE_UNAVAILABLE) {
            throw new StoreUnavailableException("the replay store is unavailable; the proof was not checked");
        }
        return verdict == Verdict.FIRST_USE;
    }
}
