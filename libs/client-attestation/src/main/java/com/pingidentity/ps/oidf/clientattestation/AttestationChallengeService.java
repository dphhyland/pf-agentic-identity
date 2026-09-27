/*
 * Server-issued challenges for attestation freshness / replay protection.
 */
package com.pingidentity.ps.oidf.clientattestation;

/**
 * Issues and one-time-consumes opaque challenges used as the {@code challenge} claim of a Client
 * Attestation PoP JWT (or the {@code nonce} of a combined-mode DPoP proof), per
 * draft-ietf-oauth-attestation-based-client-auth Sections 6 and 11.1.
 *
 * <p>Implementations: {@link InMemoryAttestationChallengeService} (per-node) and
 * {@link RedisAttestationStore} (shared, cluster-safe). {@link AttestationSupport} selects between
 * them based on configuration.
 *
 * <p>Consumption is three-valued for the same reason {@link AttestationReplayCache.Verdict} is: a store
 * that cannot answer is an outage to refuse on, never an unknown challenge to blame the client for.
 */
public interface AttestationChallengeService {
    int DEFAULT_MAX_ENTRIES = 8192;
    long DEFAULT_TTL_SECONDS = 300L;

    /** What the store found when asked to consume a challenge. */
    enum Consumption {
        /** The challenge had been issued, was unexpired, and is now spent. */
        CONSUMED,
        /** The challenge was never issued, has expired, or was spent already. */
        UNKNOWN,
        /** The store could not be asked or did not answer; the challenge is untouched. */
        STORE_UNAVAILABLE
    }

    /**
     * Issues a fresh challenge (token68-safe base64url) and records it for later one-time consumption.
     *
     * @throws StoreUnavailableException when the challenge could not be recorded, so it must not be handed out
     */
    String issue();

    /**
     * Consumes a challenge: {@link Consumption#CONSUMED} only if it was previously issued and is unexpired.
     * A known challenge is removed, so it cannot be reused.
     */
    Consumption consumeChallenge(String challenge);

    /**
     * The boolean view of {@link #consumeChallenge}: {@code true} on {@link Consumption#CONSUMED},
     * {@code false} on {@link Consumption#UNKNOWN}. A store outage is not a boolean and throws instead.
     *
     * @throws StoreUnavailableException on {@link Consumption#STORE_UNAVAILABLE}
     */
    default boolean consume(String challenge) {
        Consumption consumption = this.consumeChallenge(challenge);
        if (consumption == Consumption.STORE_UNAVAILABLE) {
            throw new StoreUnavailableException("the challenge store is unavailable; the challenge was not checked");
        }
        return consumption == Consumption.CONSUMED;
    }

    /** Lifetime of an issued challenge, advertised as {@code expires_in} by the challenge endpoint. */
    long ttlSeconds();
}
