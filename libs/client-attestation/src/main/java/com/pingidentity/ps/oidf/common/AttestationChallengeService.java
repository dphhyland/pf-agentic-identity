/*
 * Server-issued challenges for attestation freshness / replay protection.
 */
package com.pingidentity.ps.oidf.common;

/**
 * Issues and one-time-consumes opaque challenges used as the {@code challenge} claim of a Client
 * Attestation PoP JWT (or the {@code nonce} of a combined-mode DPoP proof), per
 * draft-ietf-oauth-attestation-based-client-auth Sections 6 and 11.1.
 *
 * <p>Implementations: {@link InMemoryAttestationChallengeService} (per-node) and
 * {@link RedisAttestationStore} (shared, cluster-safe). {@link AttestationSupport} selects between
 * them based on configuration.
 */
public interface AttestationChallengeService {
    int DEFAULT_MAX_ENTRIES = 8192;
    long DEFAULT_TTL_SECONDS = 300L;

    /** Issues a fresh challenge (token68-safe base64url) and records it for later one-time consumption. */
    String issue();

    /**
     * Consumes a challenge: returns {@code true} only if it was previously issued and is unexpired. The
     * challenge is removed regardless, so it cannot be reused.
     */
    boolean consume(String challenge);

    /** Lifetime of an issued challenge, advertised as {@code expires_in} by the challenge endpoint. */
    long ttlSeconds();
}
