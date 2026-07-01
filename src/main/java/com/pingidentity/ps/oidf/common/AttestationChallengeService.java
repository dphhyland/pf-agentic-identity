/*
 * Server-issued challenges for attestation freshness / replay protection.
 */
package com.pingidentity.ps.oidf.common;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Issues and one-time-consumes opaque challenges used as the {@code challenge} claim of a Client
 * Attestation PoP JWT (or the {@code nonce} of a combined-mode DPoP proof), per
 * draft-ietf-oauth-attestation-based-client-auth Sections 6 and 11.1.
 *
 * <p>Challenges are random, size-bounded and expire after a TTL; {@link #consume(String)} removes the
 * challenge so it can only satisfy one request. State is per-node — a clustered deployment should back
 * this with a shared store or switch to stateless (signed/self-contained) challenges.
 */
public final class AttestationChallengeService {
    public static final int DEFAULT_MAX_ENTRIES = 8192;
    public static final long DEFAULT_TTL_SECONDS = 300L;
    private static final int CHALLENGE_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final int maxEntries;
    private final long ttlSeconds;
    private final LinkedHashMap<String, Long> issued;

    public AttestationChallengeService() {
        this(DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS);
    }

    public AttestationChallengeService(int maxEntries, long ttlSeconds) {
        if (maxEntries != -1 && maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be > 0 or -1 for unbounded, got " + maxEntries);
        }
        if (ttlSeconds <= 0L) {
            throw new IllegalArgumentException("ttlSeconds must be > 0, got " + ttlSeconds);
        }
        this.maxEntries = maxEntries;
        this.ttlSeconds = ttlSeconds;
        this.issued = new LinkedHashMap<String, Long>(16, 0.75f, false) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
                return AttestationChallengeService.this.maxEntries != -1 && this.size() > AttestationChallengeService.this.maxEntries;
            }
        };
    }

    /** Issues a fresh challenge (token68-safe base64url) and records it for later one-time consumption. */
    public synchronized String issue() {
        byte[] buf = new byte[CHALLENGE_BYTES];
        this.random.nextBytes(buf);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
        long now = Instant.now().getEpochSecond();
        this.issued.put(challenge, now + this.ttlSeconds);
        return challenge;
    }

    /**
     * Consumes a challenge: returns {@code true} only if it was previously issued and is unexpired. The
     * challenge is removed regardless, so it cannot be reused.
     */
    public synchronized boolean consume(String challenge) {
        if (challenge == null || challenge.isBlank()) {
            return false;
        }
        Long expiry = this.issued.remove(challenge);
        if (expiry == null) {
            return false;
        }
        return expiry > Instant.now().getEpochSecond();
    }

    public long ttlSeconds() {
        return this.ttlSeconds;
    }

    public synchronized int size() {
        return this.issued.size();
    }
}
