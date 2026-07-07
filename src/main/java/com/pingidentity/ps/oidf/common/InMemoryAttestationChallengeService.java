/*
 * Per-node in-memory implementation of the attestation challenge store.
 */
package com.pingidentity.ps.oidf.common;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * In-memory {@link AttestationChallengeService}. Challenges are random, size-bounded and expire after
 * a TTL; {@link #consume(String)} removes the challenge so it can only satisfy one request.
 *
 * <p>State is per-node — a clustered deployment should use {@link RedisAttestationStore} (or another
 * shared store) instead.
 */
public final class InMemoryAttestationChallengeService implements AttestationChallengeService {
    private static final int CHALLENGE_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final int maxEntries;
    private final long ttlSeconds;
    private final LinkedHashMap<String, Long> issued;

    public InMemoryAttestationChallengeService() {
        this(DEFAULT_MAX_ENTRIES, DEFAULT_TTL_SECONDS);
    }

    public InMemoryAttestationChallengeService(int maxEntries, long ttlSeconds) {
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
                return InMemoryAttestationChallengeService.this.maxEntries != -1
                        && this.size() > InMemoryAttestationChallengeService.this.maxEntries;
            }
        };
    }

    @Override
    public synchronized String issue() {
        byte[] buf = new byte[CHALLENGE_BYTES];
        this.random.nextBytes(buf);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
        long now = Instant.now().getEpochSecond();
        this.issued.put(challenge, now + this.ttlSeconds);
        return challenge;
    }

    @Override
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

    @Override
    public long ttlSeconds() {
        return this.ttlSeconds;
    }

    public synchronized int size() {
        return this.issued.size();
    }
}
