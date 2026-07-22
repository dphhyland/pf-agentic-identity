/*
 * Redis-backed shared store for attestation challenges and jti replay detection.
 */
package com.pingidentity.ps.oidf.common;

import java.io.Closeable;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Cluster-safe {@link AttestationChallengeService} + {@link AttestationReplayCache} backed by Redis,
 * so any node (or classloader) can consume a challenge issued by any other. Both operations map to
 * single atomic Redis commands:
 *
 * <ul>
 *   <li>challenge issue → {@code SET oidf:challenge:<value> 1 EX <ttl>} (Redis expires it natively);</li>
 *   <li>challenge consume → {@code DEL} (returns 1 only if present and unexpired — strict single-use);</li>
 *   <li>replay first-seen → {@code SET oidf:jti:<client> <jti> 1 NX EX <ttl>} ({@code OK} only for the
 *       first writer).</li>
 * </ul>
 *
 * <p>Failure policy is fail-closed: if Redis is unreachable, {@link #consume} and {@link #firstSeen}
 * return {@code false} (authentication fails, client retries with a fresh challenge) and {@link #issue}
 * throws. Availability is never traded for a replayable credential.
 */
public final class RedisAttestationStore implements AttestationChallengeService, AttestationReplayCache, Closeable {
    private static final Log LOGGER = LogFactory.getLog(RedisAttestationStore.class);
    private static final String CHALLENGE_PREFIX = "oidf:challenge:";
    private static final String JTI_PREFIX = "oidf:jti:";
    private static final int CHALLENGE_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final MiniRedisClient client;
    private final long ttlSeconds;

    public RedisAttestationStore(String redisUrl, long ttlSeconds) {
        if (ttlSeconds <= 0L) {
            throw new IllegalArgumentException("ttlSeconds must be > 0, got " + ttlSeconds);
        }
        this.client = new MiniRedisClient(redisUrl);
        this.ttlSeconds = ttlSeconds;
    }

    @Override
    public String issue() {
        byte[] buf = new byte[CHALLENGE_BYTES];
        this.random.nextBytes(buf);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
        try {
            Object reply = this.client.call("SET", CHALLENGE_PREFIX + challenge, "1", "EX", Long.toString(this.ttlSeconds));
            if (!"OK".equals(reply)) {
                throw new IllegalStateException("Unexpected Redis reply issuing challenge: " + reply);
            }
        } catch (IOException e) {
            throw new IllegalStateException("Redis unavailable; cannot issue attestation challenge", e);
        }
        return challenge;
    }

    @Override
    public boolean consume(String challenge) {
        if (challenge == null || challenge.isBlank()) {
            return false;
        }
        try {
            Object reply = this.client.call("DEL", CHALLENGE_PREFIX + challenge);
            return reply instanceof Long && (Long) reply == 1L;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis challenge consume failed; failing closed", e);
            return false;
        }
    }

    @Override
    public long ttlSeconds() {
        return this.ttlSeconds;
    }

    @Override
    public boolean firstSeen(String clientId, String jti, long ttlSeconds) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti is required for replay protection");
        }
        long ttl = ttlSeconds > 0L ? ttlSeconds : 1L;
        String key = JTI_PREFIX + (clientId == null ? "" : clientId) + " " + jti;
        try {
            Object reply = this.client.call("SET", key, "1", "NX", "EX", Long.toString(ttl));
            boolean first = "OK".equals(reply);
            if (!first) {
                LOGGER.debug((Object) ("replay DETECTED for clientId=" + clientId + " jti=" + jti));
            }
            return first;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis replay check failed; failing closed (treating proof as replayed)", e);
            return false;
        }
    }

    @Override
    public void close() {
        this.client.close();
    }
}
