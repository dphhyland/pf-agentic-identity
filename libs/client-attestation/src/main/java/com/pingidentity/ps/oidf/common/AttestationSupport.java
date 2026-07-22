/*
 * Process-wide singletons shared between the attestation runtime hook and the challenge endpoint.
 */
package com.pingidentity.ps.oidf.common;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link AttestationChallengeService} and {@link AttestationReplayCache} so the
 * challenge endpoint (which issues challenges) and the issuance-criteria hook (which consumes them and
 * detects replay) share the same state. Lazily initialized; the challenge servlet may override
 * sizing/TTL during {@code init()}.
 *
 * <p>Store selection: if a Redis URL is configured — system property {@code oidf.redis.url}, or env var
 * {@code OIDF_REDIS_URL}, or env var {@code REDIS_URL} (checked in that order) — a single shared
 * {@link RedisAttestationStore} backs both roles, making challenge consumption and replay detection
 * cluster-wide (and immune to the servlet-vs-hook classloader split, since state lives outside the
 * JVM). Otherwise the per-node in-memory implementations are used.
 */
public final class AttestationSupport {
    private static final Log LOGGER = LogFactory.getLog(AttestationSupport.class);
    private static final Object LOCK = new Object();
    private static volatile AttestationChallengeService challengeService;
    private static volatile AttestationReplayCache replayCache;

    private AttestationSupport() {
    }

    public static AttestationChallengeService challengeService() {
        AttestationChallengeService local = challengeService;
        if (local == null) {
            synchronized (LOCK) {
                AttestationSupport.ensureInitialized();
                local = challengeService;
            }
        }
        return local;
    }

    public static AttestationReplayCache replayCache() {
        AttestationReplayCache local = replayCache;
        if (local == null) {
            synchronized (LOCK) {
                AttestationSupport.ensureInitialized();
                local = replayCache;
            }
        }
        return local;
    }

    public static void configureChallengeService(int maxEntries, long ttlSeconds) {
        synchronized (LOCK) {
            String redisUrl = AttestationSupport.redisUrl();
            if (redisUrl != null) {
                RedisAttestationStore store = new RedisAttestationStore(redisUrl, ttlSeconds);
                challengeService = store;
                replayCache = store;
                LOGGER.info((Object) ("attestation challenge/replay store: Redis, challenge TTL " + ttlSeconds
                        + "s (maxEntries ignored; Redis expires entries natively)"));
            } else {
                challengeService = new InMemoryAttestationChallengeService(maxEntries, ttlSeconds);
            }
        }
    }

    public static void configureReplayCache(int maxEntries) {
        synchronized (LOCK) {
            if (AttestationSupport.redisUrl() != null) {
                AttestationSupport.ensureInitialized();
                LOGGER.info((Object) "attestation replay cache is Redis-backed; replayCacheMaxEntries ignored");
            } else {
                replayCache = new InMemoryAttestationReplayCache(maxEntries);
            }
        }
    }

    /** Must be called under {@link #LOCK}. Fills whichever singletons are still unset. */
    private static void ensureInitialized() {
        if (challengeService != null && replayCache != null) {
            return;
        }
        String redisUrl = AttestationSupport.redisUrl();
        if (redisUrl != null) {
            RedisAttestationStore store = challengeService instanceof RedisAttestationStore
                    ? (RedisAttestationStore) challengeService
                    : replayCache instanceof RedisAttestationStore
                            ? (RedisAttestationStore) replayCache
                            : new RedisAttestationStore(redisUrl, AttestationChallengeService.DEFAULT_TTL_SECONDS);
            if (challengeService == null) {
                challengeService = store;
            }
            if (replayCache == null) {
                replayCache = store;
            }
            LOGGER.info((Object) "attestation challenge/replay store: Redis (shared, cluster-safe)");
        } else {
            if (challengeService == null) {
                challengeService = new InMemoryAttestationChallengeService();
            }
            if (replayCache == null) {
                replayCache = new InMemoryAttestationReplayCache();
            }
        }
    }

    private static String redisUrl() {
        String url = System.getProperty("oidf.redis.url");
        if (url == null || url.isBlank()) {
            url = System.getenv("OIDF_REDIS_URL");
        }
        if (url == null || url.isBlank()) {
            url = System.getenv("REDIS_URL");
        }
        return url == null || url.isBlank() ? null : url.trim();
    }
}
