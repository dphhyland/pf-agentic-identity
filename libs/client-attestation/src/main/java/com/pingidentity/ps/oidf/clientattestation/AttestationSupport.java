/*
 * Process-wide singletons shared between the attestation runtime hook and the challenge endpoint.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.time.Clock;
import java.util.EnumMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link AttestationChallengeService}, {@link AttestationReplayCache} and
 * {@link EvidenceBindingStore} so the challenge endpoint (which issues challenges), the issuance-criteria hook
 * and the token-endpoint filter (which consume them and detect replay) and the attester (which binds evidence)
 * share the same state. Lazily initialised; the challenge servlet may override sizing/TTL during {@code init()}.
 *
 * <p>Store selection: if a Redis URL is configured - system property {@code oidf.redis.url}, or env var
 * {@code OIDF_REDIS_URL}, or env var {@code REDIS_URL} (checked in that order) - one shared
 * {@link MiniRedisClient} backs a {@link RedisAttestationStore} per {@link StoreNamespace}, making challenge
 * consumption, replay detection and evidence binding cluster-wide (and immune to the servlet-vs-hook
 * classloader split, since state lives outside the JVM). Otherwise the per-node in-memory implementations are
 * used, one per namespace, so the two shapes keep the same separation.
 *
 * <p>Under the production profile a {@code redis://} URL is refused by {@link MiniRedisClient}; the refusal is
 * logged once and every store accessor throws it, so no surface silently falls back to per-node state.
 */
public final class AttestationSupport {
    private static final Log LOGGER = LogFactory.getLog(AttestationSupport.class);
    private static final Object LOCK = new Object();
    private static MiniRedisClient redis;
    private static String redisRefusal;
    private static final Map<StoreNamespace, RedisAttestationStore> REDIS_STORES = new EnumMap<>(StoreNamespace.class);
    private static final Map<StoreNamespace, InMemoryAttestationChallengeService> MEMORY_CHALLENGES = new EnumMap<>(StoreNamespace.class);
    private static final Map<StoreNamespace, InMemoryAttestationReplayCache> MEMORY_REPLAYS = new EnumMap<>(StoreNamespace.class);
    private static EvidenceBindingStore memoryEvidence;
    private static long challengeTtlSeconds = AttestationChallengeService.DEFAULT_TTL_SECONDS;
    private static int challengeMaxEntries = AttestationChallengeService.DEFAULT_MAX_ENTRIES;
    private static int replayMaxEntries = AttestationReplayCache.DEFAULT_MAX_ENTRIES;

    private AttestationSupport() {
    }

    /** The authorization server's challenge store ({@code oidf:as:challenge:*}). */
    public static AttestationChallengeService challengeService() {
        return challengeService(StoreNamespace.AS);
    }

    /** The authorization server's replay cache ({@code oidf:as:jti:*}). */
    public static AttestationReplayCache replayCache() {
        return replayCache(StoreNamespace.AS);
    }

    /** The challenge store of {@code namespace}. */
    public static AttestationChallengeService challengeService(StoreNamespace namespace) {
        synchronized (LOCK) {
            if (redisUrl() != null) {
                return redisStore(namespace);
            }
            return MEMORY_CHALLENGES.computeIfAbsent(namespace,
                    ns -> new InMemoryAttestationChallengeService(challengeMaxEntries, challengeTtlSeconds));
        }
    }

    /** The replay cache of {@code namespace}. */
    public static AttestationReplayCache replayCache(StoreNamespace namespace) {
        synchronized (LOCK) {
            if (redisUrl() != null) {
                return redisStore(namespace);
            }
            return MEMORY_REPLAYS.computeIfAbsent(namespace, ns -> new InMemoryAttestationReplayCache(replayMaxEntries));
        }
    }

    /** The attester's evidence bindings ({@code oidf:cas:evidence:*}). */
    public static EvidenceBindingStore evidenceBindingStore() {
        synchronized (LOCK) {
            if (redisUrl() != null) {
                return redisStore(StoreNamespace.CAS);
            }
            if (memoryEvidence == null) {
                memoryEvidence = new InMemoryEvidenceBindingStore();
            }
            return memoryEvidence;
        }
    }

    /** Sizing and TTL for the authorization server's challenges, from the challenge servlet's init-params. */
    public static void configureChallengeService(int maxEntries, long ttlSeconds) {
        synchronized (LOCK) {
            challengeMaxEntries = maxEntries;
            challengeTtlSeconds = ttlSeconds;
            if (redisUrl() != null) {
                REDIS_STORES.remove(StoreNamespace.AS);
                redisStore(StoreNamespace.AS);
                LOGGER.info((Object) ("attestation challenge/replay store: Redis, challenge TTL " + ttlSeconds
                        + "s (maxEntries ignored; Redis expires entries natively)"));
            } else {
                MEMORY_CHALLENGES.put(StoreNamespace.AS, new InMemoryAttestationChallengeService(maxEntries, ttlSeconds));
            }
        }
    }

    /** Sizing for the authorization server's replay cache, from the challenge servlet's init-params. */
    public static void configureReplayCache(int maxEntries) {
        synchronized (LOCK) {
            replayMaxEntries = maxEntries;
            if (redisUrl() != null) {
                redisStore(StoreNamespace.AS);
                LOGGER.info((Object) "attestation replay cache is Redis-backed; replayCacheMaxEntries ignored");
            } else {
                MEMORY_REPLAYS.put(StoreNamespace.AS, new InMemoryAttestationReplayCache(maxEntries));
            }
        }
    }

    /** Must be called under {@link #LOCK}. The Redis view of {@code namespace}, over the one shared client. */
    private static RedisAttestationStore redisStore(StoreNamespace namespace) {
        RedisAttestationStore store = REDIS_STORES.get(namespace);
        if (store == null) {
            store = new RedisAttestationStore(redisClient(), false, namespace, challengeTtlSeconds, Clock.systemUTC());
            REDIS_STORES.put(namespace, store);
            LOGGER.info((Object) ("attestation store " + namespace.prefix() + ":* is Redis (shared, cluster-safe)"));
        }
        return store;
    }

    /** Must be called under {@link #LOCK}. The shared client, or the refusal that stopped it being made. */
    private static MiniRedisClient redisClient() {
        if (redis != null) {
            return redis;
        }
        if (redisRefusal != null) {
            throw new IllegalStateException(redisRefusal);
        }
        try {
            redis = new MiniRedisClient(redisUrl());
        } catch (IllegalArgumentException e) {
            redisRefusal = "the configured Redis URL is refused: " + e.getMessage();
            LOGGER.error((Object) redisRefusal);
            throw new IllegalStateException(redisRefusal, e);
        }
        return redis;
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
