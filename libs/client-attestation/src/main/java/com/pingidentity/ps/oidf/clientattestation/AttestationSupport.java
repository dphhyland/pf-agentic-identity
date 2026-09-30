/*
 * Process-wide singletons shared between the attestation runtime hook and the challenge endpoint.
 */
package com.pingidentity.ps.oidf.clientattestation;

import com.pingidentity.ps.oidf.platform.health.Startup;
import com.pingidentity.ps.oidf.platform.lifecycle.Lifecycle;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisk;
import com.pingidentity.ps.oidf.platform.profile.AcceptedRisks;
import com.pingidentity.ps.oidf.platform.profile.ProfileRefusals;
import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import java.time.Clock;
import java.util.EnumMap;
import java.util.Map;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link AttestationChallengeService}, {@link AttestationReplayCache} and
 * {@link EvidenceBindingStore} so each surface's challenge endpoint and the checks that consume its challenges
 * share the same state: the authorization server's endpoint with the issuance-criteria hook and the
 * token-endpoint filter (which consume its challenges and detect replay), the attester's endpoint with the
 * attester (which consumes its challenges and binds evidence). Lazily initialised; each challenge servlet may
 * override the sizing and TTL of its own namespace's challenges during {@code init()}.
 *
 * <p>Store selection: if a Redis URL is configured - system property {@code oidf.redis.url}, or env var
 * {@code OIDF_REDIS_URL}, or env var {@code REDIS_URL} (checked in that order, through platform's
 * {@code platform-redis} settings catalogue) - one shared {@link RedisClient}, built from
 * {@link RedisConfig#current()}, backs a {@link RedisAttestationStore} per {@link StoreNamespace}, making challenge
 * consumption, replay detection and evidence binding cluster-wide (and immune to the servlet-vs-hook
 * classloader split, since state lives outside the JVM). Otherwise the per-node in-memory implementations are
 * used, one per namespace, so the two shapes keep the same separation.
 *
 * <p>Under the production profile a {@code redis://} URL is refused by {@link RedisClient}, and a Redis setting
 * whose value is wrong by its catalogue entry; the refusal is logged once and every store accessor throws it, so
 * no surface silently falls back to per-node state. The client is registered with platform's {@link Lifecycle},
 * so the webapp's shutdown closes its pool.
 *
 * <p>In-memory state under the production profile (Phase 3 plan, decisions 9 and 15): every node keeps its own
 * replay, challenge and evidence state, lost on restart and invisible to the other nodes, so a replayed proof or a
 * challenge redeemed twice passes on a second node. {@link #requireSharedState} is how the component that would use
 * a namespace's in-memory stores says so at start: with no Redis URL set, it needs the {@code in-memory-state}
 * accepted risk ({@code OIDF_ACCEPTED_RISKS}), or {@link ProfileRefusals#refuse} refuses the component. The
 * development profile allows it with a WARN. The challenge rate limit's counters are not state in this sense
 * (decision 9): a per-node limit is weaker, not unsafe.
 */
public final class AttestationSupport {
    private static final Log LOGGER = LogFactory.getLog(AttestationSupport.class);
    private static final Object LOCK = new Object();
    private static RedisClient redis;
    private static String redisRefusal;
    private static final Map<StoreNamespace, RedisAttestationStore> REDIS_STORES = new EnumMap<>(StoreNamespace.class);
    private static final Map<StoreNamespace, InMemoryAttestationChallengeService> MEMORY_CHALLENGES = new EnumMap<>(StoreNamespace.class);
    private static final Map<StoreNamespace, InMemoryAttestationReplayCache> MEMORY_REPLAYS = new EnumMap<>(StoreNamespace.class);
    private static EvidenceBindingStore memoryEvidence;
    /** Each namespace's challenge TTL and in-memory size, as its challenge servlet configured them; absent is the default. */
    private static final Map<StoreNamespace, Long> CHALLENGE_TTLS = new EnumMap<>(StoreNamespace.class);
    private static final Map<StoreNamespace, Integer> CHALLENGE_MAX_ENTRIES = new EnumMap<>(StoreNamespace.class);
    private static int replayMaxEntries = AttestationReplayCache.DEFAULT_MAX_ENTRIES;
    /** The accepted risks {@link #requireSharedState} reads: null for this process's ({@link AcceptedRisks#current()}). */
    private static volatile AcceptedRisks risksForTests;

    private AttestationSupport() {
    }

    /**
     * The S-9 component that would use {@code namespace}'s stores: the authorization server's token-endpoint check
     * ({@link Startup#ATTESTATION_AUTH}) for {@link StoreNamespace#AS}, the attester ({@link Startup#ATTESTATION_ISSUER})
     * for {@link StoreNamespace#CAS}, the federation endpoints ({@link Startup#FEDERATION}) for
     * {@link StoreNamespace#FED_ENDPOINT}, and the operator API ({@link Startup#OPERATOR_API}) for
     * {@link StoreNamespace#ADMIN_DPOP}.
     */
    public static String componentOf(StoreNamespace namespace) {
        switch (namespace) {
            case AS:
                return Startup.ATTESTATION_AUTH;
            case CAS:
                return Startup.ATTESTATION_ISSUER;
            case FED_ENDPOINT:
                return Startup.FEDERATION;
            default:
                return Startup.OPERATOR_API;
        }
    }

    /**
     * What {@code namespace} keeps in memory when no Redis URL is set, as a refusal names it: the challenge store and
     * the replay cache, and for {@link StoreNamespace#CAS} the evidence bindings too.
     */
    static String inMemoryStores(StoreNamespace namespace) {
        switch (namespace) {
            case AS:
                return "the authorization server's attestation challenges and spent proof jtis (" + namespace.prefix() + ":*)";
            case CAS:
                return "the attester's challenges, spent proof jtis and evidence bindings (" + namespace.prefix() + ":*)";
            default:
                return "the spent assertion jtis of " + namespace.prefix() + ":*";
        }
    }

    /**
     * Called from the start function of a part that will use {@code namespace}'s stores. Nothing happens when a
     * Redis URL is set (the stores are shared) or the {@code in-memory-state} risk is accepted. Otherwise the stores
     * would be this node's memory, and {@link ProfileRefusals#refuse} decides: under production it refuses the
     * namespace's component ({@link #componentOf}) and throws, so the part is {@code REFUSED} and every part of the
     * component with it; under development it logs a WARN once and returns.
     *
     * @throws com.pingidentity.ps.oidf.platform.settings.ProfileRefused under production, with no Redis URL and the
     *                                                                   risk not accepted
     */
    public static void requireSharedState(StoreNamespace namespace) {
        AcceptedRisks risks = risksForTests;
        requireSharedState(namespace, redisConfigured(), risks != null ? risks : AcceptedRisks.current());
    }

    /** {@link #requireSharedState(StoreNamespace)} with whether Redis is set and the accepted risks given. */
    static void requireSharedState(StoreNamespace namespace, boolean redis, AcceptedRisks risks) {
        if (redis || risks.accepts(AcceptedRisk.IN_MEMORY_STATE)) {
            return;
        }
        AcceptedRisk risk = AcceptedRisk.IN_MEMORY_STATE;
        ProfileRefusals.refuse(componentOf(namespace), inMemoryStores(namespace) + " would be kept in this node's memory,"
                + " because " + RedisConfig.URL_SETTING + " is unset. The production profile allows that only with the risk '"
                + risk.id() + "' accepted (" + risk.description() + "): set " + RedisConfig.URL_SETTING + ", or add " + risk.id()
                + " to " + AcceptedRisks.SETTING + " on a standalone node; a cluster must use Redis");
    }

    /**
     * Tests only: the accepted risks {@link #requireSharedState(StoreNamespace)} reads, in place of this process's;
     * null goes back to the process's.
     */
    public static void acceptedRisksForTests(AcceptedRisks risks) {
        risksForTests = risks;
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
            if (redisConfigured()) {
                return redisStore(namespace);
            }
            return MEMORY_CHALLENGES.computeIfAbsent(namespace,
                    ns -> new InMemoryAttestationChallengeService(challengeMaxEntries(ns), challengeTtlSeconds(ns)));
        }
    }

    /** The replay cache of {@code namespace}. */
    public static AttestationReplayCache replayCache(StoreNamespace namespace) {
        synchronized (LOCK) {
            if (redisConfigured()) {
                return redisStore(namespace);
            }
            return MEMORY_REPLAYS.computeIfAbsent(namespace, ns -> new InMemoryAttestationReplayCache(replayMaxEntries));
        }
    }

    /** The attester's evidence bindings ({@code oidf:cas:evidence:*}). */
    public static EvidenceBindingStore evidenceBindingStore() {
        synchronized (LOCK) {
            if (redisConfigured()) {
                return redisStore(StoreNamespace.CAS);
            }
            if (memoryEvidence == null) {
                memoryEvidence = new InMemoryEvidenceBindingStore();
            }
            return memoryEvidence;
        }
    }

    /** Sizing and TTL for the authorization server's challenges, from its challenge servlet's init-params. */
    public static void configureChallengeService(int maxEntries, long ttlSeconds) {
        configureChallengeService(StoreNamespace.AS, maxEntries, ttlSeconds);
    }

    /**
     * Sizing and TTL for the challenges of {@code namespace}, from that surface's challenge servlet's init-params:
     * the authorization server's endpoint configures {@link StoreNamespace#AS}, the attester's
     * {@link StoreNamespace#CAS}. Each namespace keeps its own settings, so one endpoint's never reach the other's
     * challenges. A value the store refuses (a TTL that is not positive, a size that is neither positive nor -1 in
     * memory) throws before anything is recorded, so the namespace keeps the store it had.
     */
    public static void configureChallengeService(StoreNamespace namespace, int maxEntries, long ttlSeconds) {
        synchronized (LOCK) {
            if (redisConfigured()) {
                RedisAttestationStore store = new RedisAttestationStore(redisClient(), false, namespace, ttlSeconds, Clock.systemUTC());
                REDIS_STORES.put(namespace, store);
                LOGGER.info((Object) ("attestation store " + namespace.prefix() + ":* is Redis, challenge TTL " + ttlSeconds
                        + "s (maxEntries ignored; Redis expires entries natively)"));
            } else {
                MEMORY_CHALLENGES.put(namespace, new InMemoryAttestationChallengeService(maxEntries, ttlSeconds));
            }
            CHALLENGE_MAX_ENTRIES.put(namespace, maxEntries);
            CHALLENGE_TTLS.put(namespace, ttlSeconds);
        }
    }

    /** Sizing for the authorization server's replay cache, from its challenge servlet's init-params. */
    public static void configureReplayCache(int maxEntries) {
        synchronized (LOCK) {
            replayMaxEntries = maxEntries;
            if (redisConfigured()) {
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
            store = new RedisAttestationStore(redisClient(), false, namespace, challengeTtlSeconds(namespace), Clock.systemUTC());
            REDIS_STORES.put(namespace, store);
            LOGGER.info((Object) ("attestation store " + namespace.prefix() + ":* is Redis (shared, cluster-safe)"));
        }
        return store;
    }

    /** Must be called under {@link #LOCK}. The challenge TTL of {@code namespace}: as configured, else the default. */
    private static long challengeTtlSeconds(StoreNamespace namespace) {
        return CHALLENGE_TTLS.getOrDefault(namespace, AttestationChallengeService.DEFAULT_TTL_SECONDS);
    }

    /** Must be called under {@link #LOCK}. The in-memory challenge bound of {@code namespace}: as configured, else the default. */
    private static int challengeMaxEntries(StoreNamespace namespace) {
        return CHALLENGE_MAX_ENTRIES.getOrDefault(namespace, AttestationChallengeService.DEFAULT_MAX_ENTRIES);
    }

    /** Must be called under {@link #LOCK}. The shared client, or the refusal that stopped it being made. */
    private static RedisClient redisClient() {
        if (redis != null) {
            return redis;
        }
        if (redisRefusal != null) {
            throw new IllegalStateException(redisRefusal);
        }
        try {
            redis = new RedisClient(RedisConfig.current());
        } catch (IllegalArgumentException | IllegalStateException e) {
            redisRefusal = refusal(e);
            LOGGER.error((Object) redisRefusal);
            throw new IllegalStateException(redisRefusal, e);
        }
        Lifecycle.current().register("client-attestation Redis client", redis);
        return redis;
    }

    /** Forgets every store, the shared client and any refusal, so a test starts from nothing. */
    static void reset() {
        synchronized (LOCK) {
            if (redis != null) {
                redis.close();
            }
            redis = null;
            redisRefusal = null;
            REDIS_STORES.clear();
            MEMORY_CHALLENGES.clear();
            MEMORY_REPLAYS.clear();
            memoryEvidence = null;
            CHALLENGE_TTLS.clear();
            CHALLENGE_MAX_ENTRIES.clear();
            replayMaxEntries = AttestationReplayCache.DEFAULT_MAX_ENTRIES;
            risksForTests = null;
        }
    }

    /**
     * Why the shared client could not be made: the URL (0.4.0's words), or a setting its catalogue entry refuses (a
     * {@code SettingRefused}, which names the setting and never a secret's value).
     */
    static String refusal(RuntimeException e) {
        return (e instanceof IllegalArgumentException ? "the configured Redis URL is refused: " : "a Redis setting is refused: ")
                + e.getMessage();
    }

    /** Whether a Redis URL is set: {@code oidf.redis.url}, {@code OIDF_REDIS_URL}, then {@code REDIS_URL}. */
    private static boolean redisConfigured() {
        return RedisConfig.isConfigured();
    }
}
