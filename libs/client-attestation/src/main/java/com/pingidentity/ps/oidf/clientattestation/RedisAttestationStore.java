/*
 * Redis-backed shared store for attestation challenges, jti replay detection and evidence bindings.
 */
package com.pingidentity.ps.oidf.clientattestation;

import com.pingidentity.ps.oidf.platform.redis.RedisClient;
import com.pingidentity.ps.oidf.platform.redis.RedisConfig;
import com.pingidentity.ps.oidf.platform.redis.RedisKeyspace;
import java.io.Closeable;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Cluster-safe {@link AttestationChallengeService} + {@link AttestationReplayCache} + {@link EvidenceBindingStore}
 * backed by Redis, so any node (or classloader) can consume a challenge issued by any other, and every node sees
 * the same spent proofs and evidence bindings. One instance serves one {@link StoreNamespace}; each operation is
 * a single atomic Redis command, or two where the second only reads, sent through platform's {@link RedisClient}
 * and a {@link RedisKeyspace} over the namespace's prefix:
 *
 * <ul>
 *   <li>challenge issue → {@code SET <ns>:challenge:<value> 1 PX <ttl>} (Redis expires it natively);</li>
 *   <li>challenge consume → {@code DEL} (returns 1 only if present and unexpired - strict single-use);</li>
 *   <li>replay record → {@code SET <ns>:jti:<client> <jti> 1 NX PX <ms to the end of the retention>} ({@code OK} only
 *       for the first writer; the retention is the end of the proof's acceptance window, not a TTL from now);</li>
 *   <li>evidence bind → {@code SET <ns>:evidence:<sha256> "<jkt> <client>" NX PX <ms until the evidence expires>},
 *       and when that finds the key taken, {@code GET} and compare. {@code NX} makes the winner of a race stable:
 *       two nodes presenting the same evidence at once get one {@code OK} between them.</li>
 * </ul>
 *
 * <p>Failure policy: an unreachable Redis, or one that answers with an error, is {@code STORE_UNAVAILABLE} from the
 * tri-state methods and a {@link StoreUnavailableException} from {@link #issue}. The caller refuses the request as
 * unavailable (503). It is never reported as a replay, an unknown challenge or a conflict - those are findings about
 * the client, and this is a finding about us. Availability is never traded for a replayable credential either: no
 * path here lets a request through unchecked.
 */
public final class RedisAttestationStore implements AttestationChallengeService, AttestationReplayCache,
        EvidenceBindingStore, Closeable {
    private static final Log LOGGER = LogFactory.getLog(RedisAttestationStore.class);
    private static final int CHALLENGE_BYTES = 32;

    private final SecureRandom random = new SecureRandom();
    private final RedisClient client;
    private final RedisKeyspace keys;
    private final boolean ownsClient;
    private final StoreNamespace namespace;
    private final long ttlSeconds;
    private final Clock clock;

    /** A store of its own over {@code redisUrl}, in the {@link StoreNamespace#AS} namespace. */
    public RedisAttestationStore(String redisUrl, long ttlSeconds) {
        this(redisUrl, StoreNamespace.AS, ttlSeconds);
    }

    /**
     * A store of its own over {@code redisUrl}, in {@code namespace}, with the rest of the client's settings (the CA
     * file, the pool, the deadlines, Sentinel) and the profile read from this process.
     */
    public RedisAttestationStore(String redisUrl, StoreNamespace namespace, long ttlSeconds) {
        this(new RedisClient(RedisConfig.currentFor(redisUrl)), true, namespace, ttlSeconds, Clock.systemUTC());
    }

    /** A namespaced view over a client shared with other views; {@code ownsClient} says whether {@link #close} closes it. */
    RedisAttestationStore(RedisClient client, boolean ownsClient, StoreNamespace namespace, long ttlSeconds, Clock clock) {
        if (ttlSeconds <= 0L) {
            throw new IllegalArgumentException("ttlSeconds must be > 0, got " + ttlSeconds);
        }
        this.client = client;
        this.keys = client.keyspace(namespace.prefix());
        this.ownsClient = ownsClient;
        this.namespace = namespace;
        this.ttlSeconds = ttlSeconds;
        this.clock = clock;
    }

    public StoreNamespace namespace() {
        return this.namespace;
    }

    @Override
    public String issue() {
        byte[] buf = new byte[CHALLENGE_BYTES];
        this.random.nextBytes(buf);
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
        try {
            if (!this.keys.set(StoreNamespace.challenge(challenge), "1", Duration.ofSeconds(this.ttlSeconds))) {
                throw new StoreUnavailableException("Unexpected Redis reply issuing challenge");
            }
        } catch (IOException | RuntimeException e) {
            throw new StoreUnavailableException("Redis unavailable; cannot issue attestation challenge", e);
        }
        return challenge;
    }

    @Override
    public Consumption consumeChallenge(String challenge) {
        if (challenge == null || challenge.isBlank()) {
            return Consumption.UNKNOWN;
        }
        try {
            return this.keys.del(StoreNamespace.challenge(challenge)) == 1L ? Consumption.CONSUMED : Consumption.UNKNOWN;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis challenge consume failed; the request is refused as unavailable", e);
            return Consumption.STORE_UNAVAILABLE;
        }
    }

    @Override
    public long ttlSeconds() {
        return this.ttlSeconds;
    }

    /**
     * {@code SET <ns>:jti:<client>:<jti> 1 NX PX <ms>}, where {@code <ms>} runs to the end of the second
     * {@code retainUntilEpochSeconds}, computed once from this store's clock. Platform's {@link RedisClient} has no
     * {@code PXAT}, and one computation keeps the expiry absolute to within the time the command takes to arrive:
     * a key set late expires late, never early. A retention already past answers {@link Verdict#STALE} and sends
     * nothing.
     */
    @Override
    public Verdict recordUntil(String clientId, String jti, long retainUntilEpochSeconds) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti is required for replay protection");
        }
        long nowMillis = this.clock.millis();
        if (retainUntilEpochSeconds < nowMillis / 1000L) {
            return Verdict.STALE;
        }
        long endMillis = retainUntilEpochSeconds >= Long.MAX_VALUE / 1000L - 1L
                ? Long.MAX_VALUE : (retainUntilEpochSeconds + 1L) * 1000L;
        long ttlMillis = Math.max(1L, endMillis - nowMillis);
        String key = StoreNamespace.jti(clientId, jti);
        try {
            if (this.keys.setIfAbsent(key, "1", Duration.ofMillis(ttlMillis))) {
                return Verdict.FIRST_USE;
            }
            LOGGER.debug((Object) ("replay DETECTED for clientId=" + clientId + " jti=" + jti));
            return Verdict.REPLAY;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis replay check failed; the request is refused as unavailable", e);
            return Verdict.STORE_UNAVAILABLE;
        }
    }

    /** The relative form, timed by this store's clock rather than the system's. */
    @Override
    @Deprecated
    public Verdict record(String clientId, String jti, long ttlSeconds) {
        return this.recordUntil(clientId, jti, this.clock.millis() / 1000L + Math.max(1L, ttlSeconds));
    }

    @Override
    public Result bind(String evidenceDigest, String jkt, String clientId, long evidenceExpEpochSeconds) {
        if (evidenceDigest == null || evidenceDigest.isBlank() || jkt == null || jkt.isBlank()) {
            throw new IllegalArgumentException("evidence digest and jkt are required to bind evidence");
        }
        String key = StoreNamespace.evidence(evidenceDigest);
        String value = jkt + " " + (clientId == null ? "" : clientId);
        // Until the evidence expires, to the millisecond; evidence already expired is held for a second, not forever.
        long ttlMillis = Math.max(1000L, evidenceExpEpochSeconds * 1000L - this.clock.millis());
        try {
            // Two attempts: the first SET NX can lose to a key that expires between it and the GET, in which
            // case the second SET NX takes it.
            for (int attempt = 0; attempt < 2; attempt++) {
                if (this.keys.setIfAbsent(key, value, Duration.ofMillis(ttlMillis))) {
                    return Result.bound();
                }
                String bound = this.keys.get(key);
                if (bound != null) {
                    return value.equals(bound) ? Result.bound() : conflictWith(bound);
                }
            }
            // A key that twice could be neither taken nor read: nothing was bound and nothing was learned about
            // who holds it, so this is the store failing to answer - not a conflict, which would audit a theft.
            LOGGER.error((Object) ("Redis evidence binding for " + this.keys.key(key) + " could be neither set nor read; the request is refused as unavailable"));
            return Result.unavailable();
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis evidence binding failed; the request is refused as unavailable", e);
            return Result.unavailable();
        }
    }

    /** A conflict with the holder a bound value names: {@code "<jkt> <client>"}, the client possibly empty. */
    static Result conflictWith(String held) {
        int space = held.indexOf(' ');
        return space < 0 ? Result.conflict(held, "") : Result.conflict(held.substring(0, space), held.substring(space + 1));
    }

    @Override
    public void close() {
        if (this.ownsClient) {
            this.client.close();
        }
    }
}
