/*
 * Redis-backed shared store for attestation challenges, jti replay detection and evidence bindings.
 */
package com.pingidentity.ps.oidf.clientattestation;

import java.io.Closeable;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Cluster-safe {@link AttestationChallengeService} + {@link AttestationReplayCache} + {@link EvidenceBindingStore}
 * backed by Redis, so any node (or classloader) can consume a challenge issued by any other, and every node sees
 * the same spent proofs and evidence bindings. One instance serves one {@link StoreNamespace}; each operation is
 * a single atomic Redis command, or two where the second only reads:
 *
 * <ul>
 *   <li>challenge issue → {@code SET <ns>:challenge:<value> 1 EX <ttl>} (Redis expires it natively);</li>
 *   <li>challenge consume → {@code DEL} (returns 1 only if present and unexpired - strict single-use);</li>
 *   <li>replay record → {@code SET <ns>:jti:<client> <jti> 1 NX EX <ttl>} ({@code OK} only for the first writer);</li>
 *   <li>evidence bind → {@code SET <ns>:evidence:<sha256> "<jkt> <client>" NX EX <until the evidence expires>},
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
    private final MiniRedisClient client;
    private final boolean ownsClient;
    private final StoreNamespace namespace;
    private final long ttlSeconds;
    private final Clock clock;

    /** A store of its own over {@code redisUrl}, in the {@link StoreNamespace#AS} namespace. */
    public RedisAttestationStore(String redisUrl, long ttlSeconds) {
        this(redisUrl, StoreNamespace.AS, ttlSeconds);
    }

    /** A store of its own over {@code redisUrl}, in {@code namespace}. */
    public RedisAttestationStore(String redisUrl, StoreNamespace namespace, long ttlSeconds) {
        this(new MiniRedisClient(redisUrl), true, namespace, ttlSeconds, Clock.systemUTC());
    }

    /** A namespaced view over a client shared with other views; {@code ownsClient} says whether {@link #close} closes it. */
    RedisAttestationStore(MiniRedisClient client, boolean ownsClient, StoreNamespace namespace, long ttlSeconds, Clock clock) {
        if (ttlSeconds <= 0L) {
            throw new IllegalArgumentException("ttlSeconds must be > 0, got " + ttlSeconds);
        }
        this.client = client;
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
            Object reply = this.client.call("SET", this.namespace.challengeKey(challenge), "1", "EX", Long.toString(this.ttlSeconds));
            if (!"OK".equals(reply)) {
                throw new StoreUnavailableException("Unexpected Redis reply issuing challenge: " + reply);
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
            Object reply = this.client.call("DEL", this.namespace.challengeKey(challenge));
            return Long.valueOf(1L).equals(reply) ? Consumption.CONSUMED : Consumption.UNKNOWN;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis challenge consume failed; the request is refused as unavailable", e);
            return Consumption.STORE_UNAVAILABLE;
        }
    }

    @Override
    public long ttlSeconds() {
        return this.ttlSeconds;
    }

    @Override
    public Verdict record(String clientId, String jti, long ttlSeconds) {
        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("jti is required for replay protection");
        }
        long ttl = ttlSeconds > 0L ? ttlSeconds : 1L;
        String key = this.namespace.jtiKey(clientId, jti);
        try {
            Object reply = this.client.call("SET", key, "1", "NX", "EX", Long.toString(ttl));
            if ("OK".equals(reply)) {
                return Verdict.FIRST_USE;
            }
            LOGGER.debug((Object) ("replay DETECTED for clientId=" + clientId + " jti=" + jti));
            return Verdict.REPLAY;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis replay check failed; the request is refused as unavailable", e);
            return Verdict.STORE_UNAVAILABLE;
        }
    }

    @Override
    public Binding bind(String evidenceDigest, String jkt, String clientId, long evidenceExpEpochSeconds) {
        if (evidenceDigest == null || evidenceDigest.isBlank() || jkt == null || jkt.isBlank()) {
            throw new IllegalArgumentException("evidence digest and jkt are required to bind evidence");
        }
        String key = this.namespace.evidenceKey(evidenceDigest);
        String value = jkt + " " + (clientId == null ? "" : clientId);
        long ttl = Math.max(1L, evidenceExpEpochSeconds - this.clock.instant().getEpochSecond());
        try {
            // Two attempts: the first SET NX can lose to a key that expires between it and the GET, in which
            // case the second SET NX takes it. A key that is neither settable nor readable is refused.
            for (int attempt = 0; attempt < 2; attempt++) {
                Object reply = this.client.call("SET", key, value, "NX", "EX", Long.toString(ttl));
                if ("OK".equals(reply)) {
                    return Binding.BOUND;
                }
                Object bound = this.client.call("GET", key);
                if (bound != null) {
                    return value.equals(bound) ? Binding.BOUND : Binding.CONFLICT;
                }
            }
            return Binding.CONFLICT;
        } catch (IOException | RuntimeException e) {
            LOGGER.error((Object) "Redis evidence binding failed; the request is refused as unavailable", e);
            return Binding.STORE_UNAVAILABLE;
        }
    }

    @Override
    public void close() {
        if (this.ownsClient) {
            this.client.close();
        }
    }
}
