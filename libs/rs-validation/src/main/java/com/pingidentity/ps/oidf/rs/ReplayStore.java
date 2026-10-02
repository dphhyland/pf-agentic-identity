/*
 * Where a resource server remembers the DPoP proofs it has accepted.
 */
package com.pingidentity.ps.oidf.rs;

import java.io.IOException;
import java.time.Duration;

/**
 * Remembers each accepted DPoP proof for as long as the proof itself would be accepted, so the same proof is
 * accepted once. Required: {@link DelegatedTokenValidator.Builder#build()} refuses to build without one.
 *
 * <p>RFC 9449 §11.1: "In the context of the target URI, servers can store the jti value of each DPoP proof for
 * the time window in which the respective DPoP proof JWT would be accepted to prevent multiple uses of the same
 * DPoP proof. HTTP requests to the same URI for which the jti value has been seen before would be declined."
 * The validator computes both the key (a hash, never the raw {@code jti} - the same section: "a server that is
 * tracking jti values should reject DPoP proof JWTs with unnecessarily large jti values or store only a hash
 * thereof") and the window; a store only has to answer whether it has seen the key.
 *
 * <p>Every node that serves one resource must share the store, or a proof accepted by one node is accepted again
 * by the next: {@link RedisReplayStore} for more than one node, {@link InMemoryReplayStore} for one.
 */
public interface ReplayStore {

    /**
     * Records {@code key} for {@code window} if it is not already recorded.
     *
     * @param key    the proof's replay key, at most 64 characters of base64url
     * @param window how long to remember it: at least a millisecond
     * @return true when this is the key's first use in its window, false when it has been seen: a replay
     * @throws IOException when the store cannot answer; the request is then refused as unavailable, never
     *                     accepted
     */
    boolean firstUse(String key, Duration window) throws IOException;
}
