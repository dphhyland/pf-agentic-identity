/*
 * The key namespaces of the shared store, one per surface that writes to it.
 */
package com.pingidentity.ps.oidf.clientattestation;

/**
 * Where a surface keeps its state in the shared store. Each namespace is a key prefix, so an operator can
 * see at a glance which surface wrote a key, expire or flush one surface's state without touching another's,
 * and so a {@code jti} spent at the token endpoint is a different record from the same {@code jti} spent at
 * the attester. The layout under a namespace:
 *
 * <ul>
 *   <li>{@code <ns>:challenge:<value>} - a challenge that has been issued and not yet consumed;</li>
 *   <li>{@code <ns>:jti:<client> <jti>} - a proof {@code jti} that has been spent (the space separates the two,
 *       because a client id is a URL and cannot carry an unencoded space);</li>
 *   <li>{@code <ns>:evidence:<sha256>} - the instance key and client a piece of evidence is bound to.</li>
 * </ul>
 *
 * <p>0.3.0 wrote {@code oidf:challenge:*} and {@code oidf:jti:*}. Nothing reads those prefixes from 0.4.0
 * on; keys under them expire on their own TTL. From 0.5.0 each namespace is a
 * {@link com.pingidentity.ps.oidf.platform.redis.RedisKeyspace} over platform's Redis client, and the keys are
 * byte for byte the ones 0.4.0 wrote, so a key written by a 0.4.0 node is found by a 0.5.0 one during a rolling
 * upgrade ({@code RedisAttestationStoreTest}).
 */
public enum StoreNamespace {
    /** The authorization server: the token endpoint's attestation challenges and proof {@code jti}s. */
    AS("oidf:as"),
    /** The client attestation service: the issuance endpoint's challenges, proof {@code jti}s and evidence bindings. */
    CAS("oidf:cas"),
    /** Client authentication at the federation endpoints (OpenID Federation 1.0 §8.8): spent assertion {@code jti}s. */
    FED_ENDPOINT("oidf:fed:endpoint"),
    /** The administration API's DPoP proofs. Reserved: nothing writes under it until the operator API takes DPoP (S-8). */
    ADMIN_DPOP("oidf:admin:dpop");

    private final String prefix;

    StoreNamespace(String prefix) {
        this.prefix = prefix;
    }

    /** The namespace's key prefix, without a trailing separator. */
    public String prefix() {
        return this.prefix;
    }

    /** A challenge's key under the namespace: {@code challenge:<value>}. */
    static String challenge(String challenge) {
        return "challenge:" + challenge;
    }

    /** A spent proof's key under the namespace: {@code jti:<client> <jti>}. */
    static String jti(String clientId, String jti) {
        return "jti:" + (clientId == null ? "" : clientId) + " " + jti;
    }

    /** An evidence binding's key under the namespace: {@code evidence:<sha256>}. */
    static String evidence(String digest) {
        return "evidence:" + digest;
    }

    /** The full key of a challenge, as 0.4.0 wrote it. */
    String challengeKey(String challenge) {
        return this.prefix + ":" + challenge(challenge);
    }

    /** The full key of a spent proof, as 0.4.0 wrote it. */
    String jtiKey(String clientId, String jti) {
        return this.prefix + ":" + jti(clientId, jti);
    }

    /** The full key of an evidence binding, as 0.4.0 wrote it. */
    String evidenceKey(String digest) {
        return this.prefix + ":" + evidence(digest);
    }
}
