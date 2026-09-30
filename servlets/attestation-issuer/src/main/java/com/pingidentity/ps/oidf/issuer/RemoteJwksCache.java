/*
 * Cached fetch of a remote trust-bundle JWKS (attestation_bundle_url).
 */
package com.pingidentity.ps.oidf.issuer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import com.pingidentity.ps.oidf.jose.JdkHttpGetClient;

/**
 * Fetches a trust-bundle JWKS by URL and caches it, so clients whose keys rotate (a GKE cluster's OIDC
 * JWKS, a SPIRE bundle endpoint) can be configured with {@code attestation_bundle_url} instead of a pasted
 * inline bundle. Entries are re-fetched after {@link #DEFAULT_TTL_SECONDS}; if a re-fetch fails and a
 * previously-fetched copy exists, the stale copy is served rather than failing issuance (the keys it holds
 * were valid recently, and signature verification still gates everything). A fetch failure with no cached
 * copy is a {@code server_error}.
 *
 * <p>Every key of the set is kept, whatever its {@code use}: a SPIRE bundle endpoint's keys carry {@code use}
 * {@code jwt-svid} or {@code x509-svid}, since the SPIFFE bundle format says "The use parameter MUST be set"
 * (SPIFFE Trust Domain and Bundle §4.2.2). A validator that wants signing keys only filters with
 * {@link #signingKeys}, as {@link CloudTokenValidator} does. The cache is bounded: a set of more than
 * {@value #MAX_KEYS} keys is refused as a failed fetch, and at most {@value #MAX_ENTRIES} URLs are held, the oldest
 * fetch dropped first.
 */
public final class RemoteJwksCache {

    public static final long DEFAULT_TTL_SECONDS = 300L;
    /** The most keys one fetched set may hold; a provider's set holds a handful. */
    public static final int MAX_KEYS = 64;
    /** The most URLs held at once. */
    public static final int MAX_ENTRIES = 256;

    private final HttpGetClient http;
    private final long ttlSeconds;
    private final Map<String, Entry> cache = new ConcurrentHashMap<>();

    /**
     * Deliberately NOT given an operator exemption: the URLs this cache fetches come from attestation
     * and metadata content, i.e. from the caller, so they are exactly the input OutboundUrlPolicy
     * exists to screen. An administrator with a genuinely private JWKS host names it in
     * OIDF_FETCH_HOST_ALLOWLIST rather than having the exemption applied here for everyone.
     */
    public RemoteJwksCache() {
        this(new JdkHttpGetClient(false), DEFAULT_TTL_SECONDS);
    }

    public RemoteJwksCache(HttpGetClient http, long ttlSeconds) {
        this.http = http;
        this.ttlSeconds = ttlSeconds;
    }

    /** The bundle keys at {@code url}: cached if fresh, re-fetched if expired, stale-on-error. */
    public List<JsonWebKey> get(String url) throws IssuanceException {
        long now = System.currentTimeMillis() / 1000L;
        Entry cached = this.cache.get(url);
        if (cached != null && now - cached.fetchedAtEpochSeconds < this.ttlSeconds) {
            return cached.keys;
        }
        try {
            String body = this.http.get(url, "application/json");
            List<JsonWebKey> keys = new JsonWebKeySet(body).getJsonWebKeys();
            if (keys.size() > MAX_KEYS) {
                throw new IllegalArgumentException("JWKS carries more than " + MAX_KEYS + " keys");
            }
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("JWKS carries no keys");
            }
            if (cached == null && this.cache.size() >= MAX_ENTRIES) {
                this.evictOldest();
            }
            this.cache.put(url, new Entry(keys, now));
            return keys;
        } catch (Exception e) {
            if (cached != null) {
                return cached.keys;
            }
            throw IssuanceException.serverError("trust bundle could not be fetched: " + url);
        }
    }

    /**
     * The keys whose {@code use} is absent or {@code sig}, in order; empty for null. RFC 7517 §4.2: {@code use} "is
     * employed to indicate whether a public key is used for encrypting data or verifying the signature on data".
     */
    public static List<JsonWebKey> signingKeys(List<JsonWebKey> keys) {
        List<JsonWebKey> out = new ArrayList<>();
        if (keys != null) {
            for (JsonWebKey key : keys) {
                if (key.getUse() == null || "sig".equals(key.getUse())) {
                    out.add(key);
                }
            }
        }
        return out;
    }

    /** Drops the entry fetched longest ago. */
    private void evictOldest() {
        String oldest = null;
        long at = Long.MAX_VALUE;
        for (Map.Entry<String, Entry> e : this.cache.entrySet()) {
            if (e.getValue().fetchedAtEpochSeconds < at) {
                at = e.getValue().fetchedAtEpochSeconds;
                oldest = e.getKey();
            }
        }
        if (oldest != null) {
            this.cache.remove(oldest);
        }
    }

    /** How many URLs are held. */
    int size() {
        return this.cache.size();
    }

    private static final class Entry {
        final List<JsonWebKey> keys;
        final long fetchedAtEpochSeconds;

        Entry(List<JsonWebKey> keys, long fetchedAtEpochSeconds) {
            this.keys = List.copyOf(keys);
            this.fetchedAtEpochSeconds = fetchedAtEpochSeconds;
        }
    }
}
