/*
 * Cached fetch of a remote trust-bundle JWKS (attestation_bundle_url).
 */
package com.pingidentity.ps.oidf.common;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;

/**
 * Fetches a trust-bundle JWKS by URL and caches it, so clients whose keys rotate (a GKE cluster's OIDC
 * JWKS, a SPIRE bundle endpoint) can be configured with {@code attestation_bundle_url} instead of a pasted
 * inline bundle. Entries are re-fetched after {@link #DEFAULT_TTL_SECONDS}; if a re-fetch fails and a
 * previously-fetched copy exists, the stale copy is served rather than failing issuance (the keys it holds
 * were valid recently, and signature verification still gates everything). A fetch failure with no cached
 * copy is a {@code server_error}.
 */
public final class RemoteJwksCache {

    public static final long DEFAULT_TTL_SECONDS = 300L;

    private final HttpGetClient http;
    private final long ttlSeconds;
    private final Map<String, Entry> cache = new ConcurrentHashMap<>();

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
            if (keys.isEmpty()) {
                throw new IllegalArgumentException("JWKS carries no keys");
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

    private static final class Entry {
        final List<JsonWebKey> keys;
        final long fetchedAtEpochSeconds;

        Entry(List<JsonWebKey> keys, long fetchedAtEpochSeconds) {
            this.keys = List.copyOf(keys);
            this.fetchedAtEpochSeconds = fetchedAtEpochSeconds;
        }
    }
}
