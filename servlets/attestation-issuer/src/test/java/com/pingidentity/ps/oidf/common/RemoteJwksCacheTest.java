/*
 * RemoteJwksCache: fresh fetch, TTL-cached reuse, stale-on-error, hard failure.
 */
package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.junit.jupiter.api.Test;

class RemoteJwksCacheTest {

    private static String jwks() throws Exception {
        JsonWebKey pub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("k1")));
        return new JsonWebKeySet(pub).toJson();
    }

    @Test
    void cachesWithinTtlAndRefetchesAfter() throws Exception {
        AtomicInteger fetches = new AtomicInteger();
        String body = jwks();
        HttpGetClient http = (url, accept) -> {
            fetches.incrementAndGet();
            return body;
        };

        RemoteJwksCache fresh = new RemoteJwksCache(http, 300);
        fresh.get("https://cluster.example/jwks");
        fresh.get("https://cluster.example/jwks");
        assertEquals(1, fetches.get(), "second call within TTL served from cache");

        RemoteJwksCache expiring = new RemoteJwksCache(http, 0);
        fetches.set(0);
        expiring.get("https://cluster.example/jwks");
        expiring.get("https://cluster.example/jwks");
        assertEquals(2, fetches.get(), "zero TTL forces a re-fetch every call");
    }

    @Test
    void servesStaleCopyWhenRefetchFails() throws Exception {
        String body = jwks();
        AtomicInteger fetches = new AtomicInteger();
        HttpGetClient http = (url, accept) -> {
            if (fetches.incrementAndGet() == 1) {
                return body;
            }
            throw new IllegalStateException("upstream down");
        };
        RemoteJwksCache cache = new RemoteJwksCache(http, 0);
        assertEquals(1, cache.get("https://cluster.example/jwks").size());
        assertEquals(1, cache.get("https://cluster.example/jwks").size(), "stale copy served on error");
    }

    @Test
    void fetchFailureWithNoCachedCopyIsServerError() {
        HttpGetClient http = (url, accept) -> {
            throw new IllegalStateException("upstream down");
        };
        RemoteJwksCache cache = new RemoteJwksCache(http, 300);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> cache.get("https://cluster.example/jwks"));
        assertEquals("server_error", e.error());
    }

    @Test
    void emptyJwksIsAFetchFailure() {
        HttpGetClient http = (url, accept) -> "{\"keys\":[]}";
        RemoteJwksCache cache = new RemoteJwksCache(http, 300);
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> cache.get("https://cluster.example/jwks"));
        assertEquals("server_error", e.error());
    }
}
