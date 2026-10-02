/*
 * RemoteJwksCache: fresh fetch, TTL-cached reuse, stale-on-error, hard failure, every key kept whatever its use (a SPIRE
 * bundle's are jwt-svid), the signing-key filter the cloud validators apply, and its bounds.
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.jose.HttpGetClient;

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

    private static JsonWebKey key(String kid, String use) throws Exception {
        Map<String, Object> params = new LinkedHashMap<>(TestJwts.publicParams(TestJwts.ec(kid)));
        if (use != null) {
            params.put("use", use);
        }
        return JsonWebKey.Factory.newJwk(params);
    }

    @Test
    void everyKeyIsKeptWhateverItsUseAndSigningKeysFiltersToSig() throws Exception {
        String body = new JsonWebKeySet(key("sig", "sig"), key("enc", "enc"), key("plain", null), key("svid", "jwt-svid"))
                .toJson();
        List<JsonWebKey> keys = new RemoteJwksCache((url, accept) -> body, 300).get("https://cluster.example/jwks");
        assertEquals(List.of("sig", "enc", "plain", "svid"), keys.stream().map(JsonWebKey::getKeyId).toList());
        assertEquals(List.of("sig", "plain"), RemoteJwksCache.signingKeys(keys).stream().map(JsonWebKey::getKeyId).toList());
        assertTrue(RemoteJwksCache.signingKeys(null).isEmpty());
    }

    @Test
    void aSpireBundleFetchedByUrlStillVerifiesAJwtSvid() throws Exception {
        // The SPIFFE bundle format: "The use parameter MUST be set" (to x509-svid, jwt-svid or wit-svid), so a SPIRE
        // bundle endpoint's keys are never use=sig; the cache keeps them for SpiffeSvidValidator as it did before 0.6.0.
        PublicJsonWebKey signer = TestJwts.ec("spire-1");
        Map<String, Object> params = new LinkedHashMap<>(TestJwts.publicParams(signer));
        params.put("use", "jwt-svid");
        String body = new JsonWebKeySet(JsonWebKey.Factory.newJwk(params), key("x509", "x509-svid")).toJson();
        List<JsonWebKey> bundle = new RemoteJwksCache((url, accept) -> body, 300).get("https://spire.example/bundle");
        JwtClaims claims = new JwtClaims();
        claims.setSubject("spiffe://banking.demo/payment-agent");
        claims.setAudience("https://attester.example.com");
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 600L));
        String svid = TestJwts.sign(signer, "ES256", "JWT", claims);
        SpiffeSvid verified = new SpiffeSvidValidator().validate(svid, bundle, "https://attester.example.com", "banking.demo");
        assertEquals("spiffe://banking.demo/payment-agent", verified.spiffeId());
    }

    @Test
    void aSetOfMoreKeysThanTheBoundIsAFetchFailure() throws Exception {
        List<JsonWebKey> many = new ArrayList<>();
        for (int i = 0; i <= RemoteJwksCache.MAX_KEYS; i++) {
            many.add(key("k" + i, null));
        }
        String tooMany = new JsonWebKeySet(many).toJson();
        assertThrows(IssuanceException.class,
                () -> new RemoteJwksCache((url, accept) -> tooMany, 300).get("https://cluster.example/jwks"));
        String enough = new JsonWebKeySet(many.subList(0, RemoteJwksCache.MAX_KEYS)).toJson();
        assertEquals(RemoteJwksCache.MAX_KEYS,
                new RemoteJwksCache((url, accept) -> enough, 300).get("https://cluster.example/jwks").size());
    }

    @Test
    void theCacheHoldsAtMostItsBoundOfUrls() throws Exception {
        String body = jwks();
        RemoteJwksCache cache = new RemoteJwksCache((url, accept) -> body, 0);
        for (int i = 0; i < RemoteJwksCache.MAX_ENTRIES; i++) {
            cache.get("https://cluster.example/" + i);
        }
        assertEquals(RemoteJwksCache.MAX_ENTRIES, cache.size());
        // A re-fetch of a URL it holds evicts nothing; a new URL evicts the oldest fetch.
        cache.get("https://cluster.example/7");
        assertEquals(RemoteJwksCache.MAX_ENTRIES, cache.size());
        cache.get("https://cluster.example/new");
        assertEquals(RemoteJwksCache.MAX_ENTRIES, cache.size());
    }
}
