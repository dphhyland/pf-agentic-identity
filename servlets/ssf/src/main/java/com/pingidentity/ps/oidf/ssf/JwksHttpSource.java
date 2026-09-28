/*
 * Fetches and caches a transmitter's JWKS for shared-signals' SetVerifier (receiver side).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;

/**
 * The receiver's {@link SetVerifier.JwksSource}: fetch the JWKS URL, cache it for {@code cacheTtlSeconds}, and
 * fetch again on demand (the verifier asks once more on an unknown {@code kid} - the standard rotation pattern).
 * shared-signals makes no network call, so the fetch stays here until plan item S5d moves it onto platform's
 * outbound HTTP client.
 */
public final class JwksHttpSource {

    private JwksHttpSource() {
    }

    /**
     * {@code insecureTls} is the receiver's switch and trusts any certificate chain through platform's
     * {@link InsecureTls}; the host name is still checked.
     */
    public static SetVerifier.JwksSource of(String jwksUrl, long cacheTtlSeconds, boolean insecureTls) {
        HttpClient http = InsecureTls.trustAnyCertificate(HttpClient.newBuilder(), PollReceiverClient.RECEIVER_INSECURE_TLS,
                insecureTls).build();
        return new SetVerifier.JwksSource() {
            private volatile List<JsonWebKey> cached;
            private volatile long fetchedAt;

            @Override
            public synchronized List<JsonWebKey> keys(boolean refresh) throws Exception {
                long now = System.currentTimeMillis() / 1000L;
                if (!refresh && this.cached != null && now - this.fetchedAt < cacheTtlSeconds) {
                    return this.cached;
                }
                HttpResponse<String> resp = http.send(
                        HttpRequest.newBuilder(URI.create(jwksUrl)).header("Accept", "application/json").GET().build(),
                        HttpResponse.BodyHandlers.ofString());
                if (resp.statusCode() != 200) {
                    throw new IllegalStateException("JWKS fetch returned HTTP " + resp.statusCode());
                }
                this.cached = new JsonWebKeySet(resp.body()).getJsonWebKeys();
                this.fetchedAt = now;
                return this.cached;
            }
        };
    }
}
