/*
 * Fetches and caches a transmitter's JWKS for shared-signals' SetVerifier (receiver side).
 */
package com.pingidentity.ps.oidf.ssf;

import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundHttpException;
import com.pingidentity.ps.oidf.platform.http.OutboundRequest;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import com.pingidentity.ps.oidf.platform.tls.InsecureTls;
import com.pingidentity.ps.oidf.signals.SetVerifier;
import java.time.Duration;
import java.util.List;
import org.jose4j.jwk.JsonWebKey;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jose4j.jwk.JsonWebKeySet;

/**
 * The receiver's {@link SetVerifier.JwksSource}: fetch the JWKS URL, cache it for {@code cacheTtlSeconds}, and
 * fetch again on demand (the verifier asks once more on an unknown {@code kid} - the standard rotation pattern).
 * shared-signals makes no network call, so the fetch is here, through platform's {@link OutboundHttp} under the
 * receiver's rules ({@link PollReceiverClient#receiverPolicy}): connecting within 1 s, the whole fetch within 2.5 s
 * and at most 64 KiB, since it runs while a pushed SET waits to be verified. A fetch that fails is logged with its reason and
 * throws, and the SET is refused as its verifier refuses one it has no key for.
 */
public final class JwksHttpSource {

    private static final Log LOGGER = LogFactory.getLog(JwksHttpSource.class);

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(1);
    static final Duration TOTAL_TIMEOUT = Duration.ofMillis(2500);
    static final long MAX_BODY_BYTES = 64L * 1024L;

    private JwksHttpSource() {
    }

    /**
     * {@code insecureTls} is the receiver's switch and trusts any certificate chain through platform's
     * {@link InsecureTls}; the host name is still checked.
     */
    public static SetVerifier.JwksSource of(String jwksUrl, long cacheTtlSeconds, boolean insecureTls) {
        return of(jwksUrl, cacheTtlSeconds, PollReceiverClient.receiverHttp(PollReceiverClient.receiverPolicy(), insecureTls,
                CONNECT_TIMEOUT, MAX_BODY_BYTES), TOTAL_TIMEOUT);
    }

    /** The source over {@code http}, each fetch within {@code total}: the test seam. */
    static SetVerifier.JwksSource of(String jwksUrl, long cacheTtlSeconds, OutboundHttp http, Duration total) {
        return new SetVerifier.JwksSource() {
            private volatile List<JsonWebKey> cached;
            private volatile long fetchedAt;

            @Override
            public synchronized List<JsonWebKey> keys(boolean refresh) throws Exception {
                long now = System.currentTimeMillis() / 1000L;
                if (!refresh && this.cached != null && now - this.fetchedAt < cacheTtlSeconds) {
                    return this.cached;
                }
                OutboundResponse resp;
                try {
                    resp = PollReceiverClient.withReason(http,
                            OutboundRequest.get(jwksUrl).header("Accept", "application/json").build(), total);
                } catch (OutboundHttpException e) {
                    // The verifier refuses a SET it has no keys for and says no more, so the reason is logged here.
                    LOGGER.warn((Object) ("SSF receiver: the JWKS fetch failed: " + e.getMessage()));
                    throw e;
                }
                if (resp.status() != 200) {
                    throw new IllegalStateException("JWKS fetch returned HTTP " + resp.status());
                }
                this.cached = new JsonWebKeySet(resp.bodyText()).getJsonWebKeys();
                this.fetchedAt = now;
                return this.cached;
            }
        };
    }
}
