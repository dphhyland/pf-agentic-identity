/*
 * The authorisation server's JWKS, fetched through platform.http and cached by kid.
 */
package com.pingidentity.ps.oidf.rs;

import com.pingidentity.ps.oidf.platform.http.Deadline;
import com.pingidentity.ps.oidf.platform.http.OutboundHttp;
import com.pingidentity.ps.oidf.platform.http.OutboundResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;

/**
 * A {@link JwksSource} that fetches the authorisation server's {@code jwks_uri} through {@code platform.http}
 * (pinned to checked addresses, bounded in time and size) and caches the keys by {@code kid}.
 *
 * <ul>
 *   <li><b>Deadline.</b> Each fetch has {@code fetchTimeout} end to end - connect, TLS, headers and body.</li>
 *   <li><b>Unknown kid.</b> A {@code kid} the cache does not hold fetches the JWKS again, so a key the server has
 *       just rotated in is found - but at most once per {@code minRefreshInterval}, so a stream of tokens naming
 *       made-up keys costs the authorisation server one request per interval, not one per token.</li>
 *   <li><b>Age.</b> The cache is fetched again once it is {@code maxAge} old, at the same bounded rate, so a key
 *       the server has withdrawn stops verifying within {@code maxAge}.</li>
 *   <li><b>Failure.</b> A failed fetch keeps the keys already held (a key found there still verifies). A
 *       {@code kid} that is not held, when the last fetch failed or none has ever succeeded, is an
 *       {@link IOException}: the answer is not known, and the request is refused as unavailable rather than as
 *       an invalid token.</li>
 * </ul>
 *
 * <p>Lookups are serialised on this object, so while a fetch is under way other requests wait for it, for no
 * longer than {@code fetchTimeout}.
 */
public final class RemoteJwks implements JwksSource {
    public static final Duration DEFAULT_FETCH_TIMEOUT = Duration.ofSeconds(5);
    public static final Duration DEFAULT_MIN_REFRESH_INTERVAL = Duration.ofSeconds(30);
    public static final Duration DEFAULT_MAX_AGE = Duration.ofMinutes(10);

    /** Reads the JWKS document; a seam for the tests. */
    interface Fetch {
        String fetch() throws IOException;
    }

    private final String uri;
    private final Fetch fetch;
    private final long minRefreshMillis;
    private final long maxAgeMillis;
    private final Clock clock;

    private Map<String, List<PublicJsonWebKey>> keys;
    private long fetchedAt;
    private long attemptedAt;
    private boolean attempted;
    private boolean lastFailed;
    private String lastError;

    /** Fetches {@code jwksUri} with the default timeout, refresh interval and age. */
    public RemoteJwks(OutboundHttp http, String jwksUri) {
        this(http, jwksUri, DEFAULT_FETCH_TIMEOUT, DEFAULT_MIN_REFRESH_INTERVAL, DEFAULT_MAX_AGE, Clock.systemUTC());
    }

    public RemoteJwks(OutboundHttp http, String jwksUri, Duration fetchTimeout, Duration minRefreshInterval,
                      Duration maxAge, Clock clock) {
        this(jwksUri, fetcher(Objects.requireNonNull(http, "http"), jwksUri, fetchTimeout), minRefreshInterval,
                maxAge, clock);
    }

    RemoteJwks(String jwksUri, Fetch fetch, Duration minRefreshInterval, Duration maxAge, Clock clock) {
        this.uri = Objects.requireNonNull(jwksUri, "jwksUri");
        this.fetch = Objects.requireNonNull(fetch, "fetch");
        this.minRefreshMillis = minRefreshInterval.toMillis();
        this.maxAgeMillis = maxAge.toMillis();
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    private static Fetch fetcher(OutboundHttp http, String jwksUri, Duration fetchTimeout) {
        Objects.requireNonNull(fetchTimeout, "fetchTimeout");
        return () -> {
            OutboundResponse response = http.get(jwksUri, "application/json", Deadline.after(fetchTimeout));
            if (response.status() != 200) {
                throw new IOException("the JWKS answered " + response.status());
            }
            return response.bodyText();
        };
    }

    @Override
    public synchronized List<PublicJsonWebKey> keys(String kid) throws IOException {
        long now = this.clock.millis();
        if (this.keys == null || now - this.fetchedAt >= this.maxAgeMillis) {
            this.refreshIfAllowed(now);
        }
        List<PublicJsonWebKey> found = this.held(kid);
        if (found.isEmpty()) {
            this.refreshIfAllowed(now);
            found = this.held(kid);
        }
        if (found.isEmpty() && (this.keys == null || this.lastFailed)) {
            throw new IOException("the authorisation server's JWKS at " + this.uri
                    + " could not be read, so whether it has key " + kid + " is not known: " + this.lastError);
        }
        return found;
    }

    private List<PublicJsonWebKey> held(String kid) {
        return this.keys == null ? List.of() : this.keys.getOrDefault(kid, List.of());
    }

    /** Fetches the JWKS, unless the last attempt was less than the minimum refresh interval ago. */
    private void refreshIfAllowed(long now) {
        if (this.attempted && now - this.attemptedAt < this.minRefreshMillis) {
            return;
        }
        this.attempted = true;
        this.attemptedAt = now;
        try {
            this.keys = StaticJwks.index(new JsonWebKeySet(this.fetch.fetch()).getJsonWebKeys());
            this.fetchedAt = now;
            this.lastFailed = false;
        } catch (Exception e) {
            this.lastFailed = true;
            this.lastError = e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }
}
