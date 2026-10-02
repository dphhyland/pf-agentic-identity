/*
 * What stands between a caller and a trust chain resolution at the resolve endpoint.
 */
package com.pingidentity.ps.oidf.federation;

import com.pingidentity.ps.oidf.platform.settings.Catalogue;
import com.pingidentity.ps.oidf.platform.settings.Settings;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The resolve endpoint's cap and cache (plan item H-FED-9). OpenID Federation 1.0 §18.1 names the resolve endpoint the
 * first of the interfaces that "could be used for Denial-of-Service attacks", and says of an unauthenticated one that it
 * "should only respond to unauthenticated Client requests with cached information about Entities that have already been
 * evaluated". So:
 *
 * <ul>
 *   <li>one caller address is answered about at most {@link #SUBJECTS_PER_MINUTE_SETTING} distinct subjects in any
 *       minute; one more is refused {@code temporarily_unavailable} (§8.9: "unable to handle the request due to temporary
 *       overloading") with the seconds until the oldest leaves the minute, and a subject already counted is not counted
 *       again;</li>
 *   <li>a response is kept for {@link #CACHE_SECONDS_SETTING} or until its own {@code exp}, whichever is sooner, and the
 *       same request - subject, trust anchors, entity types, the issuer answering and the client it is addressed to -
 *       is answered with it.</li>
 * </ul>
 *
 * <p>Both tables are bounded ({@link #MAX_CALLERS}, {@link #MAX_RESPONSES}), the least recently used dropped first; a
 * caller dropped from a full table starts a new minute, and the validator's own budget still bounds what it can cost.
 */
public final class ResolveGuard {
    public static final String SUBJECTS_PER_MINUTE_SETTING = "OIDF_FEDERATION_RESOLUTION_RESOLVE_SUBJECTS_PER_MINUTE";
    public static final String CACHE_SECONDS_SETTING = "OIDF_FEDERATION_RESOLUTION_RESOLVE_CACHE_SECONDS";

    /** How many caller addresses are tracked at once. */
    static final int MAX_CALLERS = 10_000;

    /** How many resolve responses are kept at once. */
    static final int MAX_RESPONSES = 1_000;

    private static final Duration WINDOW = Duration.ofMinutes(1);

    /** The caller refused: how long until it may ask about another subject. */
    public static final class Limited extends FederationException {
        private static final long serialVersionUID = 1L;
        private final long retryAfterSeconds;

        Limited(long retryAfterSeconds, int cap) {
            super(FederationError.TEMPORARILY_UNAVAILABLE, "this resolver answers at most " + cap
                    + " distinct subjects a minute for one caller; ask again in " + retryAfterSeconds + " s");
            this.retryAfterSeconds = retryAfterSeconds;
        }

        /** For the {@code Retry-After} header. */
        public long retryAfterSeconds() {
            return this.retryAfterSeconds;
        }
    }

    private record Key(String issuer, String subject, List<String> anchors, List<String> entityTypes, String client) {
    }

    private record Kept(String jwt, Instant until) {
    }

    private final int subjectsPerMinute;
    private final Duration cacheFor;
    private final Clock clock;
    /** Caller address -> the subjects it was answered about, each with when it was first counted this minute. */
    private final LinkedHashMap<String, LinkedHashMap<String, Instant>> callers = lru(MAX_CALLERS);
    private final LinkedHashMap<Key, Kept> responses = lru(MAX_RESPONSES);

    ResolveGuard(int subjectsPerMinute, Duration cacheFor, Clock clock) {
        if (subjectsPerMinute < 1) {
            throw new IllegalArgumentException("subjectsPerMinute must be at least 1");
        }
        this.subjectsPerMinute = subjectsPerMinute;
        this.cacheFor = Objects.requireNonNull(cacheFor, "cacheFor");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** The limits {@code settings} (a {@code federation-resolution} catalogue's) name. */
    static ResolveGuard fromSettings(Settings settings, Clock clock) {
        return new ResolveGuard(settings.integer(SUBJECTS_PER_MINUTE_SETTING), settings.duration(CACHE_SECONDS_SETTING), clock);
    }

    /** The limits this process's {@code federation-resolution} settings name. */
    static ResolveGuard fromProcess(Clock clock) {
        return fromSettings(Settings.of(CatalogueHolder.CATALOGUE, Sources.process()), clock);
    }

    /**
     * Counts {@code subject} against {@code caller}'s minute.
     *
     * @throws Limited when it is a new subject and the caller has had its share this minute
     */
    synchronized void admit(String caller, String subject) {
        Instant now = this.clock.instant();
        LinkedHashMap<String, Instant> seen = this.callers.computeIfAbsent(String.valueOf(caller), c -> new LinkedHashMap<>());
        for (Iterator<Instant> first = seen.values().iterator(); first.hasNext(); ) {
            if (!first.next().plus(WINDOW).isAfter(now)) {
                first.remove();
            }
        }
        String key = EntityId.comparable(subject);
        if (seen.containsKey(key)) {
            return;
        }
        if (seen.size() >= this.subjectsPerMinute) {
            Instant oldest = seen.values().iterator().next();
            throw new Limited(Math.max(1L, Duration.between(now, oldest.plus(WINDOW)).toSeconds() + 1), this.subjectsPerMinute);
        }
        seen.put(key, now);
    }

    /** The response kept for this request, while it may still be served. */
    synchronized String kept(ResolveRequest request, String issuer, String client) {
        Key key = key(request, issuer, client);
        Kept kept = this.responses.get(key);
        if (kept == null) {
            return null;
        }
        if (!this.clock.instant().isBefore(kept.until())) {
            this.responses.remove(key);
            return null;
        }
        return kept.jwt();
    }

    /** Keeps {@code jwt}, which expires at {@code expEpochSeconds}, for this request. */
    synchronized void keep(ResolveRequest request, String issuer, String client, String jwt, long expEpochSeconds) {
        Instant until = this.clock.instant().plus(this.cacheFor);
        Instant exp = Instant.ofEpochSecond(expEpochSeconds);
        if (exp.isBefore(until)) {
            until = exp;
        }
        if (until.isAfter(this.clock.instant())) {
            this.responses.put(key(request, issuer, client), new Kept(jwt, until));
        }
    }

    private static Key key(ResolveRequest request, String issuer, String client) {
        return new Key(EntityId.comparable(issuer), EntityId.comparable(request.subject()),
                request.trustAnchors().stream().map(EntityId::comparable).toList(), List.copyOf(request.entityTypes()),
                client == null ? null : EntityId.comparable(client));
    }

    private static <K, V> LinkedHashMap<K, V> lru(int max) {
        return new LinkedHashMap<>(16, 0.75f, true) {
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<K, V> eldest) {
                return this.size() > max;
            }
        };
    }

    /** The catalogue, loaded once per loaded copy of this class and read from the process each time. */
    private static final class CatalogueHolder {
        static final Catalogue CATALOGUE = Catalogue.load(ResolveGuard.class.getClassLoader(), ValidatorOptions.COMPONENT);
    }
}
