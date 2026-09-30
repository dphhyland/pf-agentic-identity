package com.pingidentity.ps.oidf.federation;

import java.time.Clock;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiPredicate;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Thread-safe, optionally size-bounded cache of subordinate/entity statements keyed by
 * authority issuer and subject. Entries carry {@code exp}/{@code iat} so reads can evict on
 * expiry-buffer or max-age, and an access-ordered LRU eviction bounds the size. {@link PendingWrites}
 * lets a caller stage writes during a chain walk and commit or discard them atomically - or commit only
 * those of the route that validated ({@link PendingWrites#commitOnly}).
 *
 * <p>Both parts of a key are compared as {@link EntityId#comparable} forms, so {@code https://a.example/} and
 * {@code https://a.example} are one entry, however a caller spelled them (plan item H-FED-8).
 */
public final class SubordinateStatementCache {
    private static final Log LOGGER = LogFactory.getLog(SubordinateStatementCache.class);
    public static final int DEFAULT_MAX_ENTRIES = 256;
    public static final int UNBOUNDED = -1;
    public static final long DEFAULT_EXPIRY_BUFFER_SECONDS = 300L;
    public static final long NO_MAX_AGE_LIMIT = -1L;
    private final int maxEntries;
    private final Clock clock;
    private final LinkedHashMap<Key, CachedEntry> entries;

    public SubordinateStatementCache() {
        this(256);
    }

    public SubordinateStatementCache(int maxEntries) {
        this(maxEntries, Clock.systemUTC());
    }

    /** As {@link #SubordinateStatementCache(int)}, ageing entries against {@code clock}. */
    public SubordinateStatementCache(int maxEntries, Clock clock) {
        this.clock = java.util.Objects.requireNonNull(clock, "clock");
        if (maxEntries != -1 && maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be > 0 or -1 for unbounded, got " + maxEntries);
        }
        this.maxEntries = maxEntries;
        this.entries = new LinkedHashMap<Key, CachedEntry>(16, 0.75f, true){
            private static final long serialVersionUID = 1L;

            @Override
            protected boolean removeEldestEntry(Map.Entry<Key, CachedEntry> eldest) {
                int limit = SubordinateStatementCache.this.maxEntries;
                if (limit == -1) {
                    return false;
                }
                return this.size() > limit;
            }
        };
    }

    public synchronized String get(String authorityIssuer, String subject, long expiryBufferSeconds) {
        return this.get(authorityIssuer, subject, expiryBufferSeconds, -1L);
    }

    public synchronized String get(String authorityIssuer, String subject, long expiryBufferSeconds, long maxAgeFromIatSeconds) {
        long ageSinceIat;
        Key key = new Key(authorityIssuer, subject);
        CachedEntry entry = this.entries.get(key);
        if (entry == null) {
            LOGGER.debug("cache MISS for iss=" + authorityIssuer + " sub=" + subject + " (size=" + this.entries.size() + ")");
            return null;
        }
        long now = this.clock.instant().getEpochSecond();
        long remaining = entry.expEpochSeconds - now;
        if (remaining <= expiryBufferSeconds) {
            this.entries.remove(key);
            LOGGER.debug("cache EVICT-ON-GET for iss=" + authorityIssuer + " sub=" + subject + " (exp=" + entry.expEpochSeconds + ", now=" + now + ", remainingSeconds=" + remaining + ", bufferSeconds=" + expiryBufferSeconds + ")");
            return null;
        }
        if (maxAgeFromIatSeconds > 0L && entry.iatEpochSeconds > 0L && (ageSinceIat = now - entry.iatEpochSeconds) > maxAgeFromIatSeconds) {
            this.entries.remove(key);
            LOGGER.debug("cache EVICT-ON-AGE for iss=" + authorityIssuer + " sub=" + subject + " (iat=" + entry.iatEpochSeconds + ", now=" + now + ", ageSinceIatSeconds=" + ageSinceIat + ", maxAgeFromIatSeconds=" + maxAgeFromIatSeconds + ")");
            return null;
        }
        LOGGER.debug("cache HIT  for iss=" + authorityIssuer + " sub=" + subject + " (remainingSeconds=" + remaining + ")");
        return entry.jwt;
    }

    public synchronized void put(String authorityIssuer, String subject, String jwt, long expEpochSeconds) {
        this.put(authorityIssuer, subject, jwt, expEpochSeconds, 0L);
    }

    public synchronized void put(String authorityIssuer, String subject, String jwt, long expEpochSeconds, long iatEpochSeconds) {
        this.entries.put(new Key(authorityIssuer, subject), new CachedEntry(jwt, expEpochSeconds, iatEpochSeconds));
        long now = this.clock.instant().getEpochSecond();
        LOGGER.debug("cache PUT  for iss=" + authorityIssuer + " sub=" + subject + " (exp=" + expEpochSeconds + ", iat=" + iatEpochSeconds + ", now=" + now + ", lifetimeSeconds=" + (expEpochSeconds - now) + ", size=" + this.entries.size() + ")");
    }

    public synchronized void evict(String authorityIssuer, String subject) {
        CachedEntry removed = this.entries.remove(new Key(authorityIssuer, subject));
        if (removed != null) {
            LOGGER.debug("cache EVICT-EXPLICIT for iss=" + authorityIssuer + " sub=" + subject);
        }
    }

    public synchronized int size() {
        return this.entries.size();
    }

    public PendingWrites newPendingWrites() {
        return new PendingWrites(this);
    }

    public static PendingWrites disabledPendingWrites() {
        return new PendingWrites(null);
    }

    private static final class BufferedWrite {
        private final String authorityIssuer;
        private final String subject;
        private final String jwt;
        private final long expEpochSeconds;
        private final long iatEpochSeconds;

        private BufferedWrite(String authorityIssuer, String subject, String jwt, long expEpochSeconds, long iatEpochSeconds) {
            this.authorityIssuer = authorityIssuer;
            this.subject = subject;
            this.jwt = jwt;
            this.expEpochSeconds = expEpochSeconds;
            this.iatEpochSeconds = iatEpochSeconds;
        }
    }

    private static final class CachedEntry {
        private final String jwt;
        private final long expEpochSeconds;
        private final long iatEpochSeconds;

        private CachedEntry(String jwt, long expEpochSeconds, long iatEpochSeconds) {
            this.jwt = Objects.requireNonNull(jwt, "jwt");
            this.expEpochSeconds = expEpochSeconds;
            this.iatEpochSeconds = iatEpochSeconds;
        }

    }

    private static final class Key {
        private final String authorityIssuer;
        private final String subject;

        private Key(String authorityIssuer, String subject) {
            this.authorityIssuer = EntityId.comparable(Objects.requireNonNull(authorityIssuer, "authorityIssuer"));
            this.subject = EntityId.comparable(Objects.requireNonNull(subject, "subject"));
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof Key)) {
                return false;
            }
            Key other = (Key)o;
            return this.authorityIssuer.equals(other.authorityIssuer) && this.subject.equals(other.subject);
        }

        public int hashCode() {
            return Objects.hash(this.authorityIssuer, this.subject);
        }
    }

    public static final class PendingWrites {
        private final SubordinateStatementCache cache;
        private final List<BufferedWrite> writes = new ArrayList<BufferedWrite>();

        private PendingWrites(SubordinateStatementCache cache) {
            this.cache = cache;
        }

        public void stagePut(String authorityIssuer, String subject, String jwt, long expEpochSeconds, long iatEpochSeconds) {
            if (this.cache == null) {
                return;
            }
            Objects.requireNonNull(authorityIssuer, "authorityIssuer");
            Objects.requireNonNull(subject, "subject");
            Objects.requireNonNull(jwt, "jwt");
            this.writes.add(new BufferedWrite(authorityIssuer, subject, jwt, expEpochSeconds, iatEpochSeconds));
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("cache STAGE for iss=" + authorityIssuer + " sub=" + subject + " (exp=" + expEpochSeconds + ", iat=" + iatEpochSeconds + ", stagedSoFar=" + this.writes.size() + ")");
            }
        }

        /**
         * A statement already fetched and staged EARLIER IN THIS SAME chain walk — checked
         * before firing another live fetch for the same (authorityIssuer, subject), since
         * staged writes aren't visible in the shared cache until {@link #commit()} runs at
         * the end of the walk. Without this, a single {@code validate()} call that needs the
         * same entity statement more than once (e.g. once while walking authority_hints, again
         * while verifying a signature against it) fetches it over the network every time.
         */
        public String find(String authorityIssuer, String subject) {
            for (int i = this.writes.size() - 1; i >= 0; i--) {
                BufferedWrite w = this.writes.get(i);
                if (EntityId.same(w.authorityIssuer, authorityIssuer) && EntityId.same(w.subject, subject)) {
                    return w.jwt;
                }
            }
            return null;
        }

        /**
         * Commits only the staged statements whose issuer and subject {@code onRoute} accepts - those of the route that
         * validated - and drops the rest: a statement fetched on a route the search abandoned was never validated, and
         * must not answer a later resolution from the cache (plan item H-FED-8).
         */
        public void commitOnly(BiPredicate<String, String> onRoute) {
            Objects.requireNonNull(onRoute, "onRoute");
            this.writes.removeIf(w -> !onRoute.test(w.authorityIssuer, w.subject));
            this.commit();
        }

        public void commit() {
            if (this.cache == null || this.writes.isEmpty()) {
                this.writes.clear();
                return;
            }
            synchronized (this.cache) {
                for (BufferedWrite w : this.writes) {
                    this.cache.entries.put(new Key(w.authorityIssuer, w.subject), new CachedEntry(w.jwt, w.expEpochSeconds, w.iatEpochSeconds));
                }
            }
            if (LOGGER.isDebugEnabled()) {
                long now = this.cache.clock.instant().getEpochSecond();
                LOGGER.debug("cache COMMIT applied " + this.writes.size() + " staged write(s) (cacheSize=" + this.cache.size() + ", now=" + now + ")");
            }
            this.writes.clear();
        }

        public void discard() {
            if (!this.writes.isEmpty() && LOGGER.isDebugEnabled()) {
                LOGGER.debug("cache DISCARD dropped " + this.writes.size() + " staged write(s)");
            }
            this.writes.clear();
        }

        public int stagedCount() {
            return this.writes.size();
        }
    }
}

