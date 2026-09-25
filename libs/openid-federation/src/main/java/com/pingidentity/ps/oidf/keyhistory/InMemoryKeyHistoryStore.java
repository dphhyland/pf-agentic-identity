/*
 * Key history held in memory.
 */
package com.pingidentity.ps.oidf.keyhistory;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link KeyHistoryStore} for tests and a single-node demo. It forgets everything on restart - including the key it
 * last saw, so a rotation across a restart goes unrecorded.
 */
public final class InMemoryKeyHistoryStore implements KeyHistoryStore {
    private Map<String, Object> current;
    private Instant currentSince;
    private final Map<String, HistoricalKey> retired = new LinkedHashMap<>();

    @Override
    public synchronized Optional<HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant retiredUntil)
            throws AuthorityRegistryException {
        String kid = (String) publicJwk.get("kid");
        Map<String, Object> previous = this.current;
        if (previous != null && kid.equals(previous.get("kid"))) {
            return Optional.empty();
        }
        HistoricalKey returning = this.retired.get(kid);
        if (returning != null && returning.revokedAt() != null) {
            throw new AuthorityRegistryException(AuthorityRegistryException.STALE_UPDATE, "key " + kid + " was revoked and must not sign again");
        }
        // A retired key signing again is no longer history.
        this.retired.remove(kid);
        Instant previousSince = this.currentSince;
        this.current = Map.copyOf(publicJwk);
        this.currentSince = now;
        if (previous == null) {
            return Optional.empty();
        }
        HistoricalKey key = new HistoricalKey((String) previous.get("kid"), previous, previousSince, retiredUntil, null, null);
        this.retired.put(key.kid(), key);
        return Optional.of(key);
    }

    @Override
    public synchronized HistoricalKey revoke(String kid, Instant revokedAt, String reason) throws AuthorityRegistryException {
        HistoricalKey key = this.retired.get(kid);
        if (key == null) {
            throw new AuthorityRegistryException(AuthorityRegistryException.NOT_FOUND, "no retired key " + kid);
        }
        if (key.revokedAt() != null) {
            return key;
        }
        HistoricalKey revoked = new HistoricalKey(kid, key.publicJwk(), key.issuedAt(), key.expiresAt(), revokedAt, reason);
        this.retired.put(kid, revoked);
        return revoked;
    }

    @Override
    public synchronized List<HistoricalKey> retired() {
        return new ArrayList<>(this.retired.values());
    }
}
