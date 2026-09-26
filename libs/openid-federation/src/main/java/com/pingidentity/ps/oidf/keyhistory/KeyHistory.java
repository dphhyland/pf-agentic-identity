/*
 * This entity's key history, as its endpoint and its operator see it.
 */
package com.pingidentity.ps.oidf.keyhistory;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import com.pingidentity.ps.oidf.federation.FederationError;
import com.pingidentity.ps.oidf.federation.FederationException;
import com.pingidentity.ps.oidf.federation.HistoricalKeys;
import com.pingidentity.ps.oidf.federation.event.FederationEvents;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The key history of this entity (OpenID Federation 1.0 §8.7): what its historical keys endpoint publishes, the rotation
 * check made when it starts, and revocation.
 *
 * <p>A retired key stays valid for {@code grace} after it is retired, so what it signed before - statements, Trust
 * Marks - can still be checked until they expire. The grace should be at least the longest lifetime of anything this
 * entity signs.
 */
public final class KeyHistory implements HistoricalKeys {
    private final KeyHistoryStore store;
    private final Clock clock;
    private final Duration grace;

    public KeyHistory(KeyHistoryStore store, Clock clock, Duration grace) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.grace = Objects.requireNonNull(grace, "grace");
    }

    /**
     * Records that this entity signs with {@code signingJwk}. When that is a different key from the one recorded before,
     * the old one is retired.
     *
     * @throws AuthorityRegistryException {@link AuthorityRegistryException#STALE_UPDATE} when {@code signingJwk} is a key
     *                                    that was revoked - it must never sign again
     */
    public Optional<HistoricalKey> observe(Map<String, Object> signingJwk) throws AuthorityRegistryException {
        Optional<HistoricalKey> retired = this.store.rotateTo(signingJwk, this.clock.instant(), this.clock.instant().plus(this.grace));
        if (retired.isPresent()) {
            FederationEvents.event(FederationEvents.KEY_RETIRED).audit().field("kid", retired.get().kid()).field("new_kid", signingJwk.get("kid"))
                    .field("exp", retired.get().expiresAt().getEpochSecond()).emit();
        }
        return retired;
    }

    /**
     * Revokes a retired key, with a §8.7.3 reason or none.
     *
     * @throws IllegalArgumentException for a reason §8.7.3 does not define
     */
    public HistoricalKey revoke(String kid, String reason, String actor) throws AuthorityRegistryException {
        if (reason != null && !HistoricalKey.REASONS.contains(reason)) {
            throw new IllegalArgumentException("the reason must be one of " + HistoricalKey.REASONS + " (§8.7.3), or none");
        }
        HistoricalKey revoked = this.store.revoke(kid, this.clock.instant(), reason);
        FederationEvents.event(FederationEvents.KEY_REVOKED).audit().field("kid", kid).field("reason", reason).field("actor", actor).emit();
        return revoked;
    }

    public List<HistoricalKey> retired() throws AuthorityRegistryException {
        return this.store.retired();
    }

    @Override
    public List<Map<String, Object>> keys() {
        try {
            return this.store.retired().stream().map(HistoricalKey::asJwk).toList();
        } catch (AuthorityRegistryException e) {
            throw new FederationException(FederationError.SERVER_ERROR, "the key history could not be read");
        }
    }
}
