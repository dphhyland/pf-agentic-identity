/*
 * The attester's cached index of PingFederate's attestation clients.
 */
package com.pingidentity.ps.oidf.servlet.attestation;

import com.pingidentity.ps.oidf.issuer.AttesterClient;
import com.pingidentity.ps.oidf.issuer.IssuanceException;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The attestation clients the issuance endpoint matches evidence against, read from PingFederate once and kept (plan
 * item H-ATT-2, F-0060), instead of every PingFederate client being enumerated on every request.
 *
 * <p>The index is rebuilt three ways: on a schedule, every {@code OIDF_ATTESTER_CLIENT_INDEX_REFRESH_SECONDS} (30 by
 * default), by {@link #refresh} on the webapp's managed executor; on a miss - evidence no indexed client accepts - at
 * most once per {@link #MISS_REFRESH_INTERVAL}, whoever sends it, so unknown evidence cannot make the attester read
 * PingFederate's clients faster than that; and on a read that finds the index older than twice the interval, which
 * covers a schedule that could not start or has stopped. A rebuild that fails keeps the index it had, until the next
 * scheduled or miss rebuild, and logs why; with no index yet, the read fails.
 *
 * <p>What a rebuild costs: one {@code ClientManager.getClients()} - every client PingFederate has, from its
 * configuration or, with a JDBC client store, a read of the whole client table - and the attestation properties of each
 * client that has an attester issuer parsed into an {@code AttestationIssuanceConfig}. What the index costs in
 * staleness: a client added, changed, disabled or deleted in PingFederate is seen here within one interval; a change
 * that makes evidence match a client for the first time is seen at the first miss after it, if that is sooner.
 */
final class ClientBindingIndex {

    private static final Log LOGGER = LogFactory.getLog(ClientBindingIndex.class);

    /** The least time between two rebuilds a miss asks for. */
    static final Duration MISS_REFRESH_INTERVAL = Duration.ofSeconds(5);

    /** Reads every attestation client from the source; what a rebuild runs. */
    @FunctionalInterface
    interface Loader {
        List<AttesterClient> load() throws IssuanceException;
    }

    private record Snapshot(List<AttesterClient> clients, long builtMillis) {
    }

    private final Loader loader;
    private final Clock clock;
    private final long intervalMillis;
    private final Object lock = new Object();
    private volatile Snapshot snapshot;
    /** When a miss last rebuilt the index; far in the past until one does. */
    private long lastMissMillis = Long.MIN_VALUE / 2;
    private long rebuilds;

    ClientBindingIndex(Loader loader, Clock clock, Duration interval) {
        this.loader = Objects.requireNonNull(loader, "loader");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.intervalMillis = interval.toMillis();
    }

    /**
     * The indexed clients: the index as it stands, built first if there is none, and rebuilt first if it is older than
     * twice the interval.
     *
     * @throws IssuanceException what the source threw, when there is no index to fall back on
     */
    List<AttesterClient> clients() throws IssuanceException {
        Snapshot current = this.snapshot;
        return this.fresh(current) ? current.clients() : this.rebuildIfStale();
    }

    /** Whether {@code snapshot} exists and is younger than twice the interval. */
    private boolean fresh(Snapshot snapshot) {
        return snapshot != null && this.clock.millis() - snapshot.builtMillis() < 2 * this.intervalMillis;
    }

    /** Rebuilds under the lock, unless a request that held it first already did: one rebuild for many stale reads. */
    private List<AttesterClient> rebuildIfStale() throws IssuanceException {
        synchronized (this.lock) {
            Snapshot current = this.snapshot;
            return this.fresh(current) ? current.clients() : this.rebuild(current);
        }
    }

    /**
     * Rebuilds the index after a miss, unless a miss rebuilt it less than {@link #MISS_REFRESH_INTERVAL} ago.
     *
     * @return whether it was rebuilt, so the caller knows a second look can find something the first did not
     */
    boolean refreshAfterMiss() {
        synchronized (this.lock) {
            long now = this.clock.millis();
            if (now - this.lastMissMillis < MISS_REFRESH_INTERVAL.toMillis()) {
                return false;
            }
            this.lastMissMillis = now;
            try {
                this.rebuild(this.snapshot);
                return true;
            } catch (IssuanceException e) {
                return false;
            }
        }
    }

    /** The scheduled rebuild: never throws, so the schedule carries on. */
    void refresh() {
        synchronized (this.lock) {
            try {
                this.rebuild(this.snapshot);
            } catch (IssuanceException e) {
                // rebuild has logged it; the index keeps what it had.
            }
        }
    }

    /** How many times the index has been built, for tests and for the cost written above. */
    long rebuilds() {
        synchronized (this.lock) {
            return this.rebuilds;
        }
    }

    /** Must hold {@link #lock}. Reads the source into a new index; on failure keeps {@code previous}, if any. */
    private List<AttesterClient> rebuild(Snapshot previous) throws IssuanceException {
        List<AttesterClient> clients;
        try {
            clients = List.copyOf(this.loader.load());
        } catch (IssuanceException | RuntimeException e) {
            if (previous == null) {
                LOGGER.warn((Object) ("The attester's client index could not be built: " + e.getMessage()));
                throw e instanceof IssuanceException ie ? ie
                        : IssuanceException.serverError("the attester's client index could not be built: " + e);
            }
            LOGGER.warn((Object) ("The attester's client index could not be rebuilt; the one built "
                    + (this.clock.millis() - previous.builtMillis()) / 1000L + " s ago is kept until the next attempt: "
                    + e.getMessage()));
            // Kept as if rebuilt now, so the next attempt is the schedule's or a miss's, not every request's.
            this.snapshot = new Snapshot(previous.clients(), this.clock.millis());
            return previous.clients();
        }
        this.snapshot = new Snapshot(clients, this.clock.millis());
        this.rebuilds++;
        return clients;
    }
}
