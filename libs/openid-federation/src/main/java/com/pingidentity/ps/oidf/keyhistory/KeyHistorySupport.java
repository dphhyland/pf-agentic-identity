/*
 * The process-wide key history store.
 */
package com.pingidentity.ps.oidf.keyhistory;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the {@link KeyHistoryStore} the federation servlet and the admin API share. The first configuration wins; with
 * none, the first use falls back to memory, loudly - and a history kept in memory cannot notice a rotation across a
 * restart.
 */
public final class KeyHistorySupport {
    private static final Log LOGGER = LogFactory.getLog(KeyHistorySupport.class);
    private static final Object LOCK = new Object();
    private static KeyHistoryStore store;

    /** Resolves the shared store on every call, so wiring done before the store is configured still uses it. */
    private static final KeyHistoryStore SHARED = new KeyHistoryStore() {
        @Override
        public Optional<HistoricalKey> rotateTo(Map<String, Object> publicJwk, Instant now, Instant retiredUntil) throws AuthorityRegistryException {
            return store().rotateTo(publicJwk, now, retiredUntil);
        }

        @Override
        public HistoricalKey revoke(String kid, Instant revokedAt, String reason) throws AuthorityRegistryException {
            return store().revoke(kid, revokedAt, reason);
        }

        @Override
        public List<HistoricalKey> retired() throws AuthorityRegistryException {
            return store().retired();
        }
    };

    private KeyHistorySupport() {
    }

    /** Keeps the history in {@code dataSource} (the {@code V103__federation_key_history.sql} schema). Ignored once configured. */
    public static void configureJdbcStore(DataSource dataSource) {
        Objects.requireNonNull(dataSource, "dataSource");
        synchronized (LOCK) {
            if (store != null) {
                LOGGER.warn("KeyHistorySupport store already configured; ignoring a second configuration");
                return;
            }
            store = new JdbcKeyHistoryStore(dataSource);
        }
    }

    public static boolean isConfigured() {
        synchronized (LOCK) {
            return store != null;
        }
    }

    /** The shared store, looked up afresh on every call. */
    public static KeyHistoryStore shared() {
        return SHARED;
    }

    public static KeyHistoryStore store() {
        synchronized (LOCK) {
            if (store == null) {
                LOGGER.warn("DEV MODE: no durable key history store configured - the history is kept in memory, lost on restart,"
                        + " and a rotation across a restart goes unrecorded");
                store = new InMemoryKeyHistoryStore();
            }
            return store;
        }
    }

    /** Tests only: forget the store. */
    public static void resetForTests() {
        synchronized (LOCK) {
            store = null;
        }
    }
}
