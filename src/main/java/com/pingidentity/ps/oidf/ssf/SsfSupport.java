/*
 * Process-wide singletons shared across the SSF servlets and the delivery executor.
 */
package com.pingidentity.ps.oidf.ssf;

import java.util.Objects;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link SsfConfiguration}, {@link SsfStore}, and {@link SetMinter} so every SSF servlet
 * (configuration, stream management, poll) and the background push executor operate on one shared state — the
 * same pattern as {@code AttestationSupport}. First servlet to {@code init()} configures it; later servlets
 * see the same instance.
 *
 * <p>Store selection follows {@code dataStoreId}: blank selects the per-node {@link InMemorySsfStore} (not
 * cluster-safe, not durable); a set id selects the PingFederate JDBC-backed store. The JDBC store is installed
 * by {@link #installStoreFactory} so this core has no compile-time dependency on the PF SDK.
 */
public final class SsfSupport {

    private static final Log LOGGER = LogFactory.getLog(SsfSupport.class);
    private static final Object LOCK = new Object();

    private static volatile SsfConfiguration configuration;
    private static volatile SsfStore store;
    private static volatile SetMinter minter;
    private static volatile StoreFactory storeFactory;

    private SsfSupport() {
    }

    /** Creates an {@link SsfStore} for a data store id; supplied by the JDBC-backed servlet layer at init. */
    public interface StoreFactory {
        SsfStore create(String dataStoreId);
    }

    /**
     * Register a factory that can build a JDBC-backed store from a {@code dataStoreId}. Called by the servlet
     * layer (which can reach the PF SDK) before {@link #configure}. If none is registered, a configured
     * {@code dataStoreId} falls back to the in-memory store with a warning.
     */
    public static void installStoreFactory(StoreFactory factory) {
        synchronized (LOCK) {
            storeFactory = factory;
        }
    }

    /** Idempotently configure the shared singletons from the first servlet's parsed configuration. */
    public static void configure(SsfConfiguration config) {
        Objects.requireNonNull(config, "config");
        synchronized (LOCK) {
            if (configuration != null) {
                return;
            }
            configuration = config;
            minter = new SetMinter(config.signingAlgorithm());
            store = selectStore(config);
        }
    }

    private static SsfStore selectStore(SsfConfiguration config) {
        if (config.usesInMemoryStore()) {
            LOGGER.info((Object) "SSF store: in-memory (per-node; NOT cluster-safe, NOT durable across restarts)");
            return new InMemorySsfStore();
        }
        StoreFactory factory = storeFactory;
        if (factory == null) {
            LOGGER.warn((Object) ("SSF dataStoreId '" + config.dataStoreId()
                    + "' configured but no JDBC store factory installed; falling back to in-memory (per-node)"));
            return new InMemorySsfStore();
        }
        LOGGER.info((Object) ("SSF store: JDBC data store '" + config.dataStoreId() + "' (cluster-safe, durable)"));
        return factory.create(config.dataStoreId());
    }

    public static SsfConfiguration configuration() {
        SsfConfiguration local = configuration;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static SsfStore store() {
        SsfStore local = store;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    public static SetMinter minter() {
        SetMinter local = minter;
        if (local == null) {
            throw new IllegalStateException("SSF transmitter is not configured (no servlet init ran)");
        }
        return local;
    }

    /** Test hook: reset all singletons so a fresh {@link #configure} takes effect. */
    static void resetForTests() {
        synchronized (LOCK) {
            configuration = null;
            store = null;
            minter = null;
            storeFactory = null;
        }
    }
}
