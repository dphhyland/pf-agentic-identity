/*
 * The process-wide Trust Mark grant registry.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.pingidentity.ps.oidf.authority.AuthorityRegistryException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the {@link TrustMarkRegistry} every servlet that issues or grants Trust Marks shares, for the same reason
 * {@code AuthoritySupport} holds the hosted-entity registry: servlets initialised separately must see one store.
 * The first configuration wins; with none, the first use falls back to an in-memory registry, loudly.
 */
public final class TrustMarkSupport {
    private static final Log LOGGER = LogFactory.getLog(TrustMarkSupport.class);
    private static final Object LOCK = new Object();
    private static volatile TrustMarkRegistry registry;

    /** Resolves the shared registry on every call, so wiring done before a servlet configures the store still uses it. */
    private static final TrustMarkRegistry SHARED = new TrustMarkRegistry() {
        @Override
        public TrustMarkGrant grant(String type, String subject, Instant notAfter, String actor) throws AuthorityRegistryException {
            return registry().grant(type, subject, notAfter, actor);
        }

        @Override
        public Optional<TrustMarkGrant> find(String type, String subject) throws AuthorityRegistryException {
            return registry().find(type, subject);
        }

        @Override
        public List<TrustMarkGrant> grantsTo(String subject) throws AuthorityRegistryException {
            return registry().grantsTo(subject);
        }

        @Override
        public List<TrustMarkGrant> grantsOf(String type) throws AuthorityRegistryException {
            return registry().grantsOf(type);
        }

        @Override
        public TrustMarkGrant revoke(String type, String subject, String reason, String actor)
                throws AuthorityRegistryException {
            return registry().revoke(type, subject, reason, actor);
        }

        @Override
        public List<TrustMarkAuditEntry> auditTrail(String type, String subject) throws AuthorityRegistryException {
            return registry().auditTrail(type, subject);
        }
    };

    private TrustMarkSupport() {
    }

    /** Keeps grants in {@code dataSource} (the {@code V102__trust_mark.sql} schema). Ignored, with a warning, once configured. */
    public static void configureJdbcRegistry(DataSource dataSource) {
        Objects.requireNonNull(dataSource, "dataSource");
        synchronized (LOCK) {
            if (registry != null) {
                LOGGER.warn("TrustMarkSupport registry already configured; ignoring a second configuration");
                return;
            }
            registry = new JdbcTrustMarkRegistry(dataSource, Clock.systemUTC());
        }
    }

    /** Whether a registry has been configured or fallen back to - after which configuring one is ignored. */
    public static boolean isConfigured() {
        return registry != null;
    }

    /** The shared registry, looked up afresh on every call. */
    public static TrustMarkRegistry shared() {
        return SHARED;
    }

    public static TrustMarkRegistry registry() {
        synchronized (LOCK) {
            if (registry == null) {
                LOGGER.warn("DEV MODE: no durable Trust Mark registry configured - grants are kept in memory and lost on restart");
                registry = new InMemoryTrustMarkRegistry(Clock.systemUTC());
            }
            return registry;
        }
    }

    /** Tests only: forget the registry. */
    public static void resetForTests() {
        synchronized (LOCK) {
            registry = null;
        }
    }
}
