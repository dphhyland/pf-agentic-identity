/*
 * Process-wide singleton shared between every servlet that mints or resolves agent_id.
 */
package com.pingidentity.ps.oidf.agent;

import java.util.Objects;
import javax.sql.DataSource;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Holds the per-process {@link AgentRegistry} so every servlet that touches agent identity shares the
 * same state — the same classloader-split lesson {@code AuthoritySupport} and {@code AttestationSupport}
 * already learned in this codebase: a challenge/registration issued in one classloader must be visible
 * to a check running in another, or the two silently diverge.
 *
 * <p>Unlike {@code AuthoritySupport.registry()}, {@link #registry()} here does <strong>not</strong>
 * lazily default to an in-memory registry. {@link InMemoryAgentRegistry}'s hazard — a restart silently
 * re-mints every {@code agent_id} in the fleet — is exactly the kind of thing a caller must choose
 * explicitly via {@link #configureInMemoryRegistry()}, never fall into by omission.
 */
public final class AgentRegistrySupport {
    private static final Log LOGGER = LogFactory.getLog(AgentRegistrySupport.class);
    private static final Object LOCK = new Object();

    private static volatile AgentRegistry registry;

    private AgentRegistrySupport() {
    }

    /**
     * Configures the shared registry against a durable store. Call once, before {@link #registry()} is
     * first used — subsequent calls (to this or {@link #configureInMemoryRegistry()}) are ignored with a
     * warning: first configuration wins, everything after is a caller bug.
     */
    public static void configureJdbcRegistry(DataSource dataSource) {
        synchronized (LOCK) {
            if (registry != null) {
                LOGGER.warn("AgentRegistrySupport registry already configured; ignoring a second configuration");
                return;
            }
            registry = new JdbcAgentRegistry(Objects.requireNonNull(dataSource, "dataSource"));
        }
    }

    /** Explicit opt-in to the in-memory registry — see its own javadoc for why this is never a default. */
    public static void configureInMemoryRegistry() {
        synchronized (LOCK) {
            if (registry != null) {
                LOGGER.warn("AgentRegistrySupport registry already configured; ignoring a second configuration");
                return;
            }
            registry = new InMemoryAgentRegistry();
        }
    }

    /** Whether something has configured a registry yet — the caller's own signal for "opted in or not". */
    public static boolean isConfigured() {
        return registry != null;
    }

    /**
     * @throws IllegalStateException if nothing has configured a registry yet — deliberately not a silent
     *                                in-memory fallback; see this class's own javadoc
     */
    public static AgentRegistry registry() {
        AgentRegistry local = registry;
        if (local == null) {
            throw new IllegalStateException("AgentRegistrySupport.configureJdbcRegistry(...) or "
                    + "configureInMemoryRegistry() must be called before registry()");
        }
        return local;
    }
}
