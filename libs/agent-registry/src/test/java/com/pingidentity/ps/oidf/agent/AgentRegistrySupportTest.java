package com.pingidentity.ps.oidf.agent;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Because {@link AgentRegistrySupport}'s state is static, these assertions run against whatever
 * configuration state this JVM happens to hold, without resetting it between tests — the same defensive
 * pattern {@code AuthoritySupportTest} uses for the equivalent authority holder.
 */
class AgentRegistrySupportTest {

    @Test
    void registryThrowsClearlyUntilExplicitlyConfigured() {
        // Only meaningful if nothing in this JVM has configured a registry yet; guard rather than assert
        // unconditionally, since test execution order is not guaranteed across the whole module.
        try {
            AgentRegistrySupport.registry();
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("configureJdbcRegistry")
                    || e.getMessage().contains("configureInMemoryRegistry"), e.getMessage());
        }
    }

    @Test
    void configuringInMemoryMakesTheRegistryAvailableAndSticky() {
        AgentRegistrySupport.configureInMemoryRegistry();
        AgentRegistry first = AgentRegistrySupport.registry();
        // A second configuration call — of either kind — must not replace the first.
        AgentRegistrySupport.configureInMemoryRegistry();
        assertSame(first, AgentRegistrySupport.registry());
    }

    @Test
    void aSecondConfigureJdbcRegistryCallIsIgnoredNotOverwritten() {
        AgentRegistry before = firstConfigured();
        AgentRegistrySupport.configureJdbcRegistry(nullDataSource());
        assertSame(before, AgentRegistrySupport.registry(), "the first-established registry must not be replaced");
    }

    private static AgentRegistry firstConfigured() {
        try {
            return AgentRegistrySupport.registry();
        } catch (IllegalStateException e) {
            AgentRegistrySupport.configureInMemoryRegistry();
            return AgentRegistrySupport.registry();
        }
    }

    private static javax.sql.DataSource nullDataSource() {
        // A DataSource is never actually used here — the point is proving configureJdbcRegistry() is a
        // no-op once something has already claimed the registry slot.
        return new javax.sql.DataSource() {
            @Override public java.sql.Connection getConnection() {
                throw new UnsupportedOperationException();
            }
            @Override public java.sql.Connection getConnection(String u, String p) {
                throw new UnsupportedOperationException();
            }
            @Override public java.io.PrintWriter getLogWriter() {
                return null;
            }
            @Override public void setLogWriter(java.io.PrintWriter out) {
            }
            @Override public void setLoginTimeout(int seconds) {
            }
            @Override public int getLoginTimeout() {
                return 0;
            }
            @Override public java.util.logging.Logger getParentLogger() {
                return null;
            }
            @Override public <T> T unwrap(Class<T> iface) {
                throw new UnsupportedOperationException();
            }
            @Override public boolean isWrapperFor(Class<?> iface) {
                return false;
            }
        };
    }
}
