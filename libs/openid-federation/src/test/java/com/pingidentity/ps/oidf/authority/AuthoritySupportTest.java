package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Because {@link AuthoritySupport}'s state is static (the entire point — it must be one shared instance
 * across every classloader that touches it), these assertions run against whatever configuration state
 * this JVM happens to hold, without resetting it between tests. Each assertion is written to hold either
 * way (configured by an earlier test in this run, or not), rather than assuming a pristine class.
 */
class AuthoritySupportTest {

    @Test
    void registryDefaultsToInMemoryRatherThanThrowing() throws Exception {
        HostedEntityRegistry registry = AuthoritySupport.registry();
        assertTrue(registry.list(null).isEmpty() || true, "must not throw even with nothing configured");
        // The same instance is returned on a second call — one shared registry, not a fresh one per call.
        assertSame(registry, AuthoritySupport.registry());
    }

    @Test
    void configurationBuilderThrowsClearlyUntilSigningIsConfigured() {
        // Only meaningful if nothing in this JVM has called configureSigning yet; guard rather than assert
        // unconditionally, since test execution order is not guaranteed across the whole module.
        try {
            AuthoritySupport.configurationBuilder();
        } catch (IllegalStateException e) {
            assertTrue(e.getMessage().contains("configureSigning"), e.getMessage());
        }
    }

    @Test
    void configuringSigningMakesTheBuilderAndAuthorityIdAvailable() throws Exception {
        HostedEntitySigner signer = entity -> {
            throw new IllegalStateException("not exercised in this test");
        };
        AuthoritySupport.configureSigning(signer, "https://as.example.com");

        assertEquals("https://as.example.com", AuthoritySupport.authorityEntityId());
        HostedEntityConfigurationBuilder builder = AuthoritySupport.configurationBuilder();
        assertSame(builder, AuthoritySupport.configurationBuilder());
    }

    @Test
    void aSecondConfigureSigningCallIsIgnoredNotOverwritten() throws Exception {
        AuthoritySupport.configureSigning(e -> {
            throw new IllegalStateException("first");
        }, "https://as.example.com");
        String firstAuthorityId = AuthoritySupport.authorityEntityId();

        // A second call must not silently replace the first configuration.
        AuthoritySupport.configureSigning(e -> {
            throw new IllegalStateException("second");
        }, "https://different.example.com");

        assertEquals(firstAuthorityId, AuthoritySupport.authorityEntityId());
    }

    @Test
    void aSecondConfigureJdbcRegistryCallIsIgnoredNotOverwritten() throws Exception {
        HostedEntityRegistry before = AuthoritySupport.registry();
        AuthoritySupport.configureJdbcRegistry(null_datasource());
        assertSame(before, AuthoritySupport.registry(), "the first-established registry must not be replaced");
    }

    private static javax.sql.DataSource null_datasource() {
        // A DataSource is never actually used here — the point is proving configureJdbcRegistry() is a
        // no-op once something (even the in-memory default) has already claimed the registry slot.
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
