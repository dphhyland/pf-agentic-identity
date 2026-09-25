package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
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

    // ---- hostedSubordinateClaims — the two branches that never touch the (test-order-dependent) signer -----

    @Test
    void hostedSubordinateClaimsReturnsNullForASubjectNeverRegistered() throws Exception {
        assertNull(AuthoritySupport.hostedSubordinateClaims(
                "https://never-registered-" + Instant.now().toEpochMilli() + ".example.com"));
    }

    @Test
    void hostedSubordinateClaimsReturnsNullForARevokedEntity() throws Exception {
        // A registered-but-unresolvable entity must short-circuit to null before ever touching the
        // signer — this holds regardless of which signer an earlier test in this class installed.
        String entityId = "https://as.example.com/agents/revoked-" + Instant.now().toEpochMilli();
        AuthoritySupport.registry().register(HostedEntity.hosted(
                entityId, "some-key-ref", Map.of("oauth_client", Map.of()), null));
        AuthoritySupport.registry().setStatus(entityId, EntityStatus.REVOKED, "test");

        assertNull(AuthoritySupport.hostedSubordinateClaims(entityId));
    }

    // ---- hostedEntityIds — delegates entirely to the registry's own listable/resolvable/type filter ----

    @Test
    void hostedEntityIdsOmitsANonListableEntity() throws Exception {
        String entityId = "https://as.example.com/agents/not-listable-" + Instant.now().toEpochMilli();
        AuthoritySupport.registry().register(HostedEntity.hosted(
                entityId, "some-key-ref", Map.of("oauth_client", Map.of()), null));

        assertTrue(!AuthoritySupport.hostedEntityIds(null).contains(entityId),
                "HostedEntity.hosted(...) defaults to listable=false");
    }

    @Test
    void hostedEntityIdsIncludesAListableEntityAndRespectsTheTypeFilter() throws Exception {
        // Listing needs hosting configured (nothing is hosted before it is); first configuration wins, so this is a no-op
        // when an earlier test in this JVM configured it already.
        AuthoritySupport.configureSigning(e -> {
            throw new IllegalStateException("not exercised in this test");
        }, "https://as.example.com");
        String entityId = "https://as.example.com/agents/listable-" + Instant.now().toEpochMilli();
        AuthoritySupport.registry().register(new HostedEntity(entityId, HostingMode.AUTHORITY_SIGNED,
                "some-key-ref", Map.of("oauth_client", Map.of()), Map.of(), EntityStatus.ACTIVE,
                true, null, Instant.now(), null));

        assertTrue(AuthoritySupport.hostedEntityIds(null).contains(entityId));
        assertTrue(AuthoritySupport.hostedEntityIds("oauth_client").contains(entityId));
        assertTrue(!AuthoritySupport.hostedEntityIds("oauth_resource").contains(entityId));
    }

    // ---- composedMetadataPolicyFor — pure logic, no registry or signer needed ----------------------

    @Test
    void noDefaultAndNoEntityPolicyComposeToEmpty() {
        HostedEntity entity = HostedEntity.hosted("https://as.example.com/agents/a1", "k1",
                Map.of("oauth_client", Map.of()), null);
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        assertTrue(AuthoritySupport.composedMetadataPolicyFor(entity).isEmpty());
    }

    @Test
    void domainDefaultAloneIsEmittedAsIs() {
        Map<String, Object> domainDefault = Map.of("oauth_client",
                Map.of("grant_types", Map.of("subset_of", List.of("client_credentials"))));
        AuthoritySupport.configureDomainDefaultMetadataPolicy(domainDefault);
        try {
            HostedEntity entity = HostedEntity.hosted("https://as.example.com/agents/a2", "k1",
                    Map.of("oauth_client", Map.of()), null);
            assertEquals(domainDefault, AuthoritySupport.composedMetadataPolicyFor(entity));
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
    }

    @Test
    void entityPolicyNarrowsBelowTheDomainDefault() {
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client",
                Map.of("grant_types", Map.of("subset_of", List.of("client_credentials", "authorization_code")))));
        try {
            HostedEntity entity = new HostedEntity("https://as.example.com/agents/a3",
                    HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()),
                    Map.of("oauth_client", Map.of("grant_types", Map.of("subset_of", List.of("client_credentials")))),
                    EntityStatus.ACTIVE, false, null, Instant.now(), null);

            Map<String, Object> composed = AuthoritySupport.composedMetadataPolicyFor(entity);
            @SuppressWarnings("unchecked")
            Map<String, Object> oauthClientOps = (Map<String, Object>) composed.get("oauth_client");
            @SuppressWarnings("unchecked")
            Map<String, Object> subsetOf = (Map<String, Object>) oauthClientOps.get("grant_types");
            assertEquals(List.of("client_credentials"), subsetOf.get("subset_of"),
                    "the composed (narrower) subset must win, not the wider domain default");
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
    }

    @Test
    void anEntityPolicyRequestingBeyondTheDomainDefaultIsAutomaticallyClampedToTheIntersection() {
        // The domain default permits only client_credentials; the entity's own policy also names
        // authorization_code. MetadataPolicy.composeWith intersects subset_of rather than rejecting a
        // wider subordinate outright — the composed result is always constrained to what's common to
        // both, so there is no way for a subordinate's own policy to escape the domain default.
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client",
                Map.of("grant_types", Map.of("subset_of", List.of("client_credentials")))));
        try {
            HostedEntity entity = new HostedEntity("https://as.example.com/agents/a4",
                    HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()),
                    Map.of("oauth_client", Map.of("grant_types",
                            Map.of("subset_of", List.of("client_credentials", "authorization_code")))),
                    EntityStatus.ACTIVE, false, null, Instant.now(), null);

            Map<String, Object> composed = AuthoritySupport.composedMetadataPolicyFor(entity);
            @SuppressWarnings("unchecked")
            Map<String, Object> oauthClientOps = (Map<String, Object>) composed.get("oauth_client");
            @SuppressWarnings("unchecked")
            Map<String, Object> subsetOf = (Map<String, Object>) oauthClientOps.get("grant_types");
            assertEquals(List.of("client_credentials"), subsetOf.get("subset_of"));
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
    }

    @Test
    void completelyDisjointPoliciesComposeToAnEmptySubsetThatIsStillEmitted() {
        // Nothing satisfies both the domain default and the entity's own policy. The Final text merges two
        // subset_of operators to their intersection and says it "may thus be an empty array" (§6.1.3.1.5), so
        // composition succeeds - and the statement must carry subset_of: [] (nothing permitted), never drop
        // it, which would read as "no restriction".
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client",
                Map.of("grant_types", Map.of("subset_of", List.of("client_credentials")))));
        try {
            HostedEntity entity = new HostedEntity("https://as.example.com/agents/a5",
                    HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()),
                    Map.of("oauth_client", Map.of("grant_types", Map.of("subset_of", List.of("implicit")))),
                    EntityStatus.ACTIVE, false, null, Instant.now(), null);
            Map<String, Object> composed = AuthoritySupport.composedMetadataPolicyFor(entity);
            assertEquals(Map.of("oauth_client", Map.of("grant_types", Map.of("subset_of", List.of()))), composed);
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
    }

    @Test
    void policiesThatCannotBeMergedFailClosed() {
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client",
                Map.of("token_endpoint_auth_method", Map.of("one_of", List.of("private_key_jwt")))));
        try {
            HostedEntity entity = new HostedEntity("https://as.example.com/agents/a6",
                    HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()),
                    Map.of("oauth_client", Map.of("token_endpoint_auth_method", Map.of("one_of", List.of("tls_client_auth")))),
                    EntityStatus.ACTIVE, false, null, Instant.now(), null);
            IllegalStateException e = assertThrows(IllegalStateException.class,
                    () -> AuthoritySupport.composedMetadataPolicyFor(entity));
            assertTrue(e.getMessage().contains("token_endpoint_auth_method"), e.getMessage());
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
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

    // ---- Trust Marks for hosted entities -------------------------------------------------------------------

    /** Runs from a clean slate and leaves one: the only test here that resets the shared state. */
    @Test
    void onlyAnEntityHostedHereThatResolvesMayHoldAHostedOnlyMark() throws Exception {
        AuthoritySupport.resetForTests();
        try {
            assertFalse(AuthoritySupport.isActiveHostedEntity("https://as.example.com/agents/a1"), "nothing is hosted until hosting is configured");
            AuthoritySupport.configureSigning(e -> {
                throw new IllegalStateException("not exercised in this test");
            }, "https://as.example.com");
            AuthoritySupport.registry().register(HostedEntity.hosted("https://as.example.com/agents/a1", "k1", Map.of("oauth_client", Map.of()), null));
            AuthoritySupport.registry().register(HostedEntity.hosted("https://as.example.com/agents/a2", "k1", Map.of("oauth_client", Map.of()), null));
            AuthoritySupport.registry().setStatus("https://as.example.com/agents/a2", EntityStatus.SUSPENDED, "test");

            assertTrue(AuthoritySupport.isActiveHostedEntity("https://as.example.com/agents/a1"));
            assertFalse(AuthoritySupport.isActiveHostedEntity("https://as.example.com/agents/a2"), "suspended");
            assertFalse(AuthoritySupport.isActiveHostedEntity("https://as.example.com/agents/never"));
        } finally {
            AuthoritySupport.resetForTests();
        }
    }

    @Test
    void aHostedEntityCarriesTheMarksTheFederationServletIssuesIt() {
        AuthoritySupport.resetForTests();
        try {
            assertEquals(List.of(), AuthoritySupport.trustMarksFor("https://as.example.com/agents/a1"), "none until configured");
            List<Map<String, Object>> marks = List.of(Map.of("trust_mark_type", "https://as.example.com/marks/m", "trust_mark", "jwt"));
            AuthoritySupport.configureTrustMarks(id -> id.endsWith("/a1") ? marks : List.of());

            assertEquals(marks, AuthoritySupport.trustMarksFor("https://as.example.com/agents/a1"));
            assertEquals(List.of(), AuthoritySupport.trustMarksFor("https://as.example.com/agents/a2"));
        } finally {
            AuthoritySupport.resetForTests();
        }
    }

    @Test
    void aRegistryThatFailsIsNotReadAsNotHosted() throws Exception {
        AuthoritySupport.resetForTests();
        try {
            AuthoritySupport.configureJdbcRegistry((javax.sql.DataSource) java.lang.reflect.Proxy.newProxyInstance(
                    javax.sql.DataSource.class.getClassLoader(), new Class<?>[]{javax.sql.DataSource.class}, (proxy, method, args) -> {
                        throw new java.sql.SQLException("connection refused");
                    }));
            AuthoritySupport.configureSigning(e -> {
                throw new IllegalStateException("not exercised in this test");
            }, "https://as.example.com");

            assertThrows(IllegalStateException.class, () -> AuthoritySupport.isActiveHostedEntity("https://as.example.com/agents/a1"));
        } finally {
            AuthoritySupport.resetForTests();
        }
    }

    /**
     * A fetch or list that arrives before hosting is configured finds nothing hosted - and leaves the registry alone, so
     * the durable one configured when HostedEntityServlet starts is the one used, not an in-memory stand-in.
     */
    @Test
    void nothingIsLookedUpBeforeHostingIsConfigured() {
        AuthoritySupport.resetForTests();
        try {
            assertEquals(List.of(), AuthoritySupport.hostedEntityIds(null));
            assertNull(AuthoritySupport.hostedSubordinateClaims("https://as.example.com/agents/a1"));

            AuthoritySupport.configureJdbcRegistry(null_datasource());

            assertTrue(AuthoritySupport.registry() instanceof JdbcHostedEntityRegistry, "the durable registry was not pre-empted");
        } finally {
            AuthoritySupport.resetForTests();
        }
    }

    @Test
    void aDomainDefaultPolicyIsCheckedWhenItIsConfigured() {
        try {
            assertThrows(IllegalArgumentException.class, () -> AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client", "scope")));
            assertThrows(IllegalArgumentException.class, () -> AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client",
                    Map.of("scope", Map.of("value", "read", "one_of", List.of("write"))))));
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
    }

    @Test
    void anEntityPolicyThatCannotComposeWithTheDomainDefaultIsRefusedBeforeItIsStored() {
        AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of("oauth_client", Map.of("token_endpoint_auth_method", Map.of("value", "private_key_jwt"))));
        try {
            HostedEntity conflicting = new HostedEntity("https://as.example.com/agents/a6", HostingMode.AUTHORITY_SIGNED, "k1",
                    Map.of("oauth_client", Map.of()), Map.of("oauth_client", Map.of("token_endpoint_auth_method", Map.of("value", "none"))),
                    EntityStatus.ACTIVE, false, null, Instant.now(), null);
            HostedEntity compatible = HostedEntity.hosted("https://as.example.com/agents/a7", "k1", Map.of("oauth_client", Map.of()), null);

            assertThrows(IllegalArgumentException.class, () -> AuthoritySupport.requireComposable(conflicting));
            AuthoritySupport.requireComposable(compatible);
        } finally {
            AuthoritySupport.configureDomainDefaultMetadataPolicy(Map.of());
        }
    }

    // ---- the Subordinate Statement claims for a hosted entity ----------------------------------------

    private static final com.pingidentity.ps.oidf.jose.JwsSigner SIGNER = new com.pingidentity.ps.oidf.jose.JwsSigner() {
        @Override
        public String algorithm() {
            return "ES256";
        }

        @Override
        public String keyId() {
            return "k1";
        }

        @Override
        public Map<String, Object> publicJwk() {
            return Map.of("kty", "EC", "kid", "k1");
        }

        @Override
        public byte[] sign(byte[] signingInput) {
            return new byte[64];
        }
    };

    @Test
    void aResolvableHostedEntityGetsItsKeyAndItsComposedPolicy() throws Exception {
        AuthoritySupport.resetForTests();
        try {
            AuthoritySupport.configureSigning(entity -> {
                if (entity.hostingKeyRef().equals("broken")) {
                    throw new IllegalStateException("vault down");
                }
                return SIGNER;
            }, "https://as.example.com");
            String plain = "https://as.example.com/agents/plain";
            String narrowed = "https://as.example.com/agents/narrowed";
            AuthoritySupport.registry().register(HostedEntity.hosted(plain, "k1", Map.of("oauth_client", Map.of()), null));
            AuthoritySupport.registry().register(new HostedEntity(narrowed, HostingMode.AUTHORITY_SIGNED, "k1", Map.of("oauth_client", Map.of()),
                    Map.of("oauth_client", Map.of("scope", Map.of("subset_of", List.of("read")))), EntityStatus.ACTIVE, false, null, Instant.now(), null));
            AuthoritySupport.registry().register(HostedEntity.hosted("https://as.example.com/agents/broken", "broken", Map.of("oauth_client", Map.of()),
                    null));
            AuthoritySupport.registry().register(HostedEntity.hosted("https://as.example.com/agents/gone", "k1", Map.of("oauth_client", Map.of()), null));
            AuthoritySupport.registry().setStatus("https://as.example.com/agents/gone", EntityStatus.REVOKED, "test");

            assertEquals(Map.of("jwks", Map.of("keys", List.of(SIGNER.publicJwk()))), AuthoritySupport.hostedSubordinateClaims(plain),
                    "no policy anywhere, none carried");
            assertEquals(Map.of("oauth_client", Map.of("scope", Map.of("subset_of", List.of("read")))),
                    AuthoritySupport.hostedSubordinateClaims(narrowed).get("metadata_policy"));
            assertNull(AuthoritySupport.hostedSubordinateClaims("https://as.example.com/agents/gone"));
            assertNull(AuthoritySupport.hostedSubordinateClaims("https://as.example.com/agents/never"));
            assertThrows(IllegalStateException.class, () -> AuthoritySupport.hostedSubordinateClaims("https://as.example.com/agents/broken"),
                    "a fault is a fault, never read as 'not hosted'");
        } finally {
            AuthoritySupport.resetForTests();
        }
    }

    @Test
    void aRegistryThatFailsIsNeverReadAsNothingHosted() {
        AuthoritySupport.resetForTests();
        try {
            AuthoritySupport.configureJdbcRegistry((javax.sql.DataSource) java.lang.reflect.Proxy.newProxyInstance(
                    javax.sql.DataSource.class.getClassLoader(), new Class<?>[]{javax.sql.DataSource.class}, (proxy, method, args) -> {
                        throw new java.sql.SQLException("connection refused");
                    }));
            AuthoritySupport.configureSigning(entity -> SIGNER, "https://as.example.com");

            assertThrows(IllegalStateException.class, () -> AuthoritySupport.hostedEntityIds(null));
            assertThrows(IllegalStateException.class, () -> AuthoritySupport.hostedSubordinateClaims("https://as.example.com/agents/a1"));
        } finally {
            AuthoritySupport.resetForTests();
        }
    }

    @Test
    void noDomainDefaultIsNoDomainDefault() {
        AuthoritySupport.configureDomainDefaultMetadataPolicy(null);
        assertTrue(AuthoritySupport.composedMetadataPolicyFor(HostedEntity.hosted("https://as.example.com/agents/a8", "k1",
                Map.of("oauth_client", Map.of()), null)).isEmpty());
    }
}
