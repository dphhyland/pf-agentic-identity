/*
 * OpenIdFederationClientResolver reads attester clients out of a federation entity's configuration.
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.Federation;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import com.pingidentity.ps.oidf.federation.HttpTrustControllerGateway;
import com.pingidentity.ps.oidf.federation.SubordinateStatementCache;
import com.pingidentity.ps.oidf.federation.TrustChainValidator;
import com.pingidentity.ps.oidf.federation.ValidatorOptions;
import com.pingidentity.ps.oidf.federation.testkit.MutableClock;
import com.pingidentity.ps.oidf.federation.testkit.ServingMap;
import com.pingidentity.ps.oidf.federation.testkit.Statements;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import org.jose4j.jwk.JsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * The attester believes a federation entity's client bindings only because a trust anchor it pinned vouches for the
 * entity (CAS §6.2 rule 2: "the CAS MUST validate the trust chain from the client entity to a configured trust
 * anchor"). So the chain is walked on every resolution the cache lets through, an outage leaves the last answer
 * standing, and an entity the anchor no longer vouches for loses its clients within one cache lifetime.
 */
class OpenIdFederationClientResolverTest {
    private static final String TA = "https://ta.example.com";
    private static final String ENTITY = "https://entity.example.com";
    private static final String CLIENT = "demo-attest-railway";
    private static final String SPIFFE_ID = "spiffe://railway.demo/workload/payment-agent";

    private final MutableClock clock = MutableClock.startingNow();

    private static List<Object> bindings() {
        Map<String, Object> trustBundle = Map.of("keys", List.of(Keys.ec("td-1").toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return List.of(
                Map.of("spiffe_id", SPIFFE_ID, "client_id", CLIENT, "issuer", "https://attester.example.com",
                        "trust_domain", "railway.demo", "bundle", trustBundle, "entitlement", List.of(Map.of("type", "sales_agent"))),
                Map.of("client_id", "no-spiffe-id"),
                Map.of("spiffe_id", "spiffe://x/y"),
                "not an object");
    }

    private Federation federation(Consumer<Statements.Spec> entityConfiguration) {
        return Federation.builder(this.clock).anchor(TA).leaf(ENTITY, TA)
                .entityConfiguration(ENTITY, s -> entityConfiguration.accept(s.claim("spiffe_client_bindings", bindings())))
                .build();
    }

    private OpenIdFederationClientResolver resolver(Federation f) {
        String signingJwk = Keys.ec("test-attester").toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        // The validator and its statement cache on the test's clock, so moving it ages what was cached.
        TrustChainValidator validator = new TrustChainValidator(new HttpTrustControllerGateway(f.http(), TA, TA,
                new SubordinateStatementCache(256, this.clock)), f.trustAnchors(), Set.of(), ValidatorOptions.defaults().withClock(this.clock));
        return new OpenIdFederationClientResolver(ENTITY + "/", validator, 300, signingJwk, this.clock);
    }

    @Test
    @Requirement("CAS §6")
    void readsTheBindingsOfAnEntityWhoseChainValidatesToThePinnedAnchor() throws Exception {
        OpenIdFederationClientResolver resolver = this.resolver(this.federation(s -> { }));

        List<AttesterClient> clients = resolver.attestationClients();

        assertEquals(1, clients.size(), "entries that are not objects, or lack a client_id or a spiffe_id, are skipped");
        assertEquals(CLIENT, clients.get(0).clientId());
        assertTrue(clients.get(0).config().bindingFor(SPIFFE_ID).isPresent());
        assertTrue(resolver.resolve(CLIENT).bindingFor(SPIFFE_ID).isPresent());
        assertEquals("invalid_client", assertThrows(IssuanceException.class, () -> resolver.resolve("unknown")).error());
        assertEquals(ClientResolverPlugins.OPENID_FEDERATION, resolver.pluginId());
    }

    /** A configuration that verifies under its own keys is not enough: the anchor must vouch for those keys. */
    @Test
    @Requirement("CAS §6")
    void anEntityTheAnchorDoesNotVouchForHasNoClients() {
        Federation forged = Federation.builder(this.clock).anchor(TA).leaf(ENTITY, TA)
                .entityConfiguration(ENTITY, s -> s.claim("spiffe_client_bindings", bindings()))
                .subordinate(TA, ENTITY, s -> s.signWith(Keys.ec("impostor-1")))
                .build();

        IssuanceException e = assertThrows(IssuanceException.class, () -> this.resolver(forged).attestationClients());

        assertEquals("invalid_client", e.error());
        assertTrue(e.getMessage().contains("does not validate"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §3(2)")
    void aConfigurationThatIsNotAnEntityStatementIsRefused() {
        IssuanceException e = assertThrows(IssuanceException.class,
                () -> this.resolver(this.federation(s -> s.typ("JWT"))).attestationClients());

        assertEquals("invalid_client", e.error());
    }

    @Test
    void theAnswerIsKeptForItsTtl() throws Exception {
        Federation f = this.federation(s -> { });
        OpenIdFederationClientResolver resolver = this.resolver(f);

        List<AttesterClient> first = resolver.attestationClients();
        long fetched = f.http().requests().size();
        this.clock.advance(Duration.ofSeconds(299));

        assertSame(first, resolver.attestationClients());
        assertEquals(fetched, f.http().requests().size(), "nothing fetched inside the TTL");
    }

    /** An outage is no evidence against anyone: the last answer stands until the federation answers again. */
    @Test
    void whenTheFederationCannotBeReachedTheLastAnswerStands() throws Exception {
        Federation f = this.federation(s -> { });
        OpenIdFederationClientResolver resolver = this.resolver(f);
        List<AttesterClient> first = resolver.attestationClients();

        this.clock.advance(Duration.ofSeconds(301));
        f.http().failing(ENTITY + "/.well-known/openid-federation", new IOException("connection refused"));

        assertSame(first, resolver.attestationClients());
    }

    @Test
    void anEntityNeverReachedIsAServerError() {
        Federation f = this.federation(s -> { });
        f.http().failing(ENTITY + "/.well-known/openid-federation", new IOException("connection refused"));

        assertEquals("server_error", assertThrows(IssuanceException.class, () -> this.resolver(f).attestationClients()).error());
    }

    /** CAS §6.2 rule 2: revoking the entity's membership revokes issuance within one cache lifetime. */
    @Test
    @Requirement("CAS §6")
    void anEntityTheAnchorStopsVouchingForLosesItsClientsWithinOneTtl() throws Exception {
        Federation f = this.federation(s -> { });
        OpenIdFederationClientResolver resolver = this.resolver(f);
        resolver.attestationClients();

        String statementAboutEntity = f.http().requests().stream().map(ServingMap.Request::url).filter(u -> u.contains("sub="))
                .findFirst().orElseThrow();
        f.http().failing(statementAboutEntity, new IllegalArgumentException("GET failed: " + statementAboutEntity + " status=404"));
        this.clock.advance(Duration.ofSeconds(301));

        IssuanceException e = assertThrows(IssuanceException.class, resolver::attestationClients);
        assertEquals("invalid_client", e.error());
        assertThrows(IssuanceException.class, resolver::attestationClients, "nothing kept to fall back on");
    }

    @Test
    void anEntityWithNoBindingsIsAServerError() {
        Federation f = Federation.builder(this.clock).anchor(TA).leaf(ENTITY, TA).build();

        IssuanceException e = assertThrows(IssuanceException.class, () -> this.resolver(f).attestationClients());
        assertEquals("server_error", e.error());
        assertTrue(e.getMessage().contains("spiffe_client_bindings"), e.getMessage());
    }
}
