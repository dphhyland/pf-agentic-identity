/*
 * OpenIdFederationClientResolver reads attester clients out of a federation entity's configuration.
 */
package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.conformance.Requirement;

/**
 * The statement this resolver reads is fetched from {@code <entity>/.well-known/openid-federation} and
 * checked only against itself - no trust chain is walked (docs/client-attestation-architecture.md §6).
 * That makes the checks it does run the whole of its defence, so each is pinned here: the explicit
 * {@code typ}, a {@code jwks} to verify with, a signature under that {@code jwks}, and the issuer.
 */
class OpenIdFederationClientResolverTest {
    private static final String ENTITY = "https://entity.example.com";
    private static final String CLIENT = "demo-attest-railway";
    private static final String SPIFFE_ID = "spiffe://railway.demo/workload/payment-agent";

    private PublicJsonWebKey entityKey;

    @BeforeEach
    void key() throws Exception {
        entityKey = TestJwts.ec("entity-1");
    }

    private JwtClaims entityConfiguration(String iss) throws Exception {
        Map<String, Object> trustBundle = Map.of("keys", List.of(TestJwts.publicParams(TestJwts.ec("td-1"))));
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(iss);
        c.setIssuedAtToNow();
        c.setExpirationTimeMinutesInTheFuture(10.0f);
        c.setClaim("jwks", Map.of("keys", List.of(TestJwts.publicParams(entityKey))));
        c.setClaim("spiffe_client_bindings", List.of(Map.of(
                "spiffe_id", SPIFFE_ID,
                "client_id", CLIENT,
                "issuer", "https://attester.example.com",
                "trust_domain", "railway.demo",
                "bundle", trustBundle,
                "entitlement", List.of(Map.of("type", "sales_agent")))));
        return c;
    }

    private static OpenIdFederationClientResolver resolverServing(String statement) throws Exception {
        String signingJwk = TestJwts.ec("test-attester").toJson(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
        return new OpenIdFederationClientResolver(ENTITY, (url, accept) -> {
            assertEquals(ENTITY + "/.well-known/openid-federation", url);
            return statement;
        }, 300, signingJwk);
    }

    @Test
    void readsTheBindingsOfATypedSelfSignedConfiguration() throws Exception {
        String statement = TestJwts.sign(entityKey, "ES256", "entity-statement+jwt", entityConfiguration(ENTITY));

        List<AttesterClient> clients = resolverServing(statement).attestationClients();

        assertEquals(1, clients.size());
        assertEquals(CLIENT, clients.get(0).clientId());
        assertTrue(clients.get(0).config().bindingFor(SPIFFE_ID).isPresent());
    }

    /**
     * OpenID Federation 1.0 §3: "Entity Statements without a typ header parameter or with a different
     * typ value MUST be rejected." Signed by the entity's own key, so the refusal can only be the type.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void aConfigurationWithNoTypIsRejected() throws Exception {
        String statement = TestJwts.sign(entityKey, "ES256", null, entityConfiguration(ENTITY));

        IssuanceException e = assertThrows(IssuanceException.class, () -> resolverServing(statement).attestationClients());
        assertTrue(e.getMessage().contains("typ"), e.getMessage());
    }

    /** The generic value a JOSE library writes when nobody set one: a JWT, but not an Entity Statement. */
    @Test
    @Requirement("OIDFED §3(2)")
    void aConfigurationWithAnotherTypIsRejected() throws Exception {
        String statement = TestJwts.sign(entityKey, "ES256", "JWT", entityConfiguration(ENTITY));

        IssuanceException e = assertThrows(IssuanceException.class, () -> resolverServing(statement).attestationClients());
        assertTrue(e.getMessage().contains("typ"), e.getMessage());
    }

    @Test
    void aConfigurationWithNoJwksIsRejected() throws Exception {
        JwtClaims claims = entityConfiguration(ENTITY);
        claims.unsetClaim("jwks");
        String statement = TestJwts.sign(entityKey, "ES256", "entity-statement+jwt", claims);

        IssuanceException e = assertThrows(IssuanceException.class, () -> resolverServing(statement).attestationClients());
        assertTrue(e.getMessage().contains("jwks"), e.getMessage());
    }

    @Test
    void aConfigurationSignedByAKeyOutsideItsJwksIsRejected() throws Exception {
        String statement = TestJwts.sign(TestJwts.ec("entity-1"), "ES256", "entity-statement+jwt", entityConfiguration(ENTITY));

        assertThrows(IssuanceException.class, () -> resolverServing(statement).attestationClients());
    }

    @Test
    void aConfigurationIssuedByAnotherEntityIsRejected() throws Exception {
        String statement = TestJwts.sign(entityKey, "ES256", "entity-statement+jwt", entityConfiguration("https://other.example.com"));

        assertThrows(IssuanceException.class, () -> resolverServing(statement).attestationClients());
    }
}
