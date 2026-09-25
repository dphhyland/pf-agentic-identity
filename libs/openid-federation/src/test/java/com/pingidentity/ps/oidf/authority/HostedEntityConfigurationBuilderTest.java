package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

/**
 * End-to-end: a registered {@link HostedEntity} produces an Entity Configuration that genuinely
 * verifies as self-signed — the point of {@link HostingMode#AUTHORITY_SIGNED} being that a resolving
 * party cannot tell, from the bytes alone, that the private key lives with the authority rather than
 * the entity.
 */
class HostedEntityConfigurationBuilderTest {

    private static final String AUTHORITY = "https://as.example.com";
    private static final String TOKEN = "test-token";

    @Test
    @Requirement("OIDFED §3.2")
    void configurationIsGenuinelySelfSigned() throws Exception {
        try (FakeBaoServer bao = new FakeBaoServer(TOKEN)) {
            HostedEntitySigner signer = new RegistryHostedEntitySigner(bao.url(), TOKEN);
            HostedEntityConfigurationBuilder builder = new HostedEntityConfigurationBuilder(signer, AUTHORITY);

            String entityId = AUTHORITY + "/agents/agent-1";
            HostedEntity entity = HostedEntity.hosted(entityId, FakeBaoServer.KEY_NAME,
                    Map.of("oauth_client", Map.of("client_name", "Payment Agent"),
                            "oauth_resource", Map.of("resource", entityId)),
                    "operator:dave");

            String compact = builder.buildEntityConfiguration(entity);

            JwtClaims claims = com.pingidentity.ps.oidf.jose.JwtCodec.parseUnverifiedClaims(compact);
            assertEquals(entityId, claims.getIssuer());
            assertEquals(entityId, claims.getSubject());
            assertTrue(claims.hasClaim("jwks"));
            assertEquals(List.of(AUTHORITY), claims.getStringListClaimValue("authority_hints"));

            // The published jwks is the key that must verify this exact JWT — the actual self-signed check.
            JsonWebSignature jws = new JsonWebSignature();
            jws.setCompactSerialization(compact);
            @SuppressWarnings("unchecked")
            Map<String, Object> jwks = (Map<String, Object>) claims.getClaimValue("jwks");
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
            jws.setKey(((PublicJsonWebKey) JsonWebKey.Factory.newJwk(keys.get(0))).getPublicKey());
            assertTrue(jws.verifySignature());
        }
    }

    @Test
    void selfSignedHostingModeHasNoAuthorityHeldSigner() {
        HostedEntitySigner signer = new RegistryHostedEntitySigner("http://bao", "t");
        // A SELF_SIGNED entity carries its own public federation keys (it signs its own configuration);
        // the authority still holds no private key for it, so its signer must refuse.
        HostedEntity entity = new HostedEntity("https://as.example.com/agents/self-hosted",
                HostingMode.SELF_SIGNED, null, Map.of("oauth_client", Map.of()), Map.of(),
                EntityStatus.ACTIVE, false, null, Instant.now(), null,
                Map.of("keys", List.of(Map.of("kty", "EC", "crv", "P-256", "kid", "agent-1",
                        "x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
                        "y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"))), null);
        assertThrows(IllegalStateException.class, () -> signer.signerFor(entity));
    }

    @Test
    void authoritySignedWithNoVaultConfiguredFailsClearly() {
        HostedEntitySigner signer = new RegistryHostedEntitySigner(null, null);
        HostedEntity entity = HostedEntity.hosted("https://as.example.com/agents/a1", "some-key",
                Map.of("oauth_client", Map.of()), null);
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> signer.signerFor(entity));
        assertTrue(e.getMessage().contains("OpenBao"), e.getMessage());
    }

    @Test
    void signerIsCachedByHostingKeyRef() throws Exception {
        try (FakeBaoServer bao = new FakeBaoServer(TOKEN)) {
            RegistryHostedEntitySigner signer = new RegistryHostedEntitySigner(bao.url(), TOKEN);
            HostedEntity a = HostedEntity.hosted("https://as.example.com/agents/a1", FakeBaoServer.KEY_NAME,
                    Map.of("oauth_client", Map.of()), null);
            HostedEntity b = HostedEntity.hosted("https://as.example.com/agents/a2", FakeBaoServer.KEY_NAME,
                    Map.of("oauth_client", Map.of()), null);
            // Same hostingKeyRef -> same signer instance, not a fresh vault round trip per entity.
            org.junit.jupiter.api.Assertions.assertSame(signer.signerFor(a), signer.signerFor(b));
        }
    }

    // ---------------------------------------------------------------- SELF_SIGNED: stored bytes, never re-signed

    /** The authority must never sign for a self-signed entity: any attempt fails the test. */
    private static final HostedEntitySigner NEVER = entity -> {
        throw new AssertionError("a self-signed entity's configuration is never signed by the authority");
    };

    private static String selfSignedConfiguration(String entityId, long exp) throws Exception {
        org.jose4j.jwk.EllipticCurveJsonWebKey key = org.jose4j.jwk.EcJwkGenerator.generateJwk(org.jose4j.keys.EllipticCurves.P256);
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(entityId);
        claims.setSubject(entityId);
        claims.setIssuedAt(org.jose4j.jwt.NumericDate.fromSeconds(exp - 3600));
        claims.setExpirationTime(org.jose4j.jwt.NumericDate.fromSeconds(exp));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setKey(key.getPrivateKey());
        return jws.getCompactSerialization();
    }

    private static HostedEntity selfSigned(String entityId, String configuration) throws Exception {
        // A self-signed entity always carries its own federation keys; the builder never looks at them.
        Map<String, Object> fedKey = org.jose4j.jwk.EcJwkGenerator.generateJwk(org.jose4j.keys.EllipticCurves.P256)
                .toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
        return new HostedEntity(entityId, HostingMode.SELF_SIGNED, null, Map.of("oauth_client", Map.of()), Map.of(),
                EntityStatus.ACTIVE, false, "operator:dave", Instant.now(), null,
                Map.of("keys", List.of(fedKey)), configuration);
    }

    @Test
    void selfSignedConfigurationIsServedVerbatim() throws Exception {
        String entityId = AUTHORITY + "/federation/agents/a1";
        String published = selfSignedConfiguration(entityId, Instant.now().getEpochSecond() + 3600);
        assertEquals(published, new HostedEntityConfigurationBuilder(NEVER, AUTHORITY).buildEntityConfiguration(selfSigned(entityId, published)));
    }

    @Test
    void selfSignedEntityThatHasNotPublishedIsNotServed() throws Exception {
        String entityId = AUTHORITY + "/federation/agents/a1";
        HostedEntity unpublished = selfSigned(entityId, null);
        HostedEntityConfigurationBuilder.NotPublishedException e = assertThrows(HostedEntityConfigurationBuilder.NotPublishedException.class,
                () -> new HostedEntityConfigurationBuilder(NEVER, AUTHORITY).buildEntityConfiguration(unpublished));
        assertTrue(e.getMessage().contains("has not published"), e.getMessage());
    }

    @Test
    void selfSignedConfigurationPastItsExpiryIsNotServed() throws Exception {
        String entityId = AUTHORITY + "/federation/agents/a1";
        HostedEntity stale = selfSigned(entityId, selfSignedConfiguration(entityId, Instant.now().getEpochSecond() - 1));
        HostedEntityConfigurationBuilder.NotPublishedException e = assertThrows(HostedEntityConfigurationBuilder.NotPublishedException.class,
                () -> new HostedEntityConfigurationBuilder(NEVER, AUTHORITY).buildEntityConfiguration(stale));
        assertTrue(e.getMessage().contains("has expired"), e.getMessage());
    }
}
