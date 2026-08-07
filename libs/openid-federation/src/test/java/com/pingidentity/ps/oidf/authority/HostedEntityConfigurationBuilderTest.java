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

            JwtClaims claims = com.pingidentity.ps.oidf.common.JwtCodec.parseUnverifiedClaims(compact);
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
        HostedEntity entity = new HostedEntity("https://as.example.com/agents/self-hosted",
                HostingMode.SELF_SIGNED, null, Map.of("oauth_client", Map.of()), Map.of(),
                EntityStatus.ACTIVE, false, null, Instant.now(), null);
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
}
