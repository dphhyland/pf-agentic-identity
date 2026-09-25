package com.pingidentity.ps.oidf.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A self-signed hosted entity (the Mac connector's agent): its Federation Entity Key never leaves the
 * device, it signs its own Entity Configuration, and the authority serves exactly what it signed.
 */
class SelfSignedEntityConfigurationsTest {

    private static final String AUTHORITY = "https://bank.example";

    private PublicJsonWebKey agentKey;
    private String entityId;
    private HostedEntity entity;

    @BeforeEach
    void setUp() throws Exception {
        agentKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        agentKey.setKeyId(agentKey.calculateBase64urlEncodedThumbprint("SHA-256"));
        entityId = AUTHORITY + "/federation/agents/" + UUID.randomUUID().toString().replace("-", "");
        entity = selfSigned(entityId, agentKey);
    }

    private static HostedEntity selfSigned(String id, PublicJsonWebKey key) {
        return new HostedEntity(id, HostingMode.SELF_SIGNED, null, Map.of(), Map.of(), EntityStatus.ACTIVE, true,
                "owner:test", Instant.now(), null, Map.of("keys", List.of(pub(key))), null);
    }

    private static Map<String, Object> pub(PublicJsonWebKey key) {
        return new LinkedHashMap<>(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private String configuration(PublicJsonWebKey signer, Map<String, Object> overrides) throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(entityId);
        claims.setSubject(entityId);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 86400));
        claims.setClaim("jwks", Map.of("keys", List.of(pub(agentKey))));
        claims.setClaim("authority_hints", List.of(AUTHORITY));
        claims.setClaim("metadata", Map.of("oauth_client", Map.of("software_id", "claude-bank-connector")));
        overrides.forEach((k, v) -> {
            if (v == null) {
                claims.unsetClaim(k);
            } else {
                claims.setClaim(k, v);
            }
        });
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signer.getPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        return jws.getCompactSerialization();
    }

    private void refused(String jwt, String because) {
        SelfSignedEntityConfigurations.InvalidConfigurationException e = assertThrows(
                SelfSignedEntityConfigurations.InvalidConfigurationException.class,
                () -> SelfSignedEntityConfigurations.validate(jwt, entity, AUTHORITY, Instant.now()));
        assertTrue(e.getMessage().contains(because), "expected '" + because + "' in: " + e.getMessage());
    }

    @Test
    void aConfigurationTheAgentSignedWithItsRegisteredKeyIsAccepted() throws Exception {
        String jwt = configuration(agentKey, Map.of());
        assertEquals(jwt, SelfSignedEntityConfigurations.validate(" " + jwt + "\n", entity, AUTHORITY, Instant.now()));
    }

    @Test
    void theAuthorityCannotBeHandedAConfigurationSignedByAnyOtherKey() throws Exception {
        PublicJsonWebKey stranger = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        stranger.setKeyId(agentKey.getKeyId());   // same kid, different key: the signature must still fail
        refused(configuration(stranger, Map.of()), "signature");
        PublicJsonWebKey other = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        other.setKeyId("other");
        refused(configuration(other, Map.of()), "did not register");
    }

    @Test
    void itMustDescribeThisEntityAndNameTheAuthority() throws Exception {
        refused(configuration(agentKey, Map.of("sub", AUTHORITY + "/federation/agents/someone-else")), "iss and sub");
        refused(configuration(agentKey, Map.of("authority_hints", List.of("https://elsewhere.example"))), "authority_hints");
    }

    @Test
    void itMayPublishOnlyTheKeysTheAuthorityRegistered() throws Exception {
        PublicJsonWebKey extra = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        extra.setKeyId("extra");
        refused(configuration(agentKey, Map.of("jwks", Map.of("keys", List.of(pub(agentKey), pub(extra))))),
                "did not register");
    }

    @Test
    void itMustBeLiveAndShortLived() throws Exception {
        long now = NumericDate.now().getValue();
        refused(configuration(agentKey, Map.of("exp", now - 10)), "expired");
        refused(configuration(agentKey, Map.of("exp", now + SelfSignedEntityConfigurations.MAX_LIFETIME_SECONDS + 3600)),
                "lifetime");
    }

    @Test
    void subordinateAndAnchorClaimsAreRefused() throws Exception {
        refused(configuration(agentKey, Map.of("metadata_policy", Map.of())), "metadata_policy");
        refused(configuration(agentKey, Map.of("trust_mark_issuers", Map.of())), "Trust Anchor");
    }

    @Test
    void anAuthoritySignedEntityCannotPublishThisWay() throws Exception {
        HostedEntity authoritySigned = HostedEntity.hosted(entityId, "bao-key", Map.of(), "owner");
        assertThrows(SelfSignedEntityConfigurations.InvalidConfigurationException.class,
                () -> SelfSignedEntityConfigurations.validate(configuration(agentKey, Map.of()), authoritySigned,
                        AUTHORITY, Instant.now()));
    }

    @Test
    void theBuilderServesThePublishedConfigurationVerbatimAndNothingBeforeIt() throws Exception {
        HostedEntityConfigurationBuilder builder = new HostedEntityConfigurationBuilder(e -> {
            throw new AssertionError("a self-signed entity must never reach the authority's signer");
        }, AUTHORITY);
        assertThrows(HostedEntityConfigurationBuilder.NotPublishedException.class,
                () -> builder.buildEntityConfiguration(entity));
        String jwt = configuration(agentKey, Map.of());
        assertEquals(jwt, builder.buildEntityConfiguration(entity.withEntityConfiguration(jwt)));
    }

    @Test
    void theSubordinateStatementVouchesForTheAgentsOwnKey() throws Exception {
        AuthoritySupport.registry().register(entity);
        Map<String, Object> claims = AuthoritySupport.hostedSubordinateClaims(entityId);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) ((Map<String, Object>) claims.get("jwks")).get("keys");
        assertEquals(agentKey.getKeyId(), keys.get(0).get("kid"));
        AuthoritySupport.registry().setStatus(entityId, EntityStatus.REVOKED, "test");
        assertEquals(null, AuthoritySupport.hostedSubordinateClaims(entityId), "a revoked agent gets no statement");
    }

    @Test
    void aSelfSignedEntityWithoutKeysCannotExist() {
        assertThrows(IllegalArgumentException.class, () -> new HostedEntity(entityId, HostingMode.SELF_SIGNED, null,
                Map.of(), Map.of(), EntityStatus.ACTIVE, false, null, Instant.now(), null, Map.of("keys", List.of()), null));
        assertThrows(IllegalArgumentException.class, () -> new HostedEntity(entityId, HostingMode.AUTHORITY_SIGNED, "k",
                Map.of(), Map.of(), EntityStatus.ACTIVE, false, null, Instant.now(), null, Map.of("keys", List.of(pub(agentKey))), null));
    }
}
