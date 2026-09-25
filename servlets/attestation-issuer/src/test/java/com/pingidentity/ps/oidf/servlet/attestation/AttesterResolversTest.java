package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.issuer.ClientResolverPlugins;
import com.pingidentity.ps.oidf.issuer.IssuanceClientResolver;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Where the attester reads its SPIFFE-ID → client mapping (CAS §6.2 rule 1: "federation, then CIMD, then local
 * registration"), and that a federation entity is only ever trusted through the deployment's pinned anchors.
 */
class AttesterResolversTest {

    private static String anchorJwks() throws Exception {
        PublicJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        return new JsonWebKeySet(anchor).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    @BeforeEach
    @AfterEach
    void clear() {
        System.clearProperty(AttesterResolvers.FEDERATION_ENTITY_PROPERTY);
        System.clearProperty(AttesterResolvers.CIMD_URL_PROPERTY);
        System.clearProperty("oidf.federation.trust.controller.host");
        System.clearProperty("oidf.federation.trust.anchor.jwks");
        FederationRuntimeConfig.resetForTests();
    }

    @Test
    void withNothingConfiguredItIsThePingFederateStore() {
        IssuanceClientResolver resolver = AttesterResolvers.fromEnvironment();

        assertEquals(List.of(ClientResolverPlugins.PF_CLIENT_METADATA), AttesterResolvers.activePluginIds(resolver));
    }

    @Test
    @Requirement("CAS §6")
    void aFederationEntityComesFirstThenCimdThenThePingFederateStore() throws Exception {
        System.setProperty("oidf.federation.trust.controller.host", "https://ta.example.com");
        System.setProperty("oidf.federation.trust.anchor.jwks", anchorJwks());
        System.setProperty(AttesterResolvers.FEDERATION_ENTITY_PROPERTY, "https://entity.example.com");
        System.setProperty(AttesterResolvers.CIMD_URL_PROPERTY, "https://cimd.example.com/clients.json");

        IssuanceClientResolver resolver = AttesterResolvers.fromEnvironment();

        assertEquals(List.of(ClientResolverPlugins.OPENID_FEDERATION, ClientResolverPlugins.CIMD, ClientResolverPlugins.PF_CLIENT_METADATA),
                AttesterResolvers.activePluginIds(resolver));
    }

    /** CAS §6.2 rule 2: a federation entity's clients are trusted only through a chain to a pinned anchor. */
    @Test
    @Requirement("CAS §6")
    void aFederationEntityWithNoPinnedAnchorStopsTheAttesterStarting() {
        System.setProperty(AttesterResolvers.FEDERATION_ENTITY_PROPERTY, "https://entity.example.com");

        IllegalStateException e = assertThrows(IllegalStateException.class, AttesterResolvers::fromEnvironment);
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.HOST_ENV) || e.getMessage().contains(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV),
                e.getMessage());
    }

    @Test
    void anchorsGivenAsAMapNeedNoTrustControllerHost() throws Exception {
        String anchors = "{\"https://ta.example.com\":" + anchorJwks() + "}";
        FederationRuntimeConfig runtime = FederationRuntimeConfig.from(Map.of(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, anchors)::get,
                name -> null);

        assertNotNull(AttesterResolvers.federationValidator(runtime, "https://entity.example.com"));
        assertNotNull(AttesterResolvers.federationValidator(runtime, null));
    }
}
