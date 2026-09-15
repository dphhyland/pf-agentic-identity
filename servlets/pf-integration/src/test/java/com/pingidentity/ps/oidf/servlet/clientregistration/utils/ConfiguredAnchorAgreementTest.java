package com.pingidentity.ps.oidf.servlet.clientregistration.utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;

/**
 * The OGNL helpers accept a trust controller host as an argument, but the anchor's keys are
 * deployment-wide. A host that is not the configured anchor would otherwise be validated against
 * keys that belong to a different entity, so the two have to agree before a validator is built.
 */
class ConfiguredAnchorAgreementTest {
    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String JWKS_PROP = "oidf.federation.trust.anchor.jwks";

    @BeforeEach
    @AfterEach
    void reset() throws Exception {
        System.clearProperty(HOST_PROP);
        System.clearProperty(JWKS_PROP);
        java.lang.reflect.Field instance = FederationRuntimeConfig.class.getDeclaredField("instance");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    private static void configure(String host) throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("anchor-1");
        System.setProperty(HOST_PROP, host);
        System.setProperty(JWKS_PROP, JsonUtil.toJson(Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)))));
    }

    @Test
    void theConfiguredAnchorIsReturnedWhenTheHostIsThatAnchor() throws Exception {
        configure("https://anchor.example");

        assertEquals("https://anchor.example", OIDFederationUtils.requireConfiguredAnchor("https://anchor.example").entityId());
    }

    @Test
    void aDifferentHostIsRefusedRatherThanValidatedAgainstAnotherEntitysKeys() throws Exception {
        configure("https://anchor.example");

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> OIDFederationUtils.requireConfiguredAnchor("https://somewhere-else.example"));
        assertTrue(e.getMessage().contains("https://somewhere-else.example"), e.getMessage());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV), e.getMessage());
    }
}
