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
 * The OGNL helpers accept a trust controller host as an argument, but the anchors' keys are
 * deployment-wide. A host that is none of the configured anchors would otherwise be validated against
 * keys that belong to a different entity, so it has to be one of them before a validator is built - and
 * the validator then trusts the whole pinned set, which is the deployment's trust policy.
 */
class ConfiguredAnchorAgreementTest {
    private static final String HOST_PROP = "oidf.federation.trust.controller.host";
    private static final String JWKS_PROP = "oidf.federation.trust.anchor.jwks";

    @BeforeEach
    @AfterEach
    void reset() throws Exception {
        System.clearProperty(HOST_PROP);
        System.clearProperty(JWKS_PROP);
        FederationRuntimeConfig.resetForTests();
    }

    private static Map<String, Object> jwks() throws Exception {
        PublicJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId("anchor-1");
        return Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
    }

    private static void configure(String host) throws Exception {
        System.setProperty(HOST_PROP, host);
        System.setProperty(JWKS_PROP, JsonUtil.toJson(jwks()));
    }

    @Test
    void theConfiguredAnchorIsReturnedWhenTheHostIsThatAnchor() throws Exception {
        configure("https://anchor.example");

        assertEquals(List.of("https://anchor.example"), OIDFederationUtils.requireConfiguredAnchors("https://anchor.example").entityIds());
    }

    @Test
    void aDifferentHostIsRefusedRatherThanValidatedAgainstAnotherEntitysKeys() throws Exception {
        configure("https://anchor.example");

        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> OIDFederationUtils.requireConfiguredAnchors("https://somewhere-else.example"));
        assertTrue(e.getMessage().contains("https://somewhere-else.example"), e.getMessage());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV), e.getMessage());
    }

    @Test
    void withAnAnchorMapTheHostMustBeOneOfThemAndTheValidatorTrustsThemAll() throws Exception {
        System.setProperty(HOST_PROP, "https://anchor.example");
        // Member order is preference order, so the document is built in order (Map.of has none).
        Map<String, Object> anchors = new java.util.LinkedHashMap<>();
        anchors.put("https://anchor.example", jwks());
        anchors.put("https://second.example", jwks());
        System.setProperty(JWKS_PROP, JsonUtil.toJson(anchors));

        assertEquals(List.of("https://anchor.example", "https://second.example"),
                OIDFederationUtils.requireConfiguredAnchors("https://anchor.example").entityIds());
        assertEquals(List.of("https://anchor.example", "https://second.example"),
                OIDFederationUtils.requireConfiguredAnchors("https://second.example/").entityIds(), "trailing slash aside");
        assertThrows(IllegalStateException.class, () -> OIDFederationUtils.requireConfiguredAnchors("https://third.example"));
    }
}
