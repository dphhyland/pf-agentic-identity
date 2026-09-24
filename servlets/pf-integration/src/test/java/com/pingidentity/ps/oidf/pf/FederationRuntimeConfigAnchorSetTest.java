package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Several Trust Anchors in one setting, the superseded setting names, and the install/reset hook tests
 * use instead of reflection.
 */
class FederationRuntimeConfigAnchorSetTest {
    private static final String TA = "https://ta.example";
    private static final String SUITE = "https://suite.example/test/a/fed/trust-anchor";

    @AfterEach
    void reset() {
        FederationRuntimeConfig.resetForTests();
    }

    private static FederationRuntimeConfig of(Map<String, String> env) {
        return FederationRuntimeConfig.from(env::get, name -> null);
    }

    private static String anchorMap() {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put(SUITE, Keys.publicJwks(Keys.ec("suite-1")));
        map.put(TA, Keys.publicJwks(Keys.ec("ta-1")));
        return JsonUtil.toJson(map);
    }

    @Test
    @Requirement("OIDFED §10.3")
    void aMapOfAnchorsIsTheValidationSetInItsOwnOrder() {
        FederationRuntimeConfig config = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, anchorMap()));

        TrustAnchorSet anchors = config.trustAnchors();

        assertEquals(List.of(SUITE, TA), anchors.entityIds());
        assertEquals(TA, config.trustAnchor().entityId());
        assertEquals("ta-1", config.trustAnchor().keys().get(0).getKeyId());
    }

    @Test
    void theControllerHostMustBeInTheMapWhenTheSingleAnchorIsAskedFor() {
        FederationRuntimeConfig config = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, "https://elsewhere.example",
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, anchorMap()));

        IllegalStateException e = assertThrows(IllegalStateException.class, config::trustAnchor);
        assertTrue(e.getMessage().contains("https://elsewhere.example"), e.getMessage());
        assertEquals(2, config.trustAnchors().size(), "the set itself does not depend on the host");
    }

    @Test
    void aSingleJwkSetIsAOneAnchorSet() {
        FederationRuntimeConfig config = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(Keys.publicJwks(Keys.ec("only-1")))));

        assertEquals(List.of(TA), config.trustAnchors().entityIds());
        assertThrows(IllegalStateException.class, () -> of(Map.of(FederationRuntimeConfig.HOST_ENV, TA)).trustAnchors());
        assertThrows(IllegalStateException.class, () -> of(Map.of()).trustAnchors());
    }

    // ---- superseded names --------------------------------------------------------------------------

    @Test
    void aSupersededNameIsStillReadAndLeavesAWarning() {
        Map<String, String> env = new HashMap<>();
        env.put(FederationRuntimeConfig.DEPRECATED_HOST_ENV, TA);
        env.put(FederationRuntimeConfig.DEPRECATED_TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(Keys.publicJwks(Keys.ec("k"))));
        env.put(FederationRuntimeConfig.DEPRECATED_IGNORE_SSL_ENV, "true");

        FederationRuntimeConfig config = of(env);

        assertEquals(TA, config.trustControllerHost());
        assertTrue(config.ignoreSslErrors());
        assertEquals(TA, config.trustAnchor().entityId());
        assertEquals(3, config.deprecationWarnings().size());
        assertTrue(config.deprecationWarnings().get(0).contains(FederationRuntimeConfig.HOST_ENV));
    }

    @Test
    void anOldAndNewNameSetAlikeIsRedundantNotAnError() {
        FederationRuntimeConfig config = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.DEPRECATED_HOST_ENV, TA));

        assertEquals(TA, config.trustControllerHost());
        assertTrue(config.deprecationWarnings().get(0).contains("redundant"));
    }

    @Test
    void anOldAndNewNameSetDifferentlyRefusesToStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> of(Map.of(
                FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.DEPRECATED_HOST_ENV, "https://other.example")));

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.DEPRECATED_HOST_ENV), e.getMessage());
        assertTrue(of(Map.of(FederationRuntimeConfig.HOST_ENV, TA)).deprecationWarnings().isEmpty());
    }

    // ---- install / reset ---------------------------------------------------------------------------

    @Test
    void anInstalledConfigurationIsWhatEveryReaderGets() {
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.HOST_ENV, TA));
        FederationRuntimeConfig.install(config);
        assertSame(config, FederationRuntimeConfig.get());
        FederationRuntimeConfig.resetForTests();
        assertFalse(FederationRuntimeConfig.get() == config);
        assertThrows(NullPointerException.class, () -> FederationRuntimeConfig.install(null));
    }
}
