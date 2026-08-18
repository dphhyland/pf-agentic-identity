package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * The deployment-wide federation settings. What matters here is that every reader gets the same
 * answer regardless of which component asked first - the defect this class replaced was three public
 * statics written as a constructor side effect, where initialisation order decided the trust anchor.
 */
class FederationRuntimeConfigTest {

    private static FederationRuntimeConfig of(Map<String, String> env, Map<String, String> props) {
        return FederationRuntimeConfig.from(env::get, props::get);
    }

    @Test
    void baseUrlDefaultsToTheHostWhenNotSeparatelyConfigured() {
        FederationRuntimeConfig c = of(Map.of(FederationRuntimeConfig.HOST_ENV, "https://anchor.example"), Map.of());

        assertEquals("https://anchor.example", c.trustControllerHost());
        assertEquals("https://anchor.example", c.trustControllerBaseUrl());
    }

    @Test
    void baseUrlMayCarryAContextPathDistinctFromTheIdentity() {
        FederationRuntimeConfig c = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, "https://pf.example",
                FederationRuntimeConfig.BASE_URL_ENV, "https://pf.example/oidf"), Map.of());

        assertEquals("https://pf.example", c.trustControllerHost());
        assertEquals("https://pf.example/oidf", c.trustControllerBaseUrl(),
                "a PF serving federation under a context path needs these to differ - the old filter "
                        + "collapsed them by passing the bare host as both");
    }

    @Test
    void systemPropertyBeatsEnvironmentVariable() {
        FederationRuntimeConfig c = of(
                Map.of(FederationRuntimeConfig.HOST_ENV, "https://from-env.example"),
                Map.of("oidf.federation.trust.controller.host", "https://from-prop.example"));

        assertEquals("https://from-prop.example", c.trustControllerHost());
    }

    @Test
    void unconfiguredIsReportable() {
        FederationRuntimeConfig c = of(Map.of(), Map.of());

        assertFalse(c.isTrustControllerConfigured(),
                "callers log this once instead of failing every request with an unexplained rejection");
        assertEquals("", c.trustControllerHost());
        assertEquals("", c.trustControllerBaseUrl());
        assertFalse(c.ignoreSslErrors());
    }

    @Test
    void ignoreSslErrorsIsOffUnlessExplicitlyTrue() {
        assertFalse(of(Map.of(), Map.of()).ignoreSslErrors());
        assertFalse(of(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "no"), Map.of()).ignoreSslErrors());
        assertTrue(of(Map.of(FederationRuntimeConfig.IGNORE_SSL_ENV, "true"), Map.of()).ignoreSslErrors());
    }

    @Test
    void valuesAreTrimmedSoAStrayNewlineDoesNotBreakAnchorMatching() {
        FederationRuntimeConfig c = of(Map.of(FederationRuntimeConfig.HOST_ENV, "  https://anchor.example\n"), Map.of());

        assertEquals("https://anchor.example", c.trustControllerHost());
        assertTrue(c.isTrustControllerConfigured());
    }
}
