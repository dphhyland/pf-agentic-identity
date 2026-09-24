package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Reading the federation entity's settings from servlet init-params: the anchors it names as superiors,
 * its subordinates, its signing algorithm, CORS and the co-hosted attester's keys.
 */
class FederationConfigurationTest {

    private static ServletConfig config(Map<String, String> params) {
        return new ServletConfig() {
            @Override
            public String getServletName() {
                return "federation";
            }

            @Override
            public ServletContext getServletContext() {
                return null;
            }

            @Override
            public String getInitParameter(String name) {
                return params.get(name);
            }

            @Override
            public Enumeration<String> getInitParameterNames() {
                return Collections.enumeration(params.keySet());
            }
        };
    }

    private static Map<String, String> minimal() {
        Map<String, String> params = new HashMap<>();
        params.put("trustAnchorIssuers", " https://ta.example , https://ta2.example ,, ");
        return params;
    }

    @Test
    void readsAnchorsSubordinatesAndDefaults() {
        Map<String, String> params = minimal();
        params.put("subordinates", "https://leaf-a.example,https://leaf-b.example");
        params.put("trustControllerHost", "https://ta.example");
        params.put("ignoreSslErrors", "true");

        FederationConfiguration c = FederationConfiguration.fromServletConfig(config(params));

        assertEquals(List.of("https://ta.example", "https://ta2.example"), c.trustAnchorIssuers());
        assertEquals(c.trustAnchorIssuers(), c.authorityHints());
        assertEquals(List.of("https://leaf-a.example", "https://leaf-b.example"), c.subordinates());
        assertEquals("https://ta.example", c.trustControllerHost());
        assertTrue(c.ignoreSslErrors());
        assertEquals("RS256", c.signingAlgorithm());
        assertTrue(c.corsEnabled());
        assertEquals("*", c.corsAllowOrigin());
        assertEquals("GET, OPTIONS", c.corsAllowMethods());
        assertEquals("Accept, Content-Type", c.corsAllowHeaders());
        assertEquals(3600, c.corsMaxAge());
        assertNull(c.attesterJwks());
        assertEquals("https://ta.example", c.defaultTrustAnchorIssuer());
    }

    @Test
    void theAnchorLookupsAnswerForConfiguredAnchorsOnly() {
        FederationConfiguration c = FederationConfiguration.fromServletConfig(config(minimal()));

        assertTrue(c.isTrustAnchor("https://ta2.example"));
        assertFalse(c.isTrustAnchor("https://elsewhere.example"));
        assertEquals("https://ta2.example", c.findTrustAnchor("https://ta2.example"));
        assertThrows(IllegalArgumentException.class, () -> c.findTrustAnchor("https://elsewhere.example"));
    }

    @Test
    void corsAndAlgorithmAreConfigurable() {
        Map<String, String> params = minimal();
        params.put("signingAlgorithm", " PS256 ");
        params.put("corsEnabled", "false");
        params.put("corsAllowOrigin", "https://ui.example");
        params.put("corsAllowMethods", "GET");
        params.put("corsAllowHeaders", "Accept");
        params.put("corsMaxAge", "60");
        params.put("attesterJwks", "{\"keys\":[]}");

        FederationConfiguration c = FederationConfiguration.fromServletConfig(config(params));

        assertEquals("PS256", c.signingAlgorithm());
        assertFalse(c.corsEnabled());
        assertEquals("https://ui.example", c.corsAllowOrigin());
        assertEquals("GET", c.corsAllowMethods());
        assertEquals("Accept", c.corsAllowHeaders());
        assertEquals(60, c.corsMaxAge());
        assertEquals("{\"keys\":[]}", c.attesterJwks());
    }

    @Test
    void refusesAConfigurationItCannotServe() {
        assertThrows(IllegalArgumentException.class, () -> FederationConfiguration.fromServletConfig(config(Map.of())));
        Map<String, String> badAlg = minimal();
        badAlg.put("signingAlgorithm", "HS256");
        assertThrows(IllegalArgumentException.class, () -> FederationConfiguration.fromServletConfig(config(badAlg)));
        Map<String, String> badAge = minimal();
        badAge.put("corsMaxAge", "an hour");
        assertThrows(IllegalArgumentException.class, () -> FederationConfiguration.fromServletConfig(config(badAge)));
    }
}
