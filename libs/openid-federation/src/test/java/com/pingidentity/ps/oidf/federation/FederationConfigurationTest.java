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
    void theAttesterKeysAreOnlyEverPublicKeys() {
        String ecPrivate = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"a\",\"x\":\"x\",\"y\":\"y\",\"d\":\"secret\"}";
        for (String jwks : List.of("{\"keys\":[" + ecPrivate + "]}", "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"a\",\"k\":\"c2VjcmV0\"}]}",
                "not json", "[]", "{\"keys\": {}}", "{\"keys\": [7]}")) {
            Map<String, String> params = minimal();
            params.put("attesterJwks", jwks);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> FederationConfiguration.fromServletConfig(config(params)), jwks);
            assertTrue(e.getCause().getMessage().startsWith("attesterJwks "), e.getCause().getMessage());
            assertFalse(e.getCause().getMessage().contains("secret"), "the message never carries key material");
        }
        String ecPublic = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"a\",\"x\":\"x\",\"y\":\"y\"}]}";
        Map<String, String> params = minimal();
        params.put("attesterJwks", ecPublic);
        assertEquals(ecPublic, FederationConfiguration.fromServletConfig(config(params)).attesterJwks());
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

    @Test
    void whatTheEntityAdvertisesAndResolvesIsConfigurable() {
        FederationConfiguration defaults = FederationConfiguration.fromServletConfig(config(minimal()));
        assertEquals(List.of("automatic", "explicit"), defaults.clientRegistrationTypes());
        assertEquals(FederationConfiguration.ResolveDiscovery.KNOWN, defaults.resolveDiscovery());
        assertNull(defaults.organizationName());

        Map<String, String> params = minimal();
        params.put("clientRegistrationTypes", "explicit");
        params.put("resolveDiscovery", " Any ");
        params.put("organizationName", " Example Pty Ltd ");
        params.put("subordinates", "https://leaf.example/");
        FederationConfiguration c = FederationConfiguration.fromServletConfig(config(params));
        assertEquals(List.of("explicit"), c.clientRegistrationTypes());
        assertEquals(FederationConfiguration.ResolveDiscovery.ANY, c.resolveDiscovery());
        assertEquals("Example Pty Ltd", c.organizationName());
        assertTrue(c.isSubordinate("https://leaf.example"), "trailing slash aside");
        assertFalse(c.isSubordinate("https://other.example"));

        Map<String, String> none = minimal();
        none.put("clientRegistrationTypes", " , ");
        assertEquals(List.of(), FederationConfiguration.fromServletConfig(config(none)).clientRegistrationTypes());

        Map<String, String> blank = minimal();
        blank.put("resolveDiscovery", " ");
        assertEquals(FederationConfiguration.ResolveDiscovery.KNOWN, FederationConfiguration.fromServletConfig(config(blank)).resolveDiscovery());

        Map<String, String> bad = minimal();
        bad.put("resolveDiscovery", "everything");
        assertThrows(IllegalArgumentException.class, () -> FederationConfiguration.fromServletConfig(config(bad)));
    }
}
