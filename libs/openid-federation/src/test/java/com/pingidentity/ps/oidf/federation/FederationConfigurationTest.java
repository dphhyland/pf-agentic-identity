package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.platform.settings.ProfileRefused;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import com.pingidentity.ps.oidf.platform.settings.Sources;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Reading the federation entity's settings through the federation-entity catalogue (plan item ST-5): the anchors it
 * names as superiors, its subordinates, its signing algorithm, CORS and the co-hosted attester's keys, each from its
 * init-param, then its system property or environment variable, strictly.
 */
class FederationConfigurationTest {

    private static final String DEVELOPMENT = "development";

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
        params.put("trustAnchorIssuers", " https://ta.example , https://ta2.example ");
        return params;
    }

    /** The configuration these init-params, this environment and these system properties give. */
    private static FederationConfiguration read(Map<String, String> params, Map<String, String> env, Map<String, String> props) {
        return FederationConfiguration.from(Sources.of(env::get, props::get, params::get));
    }

    private static FederationConfiguration read(Map<String, String> params) {
        return read(params, Map.of(), Map.of());
    }

    /** The refusal a read of these init-params gives, under the development profile, unwrapped. */
    private static SettingRefused refused(Map<String, String> params) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> read(params, Map.of("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT), Map.of()));
        assertEquals("Invalid federation servlet configuration", e.getMessage());
        return assertInstanceOf(SettingRefused.class, e.getCause());
    }

    @Test
    void theAttesterKeysAreOnlyEverPublicKeys() throws Exception {
        String ecPrivate = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"a\",\"x\":\"x\",\"y\":\"y\",\"d\":\"secret\"}";
        for (String jwks : List.of("{\"keys\":[" + ecPrivate + "]}", "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"a\",\"k\":\"c2VjcmV0\"}]}",
                "{\"keys\": {}}", "{\"keys\": [7]}")) {
            Map<String, String> params = minimal();
            params.put("attesterJwks", jwks);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> read(params), jwks);
            assertTrue(e.getCause().getMessage().startsWith("attesterJwks "), e.getCause().getMessage());
            assertFalse(e.getCause().getMessage().contains("secret"), "the message never carries key material");
        }
        for (String notAnObject : List.of("not json", "[]")) {
            Map<String, String> params = minimal();
            params.put("attesterJwks", notAnObject);
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> read(params), notAnObject);
            assertEquals(FederationConfiguration.ATTESTER_JWKS, ((SettingRefused) e.getCause()).setting());
        }
        String ecPublic = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"a\",\"x\":\"x\",\"y\":\"y\"}]}";
        Map<String, String> params = minimal();
        params.put("attesterJwks", ecPublic);
        assertEquals(org.jose4j.json.JsonUtil.parseJson(ecPublic).toString(),
                org.jose4j.json.JsonUtil.parseJson(read(params).attesterJwks()).toString());
    }

    @Test
    void readsAnchorsSubordinatesAndDefaults() {
        Map<String, String> params = minimal();
        params.put("subordinates", "https://leaf-a.example,https://leaf-b.example");

        FederationConfiguration c = read(params);

        assertEquals(List.of("https://ta.example", "https://ta2.example"), c.authorityHints());
        assertEquals(List.of("https://leaf-a.example", "https://leaf-b.example"), c.subordinates());
        assertFalse(c.ignoreSslErrors());
        assertEquals("RS256", c.signingAlgorithm());
        assertTrue(c.corsEnabled());
        assertEquals("*", c.corsAllowOrigin());
        assertEquals("GET, OPTIONS", c.corsAllowMethods());
        assertEquals("Accept, Content-Type", c.corsAllowHeaders());
        assertEquals(3600, c.corsMaxAge());
        assertNull(c.attesterJwks());
        assertEquals(AttestationMetadataConfig.defaults().tokenEndpointAuthMethodsSupported(),
                c.attestationMetadata().tokenEndpointAuthMethodsSupported());
    }

    @Test
    void theEnvironmentSuppliesWhatNoInitParamDoes() {
        FederationConfiguration c = read(Map.of(), Map.of("OIDF_FEDERATION_TRUST_ANCHORS", "https://ta.example",
                "OIDF_FEDERATION_SIGNING_ALG", "ps256"), Map.of());

        assertEquals(List.of("https://ta.example"), c.authorityHints());
        assertEquals("PS256", c.signingAlgorithm(), "a choice is read in any case and returned as the catalogue spells it");
        // Through a servlet's own config, this process's environment and properties set none of these.
        assertEquals(List.of("https://ta.example", "https://ta2.example"), FederationConfiguration.fromServletConfig(config(minimal())).authorityHints());
        assertThrows(IllegalArgumentException.class, () -> FederationConfiguration.fromServletConfig(null), "no init-params: no anchors");
    }

    /**
     * H-FED-8's anchor item (F-0050): an anchor is matched as the same Entity Identifier, whatever its trailing slash
     * and the case of its scheme and host; the path is compared as it is (RFC 3986 §6.2.2.1 folds only those two).
     */
    @Test
    void theAnchorLookupMatchesTheSameEntityIdentifier() {
        Map<String, String> params = new HashMap<>();
        params.put("trustAnchorIssuers", "https://TA.example/, https://ta2.example/fed");
        FederationConfiguration c = read(params);

        assertTrue(c.isTrustAnchor("https://ta.example"));
        assertTrue(c.isTrustAnchor("HTTPS://Ta.Example/"));
        assertTrue(c.isTrustAnchor("https://ta2.example/fed/"));
        assertFalse(c.isTrustAnchor("https://ta2.example/FED"), "the path is case-sensitive");
        assertFalse(c.isTrustAnchor("https://elsewhere.example"));
        assertFalse(c.isTrustAnchor(null));
        assertFalse(c.isTrustAnchor("not a url at all"));
        assertFalse(c.isTrustAnchor("urn:x"));
        assertEquals("https://ta.example:8443/Path", FederationConfiguration.hostInLowerCase(" HTTPS://TA.Example:8443/Path "));
        assertEquals("%zz", FederationConfiguration.hostInLowerCase("%zz"));
    }

    /** A trust anchor that is not an Entity Identifier stops the servlet starting, naming the setting and the entry. */
    @Test
    void anAnchorThatIsNotAnEntityIdentifierIsRefused() {
        for (String anchor : List.of("http://ta.example", "https://ta.example?x=1", "https://ta.example#f", "ta.example",
                "https://user@ta.example")) {
            Map<String, String> params = new HashMap<>();
            params.put("trustAnchorIssuers", "https://ok.example " + anchor);
            SettingRefused refusal = refused(params);
            assertEquals("OIDF_FEDERATION_TRUST_ANCHORS", refusal.setting(), anchor);
            assertTrue(refusal.getMessage().contains(anchor), refusal.getMessage());
        }
        SettingRefused none = refused(Map.of());
        assertEquals("OIDF_FEDERATION_TRUST_ANCHORS", none.setting());
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

        FederationConfiguration c = read(params);

        assertEquals("PS256", c.signingAlgorithm());
        assertFalse(c.corsEnabled());
        assertEquals("https://ui.example", c.corsAllowOrigin());
        assertEquals("GET", c.corsAllowMethods());
        assertEquals("Accept", c.corsAllowHeaders());
        assertEquals(60, c.corsMaxAge());
        assertEquals("{\"keys\":[]}", c.attesterJwks());
    }

    /** Each value the reader before 0.6.0 took leniently or could not refuse is refused, naming its setting. */
    @Test
    void refusesAConfigurationItCannotServe() {
        Map<String, String> bad = new HashMap<>();
        bad.put("signingAlgorithm", "HS256");
        bad.put("corsMaxAge", "an hour");
        bad.put("corsEnabled", "maybe");
        bad.put("attestationChallengeEndpointEnabled", "maybe");
        bad.put("resolveDiscovery", "everything");
        bad.put("clientRegistrationTypes", " , ");
        bad.put("tokenEndpointAuthMethodsSupported", ",");
        for (Map.Entry<String, String> one : bad.entrySet()) {
            Map<String, String> params = minimal();
            params.put(one.getKey(), one.getValue());
            SettingRefused refusal = refused(params);
            assertTrue(refusal.getMessage().contains(one.getKey()) || refusal.setting().startsWith("OIDF_FEDERATION_"),
                    refusal.getMessage());
        }
        Map<String, String> pastAnInt = minimal();
        pastAnInt.put("corsMaxAge", "4294967297");
        assertEquals("corsMaxAge", refused(pastAnInt).setting(), "a number past an int is refused, never wrapped");
    }

    /**
     * Under development a spelling only the reader before 0.6.0 took is read as it read it - {@code yes} was false - with
     * a warning; under production it is refused (Phase 3 plan, decision 11).
     */
    @Test
    void aLegacySpellingIsReadUnderDevelopmentAndRefusedUnderProduction() {
        Map<String, String> params = minimal();
        params.put("corsEnabled", "yes");
        params.put("attestationChallengeEndpointEnabled", "on");
        FederationConfiguration development = read(params, Map.of("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT), Map.of());
        assertFalse(development.corsEnabled());
        assertFalse(development.attestationMetadata().challengeEndpointEnabled());

        IllegalArgumentException production = assertThrows(IllegalArgumentException.class, () -> read(params));
        assertEquals("corsEnabled", ((SettingRefused) production.getCause()).setting());
    }

    /**
     * {@value FederationConfiguration#IGNORE_SSL_ERRORS} is one Setting for every reader (F-0197): the servlet's
     * init-param first, then the system property, the environment variable, and the superseded name, in that order.
     */
    @Test
    void ignoreSslErrorsIsReadInOnePrecedence() {
        Map<String, String> dev = Map.of("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT);
        Map<String, String> params = minimal();
        params.put("ignoreSslErrors", "true");
        assertTrue(read(params, dev, Map.of("oidf.federation.ignore.ssl.errors", "false")).ignoreSslErrors(), "the init-param first");
        Map<String, String> env = new HashMap<>(dev);
        env.put("OIDF_FEDERATION_IGNORE_SSL_ERRORS", "false");
        assertTrue(read(minimal(), env, Map.of("oidf.federation.ignore.ssl.errors", "true")).ignoreSslErrors(), "then the property");
        env.put("OIDF_FEDERATION_IGNORE_SSL_ERRORS", "true");
        assertTrue(read(minimal(), env, Map.of()).ignoreSslErrors(), "then the environment");
        Map<String, String> old = new HashMap<>(dev);
        old.put("OIDF_TRUST_CONTROLLER_IGNORE_SSL", "true");
        assertTrue(read(minimal(), old, Map.of()).ignoreSslErrors(), "then the superseded name");
        assertTrue(FederationConfiguration.ignoreSslErrors(Sources.of(old::get, name -> null, null)));
        assertFalse(FederationConfiguration.ignoreSslErrors(Sources.of(dev::get, name -> null, null)));

        Map<String, String> strict = new HashMap<>(dev);
        strict.put("OIDF_FEDERATION_IGNORE_SSL_ERRORS", "sometimes");
        assertThrows(SettingRefused.class, () -> FederationConfiguration.ignoreSslErrors(Sources.of(strict::get, name -> null, null)));
    }

    /** The switch set by init-param is the production profile's to refuse at read (the start-up sweep sees no init-param). */
    @Test
    void ignoreSslErrorsByInitParamIsRefusedUnderProduction() {
        Map<String, String> params = minimal();
        params.put("ignoreSslErrors", "true");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> read(params));
        assertInstanceOf(ProfileRefused.class, e.getCause());
    }

    /** The init-param trustControllerHost was read and never used; from 0.6.0 it is a removed name, refused when set. */
    @Test
    void theRemovedTrustControllerHostInitParamIsRefused() {
        Map<String, String> params = minimal();
        params.put("trustControllerHost", "https://ta.example");
        SettingRefused refusal = refused(params);
        assertEquals("trustControllerHost", refusal.setting());
        assertTrue(refusal.getMessage().contains("OIDF_FEDERATION_TRUST_CONTROLLER_HOST"), refusal.getMessage());
    }

    @Test
    void whatTheEntityAdvertisesAndResolvesIsConfigurable() {
        FederationConfiguration defaults = read(minimal());
        assertEquals(List.of("automatic", "explicit"), defaults.clientRegistrationTypes());
        assertEquals(FederationConfiguration.ResolveDiscovery.KNOWN, defaults.resolveDiscovery());
        assertNull(defaults.organizationName());

        Map<String, String> params = minimal();
        params.put("clientRegistrationTypes", "explicit");
        params.put("resolveDiscovery", " Any ");
        params.put("organizationName", " Example Pty Ltd ");
        params.put("subordinates", "https://leaf.example/");
        FederationConfiguration c = read(params, Map.of("OIDF_DEPLOYMENT_PROFILE", DEVELOPMENT), Map.of());
        assertEquals(List.of("explicit"), c.clientRegistrationTypes());
        assertEquals(FederationConfiguration.ResolveDiscovery.ANY, c.resolveDiscovery());
        assertEquals("Example Pty Ltd", c.organizationName());
        assertTrue(c.isSubordinate("https://leaf.example"), "trailing slash aside");
        assertFalse(c.isSubordinate("https://other.example"));

        Map<String, String> none = minimal();
        none.put("clientRegistrationTypes", " none ");
        assertEquals(List.of(), read(none).clientRegistrationTypes());
        Map<String, String> noneAndMore = minimal();
        noneAndMore.put("clientRegistrationTypes", "none explicit");
        assertEquals("OIDF_FEDERATION_CLIENT_REGISTRATION_TYPES", refused(noneAndMore).setting());

        Map<String, String> blank = minimal();
        blank.put("resolveDiscovery", " ");
        assertEquals(FederationConfiguration.ResolveDiscovery.KNOWN, read(blank).resolveDiscovery());
    }
}
