package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.clientattestation.AttestationRarModels;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.platform.profile.DeploymentProfile;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * The issued-attestation TTL cap (plan item S4c: "Issuer TTL cap: 3600 s in production, 64800 s hard maximum").
 * The AI Agent Profile §5, item 1: "An issued Client Attestation's {@code exp} SHALL NOT exceed {@code iat} + 18
 * hours."
 */
class IssuedTtlCapTest {
    private static final Function<String, String> NONE = name -> null;
    private static final Function<String, String> DEVELOPMENT =
            name -> DeploymentProfile.SETTING.equals(name) ? "development" : null;

    private static Function<String, String> env(String cap, boolean development) {
        return name -> {
            if (IssuedTtlCap.ENV.equals(name)) {
                return cap;
            }
            return development && DeploymentProfile.SETTING.equals(name) ? "development" : null;
        };
    }

    @Test
    void theDefaultIsAnHourAndAnUnsetProfileIsProduction() {
        IssuedTtlCap cap = IssuedTtlCap.fromEnvironment(NONE, NONE);
        assertEquals(3600L, cap.capSeconds());
        assertTrue(cap.production());
        assertFalse(IssuedTtlCap.fromEnvironment(NONE, DEVELOPMENT).production());
    }

    @Test
    void theCapIsReadFromThePropertyBeforeTheEnvironment() {
        assertEquals(7200L, IssuedTtlCap.fromEnvironment(NONE, env(" 7200 ", false)).capSeconds());
        assertEquals(600L, IssuedTtlCap.fromEnvironment(n -> IssuedTtlCap.PROPERTY.equals(n) ? "600" : null,
                env("7200", false)).capSeconds());
        assertEquals(3600L, IssuedTtlCap.fromEnvironment(NONE, env("  ", false)).capSeconds());
    }

    @Test
    void aCapOutsideItsRangeIsRefusedInEitherProfile() {
        for (String bad : List.of("abc", "59", "64801", "-1", "1.5")) {
            for (boolean development : List.of(false, true)) {
                IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                        () -> IssuedTtlCap.fromEnvironment(NONE, env(bad, development)), bad);
                assertTrue(e.getMessage().startsWith(IssuedTtlCap.ENV), e.getMessage());
            }
        }
        assertEquals(60L, IssuedTtlCap.fromEnvironment(NONE, env("60", false)).capSeconds());
        assertEquals(64800L, IssuedTtlCap.fromEnvironment(NONE, env("64800", false)).capSeconds());
    }

    @Test
    void productionRefusesATtlAboveTheCapNamingThePropertyNotTheValue() throws Exception {
        IssuedTtlCap cap = new IssuedTtlCap(3600L, true);
        assertEquals(3600L, cap.apply("https://a.example", 3600L));
        assertEquals(300L, cap.apply("https://a.example", 300L));
        IssuanceException e = assertThrows(IssuanceException.class, () -> cap.apply("https://a.example", 3601L));
        assertEquals("invalid_client", e.error());
        assertTrue(e.getMessage().contains(AttestationIssuanceConfig.P_TTL), e.getMessage());
        assertFalse(e.getMessage().contains("3601"), e.getMessage());
        assertFalse(e.getMessage().contains("3600"), "nor the cap's: " + e.getMessage());
    }

    @Test
    void developmentClampsATtlAboveTheCapToTheCap() throws Exception {
        IssuedTtlCap cap = new IssuedTtlCap(3600L, false);
        assertEquals(3600L, cap.apply("https://dev.example", 7200L));
        assertEquals(3600L, cap.apply("https://dev.example", 7200L), "warned once, clamped every time");
        assertEquals(3600L, cap.apply("https://dev.example", 64800L));
        // The warnings remembered are bounded: a fleet of misconfigured clients cannot grow the set without limit.
        for (int i = 0; i < 300; i++) {
            assertEquals(3600L, cap.apply("https://dev-" + i + ".example", 7200L));
        }
    }

    @Test
    @Requirement("PROFILE §5(1)")
    void aTtlAboveEighteenHoursIsRefusedInBothProfiles() {
        for (boolean production : List.of(true, false)) {
            IssuedTtlCap cap = new IssuedTtlCap(IssuedTtlCap.HARD_MAX_SECONDS, production);
            IssuanceException e = assertThrows(IssuanceException.class, () -> cap.apply("https://a.example", 64801L));
            assertEquals("invalid_client", e.error());
            assertTrue(e.getMessage().startsWith(AttestationIssuanceConfig.P_TTL), e.getMessage());
            assertFalse(e.getMessage().contains("64801"), e.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () -> new IssuedTtlCap(64801L, false));
        assertThrows(IllegalArgumentException.class, () -> new IssuedTtlCap(59L, true));
    }

    @Test
    @Requirement("PROFILE §5(1)")
    void theConfigParseAppliesTheCap() throws Exception {
        Map<String, String> props = baseProps();
        props.put(AttestationIssuanceConfig.P_TTL, "7200");
        IssuanceException refused = assertThrows(IssuanceException.class, () -> AttestationIssuanceConfig
                .fromProperties(props, AttestationRarModels.get(), new IssuedTtlCap(3600L, true)));
        assertEquals("invalid_client", refused.error());
        assertEquals(3600L, AttestationIssuanceConfig
                .fromProperties(props, AttestationRarModels.get(), new IssuedTtlCap(3600L, false)).ttlSeconds());
        props.put(AttestationIssuanceConfig.P_TTL, "64801");
        assertThrows(IssuanceException.class, () -> AttestationIssuanceConfig
                .fromProperties(props, AttestationRarModels.get(), new IssuedTtlCap(64800L, false)));
        props.put(AttestationIssuanceConfig.P_TTL, "not-a-number");
        IssuanceException text = assertThrows(IssuanceException.class, () -> AttestationIssuanceConfig
                .fromProperties(props, AttestationRarModels.get(), new IssuedTtlCap(3600L, true)));
        assertFalse(text.getMessage().contains("not-a-number"), text.getMessage());
    }

    @Test
    void aCapThatCannotBeReadIsAServerErrorAtParse() throws Exception {
        String before = System.getProperty(IssuedTtlCap.PROPERTY);
        System.setProperty(IssuedTtlCap.PROPERTY, "forever");
        try {
            IssuanceException e = assertThrows(IssuanceException.class,
                    () -> AttestationIssuanceConfig.fromProperties(baseProps()));
            assertEquals("server_error", e.error());
            assertTrue(e.getMessage().contains(IssuedTtlCap.ENV), e.getMessage());
        } finally {
            if (before == null) {
                System.clearProperty(IssuedTtlCap.PROPERTY);
            } else {
                System.setProperty(IssuedTtlCap.PROPERTY, before);
            }
        }
    }

    @Test
    void theCataloguesCarryTheCapsRange() throws Exception {
        Map<String, Object> cap = entry("attestation-issuer.json", IssuedTtlCap.ENV);
        assertEquals(IssuedTtlCap.MIN_SECONDS, ((Number) cap.get("min")).longValue());
        assertEquals(IssuedTtlCap.HARD_MAX_SECONDS, ((Number) cap.get("max")).longValue());
        assertEquals(IssuedTtlCap.DEFAULT_SECONDS, ((Number) cap.get("default")).longValue());
        Map<String, Object> ttl = entry("issuance-client-properties.json", AttestationIssuanceConfig.P_TTL);
        assertEquals(IssuedTtlCap.HARD_MAX_SECONDS, ((Number) ttl.get("max")).longValue());
        assertEquals(AttestationIssuanceConfig.DEFAULT_TTL_SECONDS, ((Number) ttl.get("default")).longValue());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> entry(String catalogue, String name) throws Exception {
        try (InputStream in = IssuedTtlCapTest.class.getResourceAsStream("/META-INF/oidf-settings/" + catalogue)) {
            Map<String, Object> doc = JsonUtil.parseJson(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            for (Object o : (List<Object>) doc.get("settings")) {
                Map<String, Object> e = (Map<String, Object>) o;
                if (name.equals(e.get("name"))) {
                    return e;
                }
            }
        }
        throw new AssertionError(name + " is not in " + catalogue);
    }

    private static Map<String, String> baseProps() throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, "https://attester.example.com");
        props.put(AttestationIssuanceConfig.P_BUNDLE,
                new JsonWebKeySet(EcJwkGenerator.generateJwk(EllipticCurves.P256)).toJson());
        props.put(AttestationIssuanceConfig.P_INSTANCES, "[{\"spiffe_id\":\"spiffe://banking.demo/agent\"}]");
        return props;
    }
}
