package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustAnchor;

/**
 * The deployment's trust anchor: its identity from {@link FederationRuntimeConfig#HOST_ENV}, its keys
 * from {@link FederationRuntimeConfig#TRUST_ANCHOR_JWKS_ENV}. OpenID Federation 1.0 §4 distributes
 * an anchor's keys out of band, so a host without keys is a configuration error that names the
 * variable, never a fallback to reading them from the host.
 */
class FederationRuntimeConfigTrustAnchorTest {

    private static FederationRuntimeConfig of(Map<String, String> env, Map<String, String> props) {
        return FederationRuntimeConfig.from(env::get, props::get);
    }

    private static String jwksJson(PublicJsonWebKey key) {
        return JsonUtil.toJson(Map.of("keys", List.of(TestJwts.publicParams(key))));
    }

    @Test
    @Requirement("OIDFED §4")
    void aHostWithPinnedKeysYieldsThatAnchor() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("anchor-1");
        FederationRuntimeConfig c = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, "https://anchor.example",
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, jwksJson(key)), Map.of());

        TrustAnchor anchor = c.trustAnchor();

        assertEquals("https://anchor.example", anchor.entityId());
        assertEquals("anchor-1", anchor.keys().get(0).getKeyId());
        assertTrue(c.toString().contains("trustAnchorJwks=set"), c.toString());
    }

    @Test
    @Requirement("OIDFED §4")
    void aHostWithoutPinnedKeysIsRefusedAndTheMessageSaysWhatToSet() {
        FederationRuntimeConfig c = of(Map.of(FederationRuntimeConfig.HOST_ENV, "https://anchor.example"), Map.of());

        IllegalStateException e = assertThrows(IllegalStateException.class, c::trustAnchor);

        assertTrue(e.getMessage().contains(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV), e.getMessage());
        assertTrue(e.getMessage().contains("https://anchor.example/.well-known/openid-federation"),
                "the operator needs to know where to capture the keys from: " + e.getMessage());
        assertTrue(c.toString().contains("trustAnchorJwks=unset"), c.toString());
    }

    @Test
    void noTrustControllerAtAllIsRefusedNamingTheHostVariable() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> of(Map.of(), Map.of()).trustAnchor());
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.HOST_ENV), e.getMessage());
    }

    @Test
    void anUnusableKeySetIsRefusedRatherThanIgnored() {
        FederationRuntimeConfig c = of(Map.of(
                FederationRuntimeConfig.HOST_ENV, "https://anchor.example",
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, "{\"keys\":[]}"), Map.of());

        assertThrows(IllegalArgumentException.class, c::trustAnchor);
    }

    @Test
    void theKeysFollowTheSamePropertyBeforeEnvironmentPrecedence() throws Exception {
        PublicJsonWebKey fromEnv = TestJwts.ec("from-env");
        PublicJsonWebKey fromProp = TestJwts.ec("from-prop");
        FederationRuntimeConfig c = of(
                Map.of(FederationRuntimeConfig.HOST_ENV, "https://anchor.example",
                        FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, jwksJson(fromEnv)),
                Map.of("oidf.federation.trust.anchor.jwks", jwksJson(fromProp)));

        assertEquals("from-prop", c.trustAnchor().keys().get(0).getKeyId());
        assertTrue(c.trustAnchorJwks().contains("from-prop"));
    }
}
