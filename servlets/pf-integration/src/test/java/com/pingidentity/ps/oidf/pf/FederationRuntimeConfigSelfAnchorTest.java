package com.pingidentity.ps.oidf.pf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.TrustAnchor;
import com.pingidentity.ps.oidf.federation.TrustAnchorSet;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * A deployment that is its own Trust Anchor ({@code OIDF_FEDERATION_SELF_ANCHOR}): chains ending at it are checked with
 * the keys it signs with, read when they are needed - nothing pinned, nothing to change when its key rotates.
 */
class FederationRuntimeConfigSelfAnchorTest {
    private static final String PF = "https://pf.example.com";
    private static final String TA = "https://ta.example.com";

    @AfterEach
    void reset() {
        FederationRuntimeConfig.resetForTests();
    }

    private static FederationRuntimeConfig of(Map<String, String> env) {
        return FederationRuntimeConfig.from(env::get, name -> null);
    }

    @Test
    @Requirement({"OIDFED §4(9)", "OIDFED §10(1)"})
    void aDeploymentThatIsItsOwnAnchorTrustsTheKeysItSignsWithAsTheyAreNow() {
        AtomicReference<PublicJsonWebKey> signing = new AtomicReference<>(Keys.rsa("pf-1"));
        FederationRuntimeConfig.useOwnKeys(() -> Keys.publicJwks(signing.get()));
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, PF));

        TrustAnchor self = config.trustAnchors().find(PF).orElseThrow();

        assertTrue(self.isLive());
        assertEquals("pf-1", self.keys().get(0).getKeyId());
        signing.set(Keys.rsa("pf-2"));
        assertEquals("pf-2", self.keys().get(0).getKeyId(), "a rotation is picked up without touching the configuration");
        assertTrue(config.hasTrustAnchors(), "no pinned keys, and yet anchored");
        assertEquals(PF, config.selfAnchor());
    }

    @Test
    void itJoinsThePinnedAnchorsAfterThem() {
        FederationRuntimeConfig.useOwnKeys(() -> Keys.publicJwks(Keys.rsa("pf-1")));
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, PF,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(Map.of(TA, Keys.publicJwks(Keys.ec("ta-1")))),
                FederationRuntimeConfig.HOST_ENV, TA));

        TrustAnchorSet anchors = config.trustAnchors();

        assertEquals(List.of(TA, PF), anchors.entityIds());
        assertFalse(anchors.find(TA).orElseThrow().isLive());
    }

    @Test
    void aSingleJwkSetForTheControllerSitsBesideIt() {
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, PF, FederationRuntimeConfig.HOST_ENV, TA,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(Keys.publicJwks(Keys.ec("ta-1")))));

        assertEquals(List.of(TA, PF), config.trustAnchors().entityIds());
    }

    @Test
    void pinningItsOwnKeysBesideIsRefused() {
        FederationRuntimeConfig config = of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, PF,
                FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(Map.of(PF, Keys.publicJwks(Keys.rsa("pf-1"))))));

        String refused = assertThrows(IllegalStateException.class, config::trustAnchors).getMessage();

        assertTrue(refused.contains("go stale"), refused);
    }

    @Test
    @Requirement("OIDFED §1.2(3.4)")
    void theEntityIdentifierIsAnHttpsUrl() {
        assertThrows(IllegalStateException.class, () -> of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, "http://pf.example.com")));
        assertThrows(IllegalStateException.class, () -> of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, "https:///no-host")));
        assertNull(of(Map.of(FederationRuntimeConfig.SELF_ANCHOR_ENV, " ")).selfAnchor(), "blank is unset");
        assertFalse(of(Map.of()).hasTrustAnchors());
        assertTrue(of(Map.of(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV, JsonUtil.toJson(Keys.publicJwks(Keys.ec("ta-1")))))
                .hasTrustAnchors());
    }
}
