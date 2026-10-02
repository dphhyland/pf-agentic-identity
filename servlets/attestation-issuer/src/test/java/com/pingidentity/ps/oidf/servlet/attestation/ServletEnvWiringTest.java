package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.WalletInstanceAttestationValidator;
import com.pingidentity.ps.oidf.platform.settings.SettingRefused;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfig;
import com.pingidentity.ps.oidf.pf.FederationRuntimeConfigTestAccess;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.conformance.Requirement;

/**
 * Ported from pf-oidf-modules (2026-08-15) when that repo was reduced to the demo — trimmed to the
 * env-wiring helpers that still exist on {@link AttestationIssuanceServlet}: {@code processSettings()} (the catalogue
 * reads that replaced {@code env()} in 0.6.0),
 * {@code walletValidatorFromEnv()}, {@code federationWalletValidatorFromEnv()}, and
 * {@code staticWalletValidatorFromEnv()}. Dropped: cases for {@code cimdResolverFromEnv()},
 * {@code parseStringMap()}, {@code parseObjectMap()} — those don't exist here; the CIMD resolver is now
 * wired from {@code AttestationIssuanceConfig} properties (see {@code CimdClientResolver},
 * {@code CimdMapping}), not a servlet-level env helper. None of these methods had a test in this repo.
 */
class ServletEnvWiringTest {

    private static final String[] PROPS = {
            "oidf.trust.controller.host", "oidf.attester.op.issuer", "oidf.wallet.provider.jwks",
            "oidf.trust.controller.ignore.ssl", "oidf.trust.anchor.jwks"};

    /** A public JWK Set for a freshly generated anchor key - what the operator would capture from the anchor. */
    private static String anchorJwks() throws Exception {
        PublicJsonWebKey anchor = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        anchor.setKeyId("anchor-1");
        return new JsonWebKeySet(anchor).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    @BeforeEach
    @AfterEach
    void clearProps() {
        for (String p : PROPS) {
            System.clearProperty(p);
        }
        FederationRuntimeConfigTestAccess.reset();
    }

    @Test
    void theAttesterSettingsReadTheSystemPropertyThenNothing() {
        assertNull(AttestationIssuanceServlet.processSettings().string("OIDF_ATTESTER_OP_ISSUER"));
        System.setProperty("oidf.attester.op.issuer", " value ");
        assertEquals("value", AttestationIssuanceServlet.processSettings().string("OIDF_ATTESTER_OP_ISSUER"));
    }

    @Test
    void walletValidatorNullUntilFederationOrStaticConfigured() throws Exception {
        assertNull(AttestationIssuanceServlet.walletValidatorFromEnv());

        // static provider→JWKS map enables the wallet validator
        PublicJsonWebKey wp = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        System.setProperty("oidf.wallet.provider.jwks",
                "{\"https://wallet.example.com\":"
                        + new JsonWebKeySet(wp).toJson(JsonWebKey.OutputControlLevel.PUBLIC_ONLY) + "}");
        InstanceAttestationValidator v = AttestationIssuanceServlet.walletValidatorFromEnv();
        assertTrue(v instanceof WalletInstanceAttestationValidator);
        assertEquals("wallet", v.format());
    }

    @Test
    void federationWalletValidatorNeedsBothHostAndOpIssuer() throws Exception {
        System.setProperty("oidf.trust.controller.host", "https://trust-controller.example.com");
        assertNull(AttestationIssuanceServlet.federationWalletValidatorFromEnv());   // op issuer missing
        System.setProperty("oidf.attester.op.issuer", "https://attester.example.com");
        System.setProperty("oidf.trust.anchor.jwks", anchorJwks());
        FederationRuntimeConfigTestAccess.reset();
        InstanceAttestationValidator v = AttestationIssuanceServlet.federationWalletValidatorFromEnv();
        assertTrue(v instanceof WalletInstanceAttestationValidator);
        assertEquals("wallet", v.format());
    }

    @Test
    @Requirement("OIDFED §4")
    void aTrustControllerWithoutPinnedAnchorKeysRefusesWalletTrustRatherThanFetchingOrFallingBack() {
        System.setProperty("oidf.trust.controller.host", "https://trust-controller.example.com");
        System.setProperty("oidf.attester.op.issuer", "https://attester.example.com");

        IllegalStateException e = assertThrows(IllegalStateException.class,
                AttestationIssuanceServlet::federationWalletValidatorFromEnv);
        assertTrue(e.getMessage().contains(FederationRuntimeConfig.TRUST_ANCHOR_JWKS_ENV), e.getMessage());

        // And a document that is not a usable key set is refused too, rather than falling back.
        System.setProperty("oidf.trust.anchor.jwks", "{\"keys\":[]}");
        FederationRuntimeConfigTestAccess.reset();
        assertThrows(IllegalArgumentException.class, AttestationIssuanceServlet::federationWalletValidatorFromEnv);
    }

    @Test
    void federationWalletTrustIsPreferredOverStaticMap() throws Exception {
        // The static map is not a JSON object, so staticWalletValidatorFromEnv() refuses it, naming the setting (plan
        // item ST-5; it used to be ignored without a word); walletValidatorFromEnv() never reads it once the federation
        // path is configured.
        System.setProperty("oidf.wallet.provider.jwks", "{ not json");
        SettingRefused refused = assertThrows(SettingRefused.class, AttestationIssuanceServlet::staticWalletValidatorFromEnv);
        assertEquals("OIDF_WALLET_PROVIDER_JWKS", refused.setting());
        System.setProperty("oidf.trust.controller.host", "https://trust-controller.example.com");
        System.setProperty("oidf.attester.op.issuer", "https://attester.example.com");
        System.setProperty("oidf.trust.anchor.jwks", anchorJwks());
        FederationRuntimeConfigTestAccess.reset();
        InstanceAttestationValidator v = AttestationIssuanceServlet.walletValidatorFromEnv();
        assertTrue(v instanceof WalletInstanceAttestationValidator);
        assertEquals("wallet", v.format());
    }
}
