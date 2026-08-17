package com.pingidentity.ps.oidf.servlet.attestation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.issuer.InstanceAttestationValidator;
import com.pingidentity.ps.oidf.issuer.WalletInstanceAttestationValidator;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Ported from pf-oidf-modules (2026-08-15) when that repo was reduced to the demo — trimmed to the
 * env-wiring helpers that still exist on {@link AttestationIssuanceServlet}: {@code env()},
 * {@code walletValidatorFromEnv()}, {@code federationWalletValidatorFromEnv()}, and
 * {@code staticWalletValidatorFromEnv()}. Dropped: cases for {@code cimdResolverFromEnv()},
 * {@code parseStringMap()}, {@code parseObjectMap()} — those don't exist here; the CIMD resolver is now
 * wired from {@code AttestationIssuanceConfig} properties (see {@code CimdClientResolver},
 * {@code CimdMapping}), not a servlet-level env helper. None of these methods had a test in this repo.
 */
class ServletEnvWiringTest {

    private static final String[] PROPS = {
            "oidf.trust.controller.host", "oidf.attester.op.issuer", "oidf.wallet.provider.jwks",
            "oidf.trust.controller.ignore.ssl"};

    @AfterEach
    void clearProps() {
        for (String p : PROPS) {
            System.clearProperty(p);
        }
    }

    @Test
    void envReadsSystemPropertyThenNull() {
        System.setProperty("oidf.attester.op.issuer", "value");
        assertEquals("value", AttestationIssuanceServlet.env("oidf.attester.op.issuer", "NO_SUCH_ENV"));
        assertNull(AttestationIssuanceServlet.env("oidf.absent.prop", "NO_SUCH_ENV_XYZ"));
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
        InstanceAttestationValidator v = AttestationIssuanceServlet.federationWalletValidatorFromEnv();
        assertTrue(v instanceof WalletInstanceAttestationValidator);
        assertEquals("wallet", v.format());
    }

    @Test
    void federationWalletTrustIsPreferredOverStaticMap() throws Exception {
        // The static map is unparseable, so staticWalletValidatorFromEnv() would return null; if
        // walletValidatorFromEnv() is still non-null, it must have taken the federation path.
        System.setProperty("oidf.wallet.provider.jwks", "{ not json");
        assertNull(AttestationIssuanceServlet.staticWalletValidatorFromEnv());
        System.setProperty("oidf.trust.controller.host", "https://trust-controller.example.com");
        System.setProperty("oidf.attester.op.issuer", "https://attester.example.com");
        InstanceAttestationValidator v = AttestationIssuanceServlet.walletValidatorFromEnv();
        assertTrue(v instanceof WalletInstanceAttestationValidator);
        assertEquals("wallet", v.format());
    }
}
