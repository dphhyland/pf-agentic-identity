package com.pingidentity.ps.oidf.issuer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import com.pingidentity.ps.oidf.clientattestation.AttesterKeyResolver;
import com.pingidentity.ps.oidf.clientattestation.StaticAttesterKeyResolver;
import com.pingidentity.ps.oidf.jose.Jwks;

class WalletInstanceAttestationValidatorTest {
    private static final String ATTESTER = "https://attester.example.com";
    private static final String PROVIDER = "https://wallet.example.com";
    private static final String OTHER_PROVIDER = "https://other-wallet.example.com";
    private static final String INSTANCE_ID = "urn:wallet:instance:abc123";

    private PublicJsonWebKey providerKey;      // the wallet provider signs the WIA
    private PublicJsonWebKey instanceKey;      // the wallet instance's own key (bound by cnf)
    private Map<String, Object> instancePub;
    private WalletInstanceAttestationValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        providerKey = TestJwts.ec("wp-1");
        instanceKey = TestJwts.ec("wallet-inst-1");
        instancePub = TestJwts.publicParams(instanceKey);
        JsonWebKey providerPub = JsonWebKey.Factory.newJwk(TestJwts.publicParams(providerKey));
        AttesterKeyResolver resolver = new StaticAttesterKeyResolver(Map.of(
                PROVIDER, List.of(providerPub),
                OTHER_PROVIDER, List.of(providerPub)));   // OTHER is trusted but not necessarily pinned
        validator = new WalletInstanceAttestationValidator(resolver);
    }

    private AttestationIssuanceConfig config() throws Exception {
        return config(null);
    }

    /**
     * A wallet-only client: it declares the wallet evidence type, which is what makes a SPIFFE trust bundle
     * unnecessary ({@link InstanceAttestationValidator#requiresTrustBundle()}). Binds the wallet instance;
     * optionally pins a provider via the trust-domain property.
     */
    private AttestationIssuanceConfig config(String pinnedProvider) throws Exception {
        Map<String, String> props = new HashMap<>();
        props.put(AttestationIssuanceConfig.P_ISSUER, ATTESTER);
        props.put(AttestationIssuanceConfig.P_EVIDENCE,
                AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION);
        props.put(AttestationIssuanceConfig.P_INSTANCES,
                "[{\"wallet_instance\":\"" + INSTANCE_ID + "\",\"metadata\":{\"tenant\":\"gold\"}}]");
        if (pinnedProvider != null) {
            props.put(AttestationIssuanceConfig.P_TRUST_DOMAIN, pinnedProvider);
        }
        return AttestationIssuanceConfig.fromProperties(props);
    }

    /** Builds a signed WIA; pass a null cnf to omit the key binding, or a distinct typ to test typ checks. */
    private String wia(PublicJsonWebKey signer, String iss, String sub, String aud,
                       Map<String, Object> cnfJwk, long expOffset, String typ) throws Exception {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setAudience(aud);
        c.setIssuedAtToNow();
        c.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + expOffset));
        if (cnfJwk != null) {
            Map<String, Object> cnf = new LinkedHashMap<>();
            cnf.put("jwk", cnfJwk);
            c.setClaim("cnf", cnf);
        }
        return TestJwts.sign(signer, "ES256", typ, c);
    }

    private String wia() throws Exception {
        return wia(providerKey, PROVIDER, INSTANCE_ID, ATTESTER, instancePub, 600L, "wallet-instance-attestation+jwt");
    }

    /** A wallet's trust root is its provider, so no bundle keys are ever consulted. */
    private InstanceIdentity validate(String presented, AttestationIssuanceConfig config) throws IssuanceException {
        return validator.validate(presented, List.of(), config);
    }

    @Test
    void happyPathValidatesToWalletInstanceIdentity() throws Exception {
        InstanceIdentity id = validate(wia(), config());
        assertEquals("wallet", id.format());
        assertEquals(INSTANCE_ID, id.subject());
        assertEquals(PROVIDER, id.trustDomain());
        // the bound key is the instance key, ready for the endpoint's boundKey==instance_key check
        assertEquals(Jwks.thumbprint(instancePub), Jwks.thumbprint(id.boundKey()));
        assertEquals(PROVIDER, id.workloadClaims().get("wallet_provider"));
        assertEquals(INSTANCE_ID, id.workloadClaims().get("wallet_instance"));
    }

    @Test
    void declaresItselfAsWalletFormatNeedingNoTrustBundle() {
        assertEquals(AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION, validator.id());
        assertEquals("wallet", validator.format());
        assertEquals(false, validator.requiresTrustBundle());
        assertEquals(false, validator.requiresTrustDomain());
    }

    @Test
    void untrustedWalletProviderIsRejected() throws Exception {
        String w = wia(providerKey, "https://rogue.example.com", INSTANCE_ID, ATTESTER, instancePub, 600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void signatureFromWrongKeyIsRejected() throws Exception {
        PublicJsonWebKey attacker = TestJwts.ec("wp-1");   // same kid, different key
        String w = wia(attacker, PROVIDER, INSTANCE_ID, ATTESTER, instancePub, 600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void kidNotInProviderBundleIsRejected() throws Exception {
        PublicJsonWebKey stray = TestJwts.ec("unknown-kid");
        String w = wia(stray, PROVIDER, INSTANCE_ID, ATTESTER, instancePub, 600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void wrongAudienceIsRejected() throws Exception {
        String w = wia(providerKey, PROVIDER, INSTANCE_ID, "https://elsewhere.example.com", instancePub, 600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void expiredWiaIsRejected() throws Exception {
        String w = wia(providerKey, PROVIDER, INSTANCE_ID, ATTESTER, instancePub, -600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void missingCnfIsRejected() throws Exception {
        String w = wia(providerKey, PROVIDER, INSTANCE_ID, ATTESTER, null, 600L, "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void unexpectedTypIsRejected() throws Exception {
        String w = wia(providerKey, PROVIDER, INSTANCE_ID, ATTESTER, instancePub, 600L, "not-a-wia+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void pinnedProviderMismatchIsRejected() throws Exception {
        // WIA from OTHER_PROVIDER (trusted) but the client pins PROVIDER.
        String w = wia(providerKey, OTHER_PROVIDER, INSTANCE_ID, ATTESTER, instancePub, 600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config(PROVIDER))).error());
    }

    @Test
    void privateCnfKeyIsRejected() throws Exception {
        String w = wia(providerKey, PROVIDER, INSTANCE_ID, ATTESTER, TestJwts.privateParams(instanceKey), 600L,
                "wallet-instance-attestation+jwt");
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate(w, config())).error());
    }

    @Test
    void absentTypIsAccepted() throws Exception {
        String w = wia(providerKey, PROVIDER, INSTANCE_ID, ATTESTER, instancePub, 600L, null);
        assertEquals(INSTANCE_ID, validate(w, config()).subject());
    }

    @Test
    void malformedTokenIsRejected() {
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class, () -> validate("not.a.jwt", config())).error());
    }

    @Test
    void unconfiguredWalletTrustRefusesRatherThanAccepting() throws Exception {
        // The placeholder registered by InstanceAttestationValidators.defaults() must refuse, never accept.
        InstanceAttestationValidator placeholder = InstanceAttestationValidators.defaults()
                .require(AttestationIssuanceConfig.EVIDENCE_WALLET_INSTANCE_ATTESTATION);
        String w = wia();
        assertEquals("invalid_instance_attestation",
                assertThrows(IssuanceException.class,
                        () -> placeholder.validate(w, List.of(), config())).error());
    }

    @Test
    void spiffeInstanceIdentityHasNoBoundKey() throws Exception {
        // Cross-check the contract the endpoint relies on: SPIFFE binds no key, so no boundKey check runs.
        SpiffeSvid svid = new SpiffeSvid("spiffe://d/x", "d", "/x", List.of(ATTESTER),
                NumericDate.now().getValue() + 600, NumericDate.now().getValue(), "raw");
        assertNull(InstanceIdentity.ofSpiffe(svid).boundKey());
    }
}
