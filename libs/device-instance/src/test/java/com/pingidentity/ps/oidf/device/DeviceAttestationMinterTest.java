package com.pingidentity.ps.oidf.device;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.common.JwsSigner;
import com.pingidentity.ps.oidf.common.Jwks;
import com.pingidentity.ps.oidf.common.LocalJwkSigner;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DeviceAttestationMinterTest {

    private static final String PLATFORM = "https://platform.example.com";

    private PublicJsonWebKey platformKey;   // the attester's signing key
    private PublicJsonWebKey enclaveKey;    // stands in for the Secure Enclave key
    private Map<String, Object> enclavePublicJwk;
    private AgentInstance instance;

    @BeforeEach
    void setUp() throws Exception {
        platformKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        platformKey.setKeyId("platform-1");
        enclaveKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        enclaveKey.setKeyId("enclave-1");
        enclavePublicJwk = publicParams(enclaveKey);

        instance = new AgentInstance(
                InstanceIdentifiers.newInstanceId(), PLATFORM, "agent/1.4.2",
                Jwks.thumbprint(enclavePublicJwk), InstanceStatus.ACTIVE,
                InstanceIdentifiers.newDeviceId(), Instant.now(), null, Instant.now());
    }

    private JwsSigner signer() {
        return new LocalJwkSigner(privateParams(platformKey));
    }

    private JwtClaims mintAndParse(DeviceAttestationMinter minter) throws Exception {
        DeviceAttestationMinter.Minted minted =
                minter.mint(instance, enclavePublicJwk, "cred-ref-abc", 300L, signer());
        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(minted.attestation());
        assertEquals("oauth-client-attestation+jwt", jws.getHeader("typ"));
        assertEquals("ES256", jws.getAlgorithmHeaderValue());
        assertEquals("platform-1", jws.getKeyIdHeaderValue());
        return JwtClaims.parse(jws.getUnverifiedPayload());
    }

    @Test
    void subjectIsTheOpaqueInstanceIdentifier() throws Exception {
        JwtClaims claims = mintAndParse(new DeviceAttestationMinter(PLATFORM));
        assertEquals(instance.id(), claims.getSubject());
        assertEquals(PLATFORM, claims.getIssuer());
    }

    /**
     * The invariant this whole design rests on. The attestation is presented on every token request, so
     * any user identifier in it becomes a permanent cross-resource-server correlation handle. This test
     * scans the entire serialised payload rather than named claims, so a future claim cannot smuggle one
     * in unnoticed.
     */
    @Test
    void noUserOrDeviceIdentifierAppearsAnywhereInTheAttestation() throws Exception {
        String pingOneSubject = "e7c4b1a2-user-subject-9f3d";
        String deviceId = instance.deviceId();

        DeviceAttestationMinter.Minted minted = new DeviceAttestationMinter(PLATFORM)
                .mint(instance, enclavePublicJwk, "cred-ref-abc", 300L, signer());
        String payload = new String(Base64.getUrlDecoder()
                .decode(minted.attestation().split("\\.")[1]), StandardCharsets.UTF_8);

        assertFalse(payload.contains(pingOneSubject), "user subject leaked into the attestation");
        assertFalse(payload.contains(deviceId), "device identifier leaked into the attestation");
        assertFalse(payload.toLowerCase(Locale.ROOT).contains("user_id"), payload);
        assertFalse(payload.toLowerCase(Locale.ROOT).contains("pingone"), payload);
        // The instance identifier, by contrast, is expected and wanted.
        assertTrue(payload.contains(instance.id()));
    }

    @Test
    void confirmationClaimCarriesTheEnclavePublicKey() throws Exception {
        JwtClaims claims = mintAndParse(new DeviceAttestationMinter(PLATFORM));
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) claims.getClaimValue("cnf");
        assertNotNull(cnf);
        @SuppressWarnings("unchecked")
        Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
        assertEquals(Jwks.thumbprint(enclavePublicJwk), Jwks.thumbprint(jwk));
        assertNull(jwk.get("d"), "a private key must never reach cnf");
    }

    @Test
    void lifetimeIsFifteenMinutesByDefault() throws Exception {
        JwtClaims claims = mintAndParse(new DeviceAttestationMinter(PLATFORM));
        long span = claims.getExpirationTime().getValue() - claims.getIssuedAt().getValue();
        assertEquals(Duration.ofMinutes(15).toSeconds(), span);
    }

    @Test
    void keyStorageIsModerateNotHigh() throws Exception {
        JwtClaims claims = mintAndParse(new DeviceAttestationMinter(PLATFORM));
        assertEquals("iso_18045_moderate", claims.getClaimValueAsString("key_storage"));
        assertEquals("iso_18045_moderate", claims.getClaimValueAsString("user_authentication"));
    }

    /**
     * A Secure Enclave is a keystore, not a WSCD, so {@code iso_18045_high} would be a false security
     * claim. It fails at construction rather than at issuance so it cannot drift upward unnoticed.
     */
    @Test
    void claimingIso18045HighIsRefused() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new DeviceAttestationMinter(PLATFORM, Duration.ofMinutes(15),
                        KeyStorageLevel.HIGH, KeyStorageLevel.MODERATE));
        assertTrue(e.getMessage().contains("keystore, not a WSCD"), e.getMessage());

        assertThrows(IllegalArgumentException.class,
                () -> new DeviceAttestationMinter(PLATFORM, Duration.ofMinutes(15),
                        KeyStorageLevel.MODERATE, KeyStorageLevel.HIGH));
    }

    @Test
    void agentBuildAndUvPolicyAreCarriedForPolicyToSee() throws Exception {
        JwtClaims claims = mintAndParse(new DeviceAttestationMinter(PLATFORM));
        assertEquals("agent/1.4.2", claims.getClaimValueAsString("agent_build"));
        assertEquals("cred-ref-abc", claims.getClaimValueAsString("authenticator_ref"));
        @SuppressWarnings("unchecked")
        Map<String, Object> uvPolicy = (Map<String, Object>) claims.getClaimValue("uv_policy");
        assertEquals(300L, ((Number) uvPolicy.get("reuse_seconds")).longValue());
    }

    @Test
    void aKeyThatIsNotTheOneBoundAtEnrolmentIsRefused() throws Exception {
        PublicJsonWebKey somebodyElse = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        somebodyElse.setKeyId("other");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> new DeviceAttestationMinter(PLATFORM)
                        .mint(instance, publicParams(somebodyElse), "ref", 300L, signer()));
        assertTrue(e.getMessage().contains("does not match the key bound"), e.getMessage());
    }

    @Test
    void aPrivateKeyPresentedAsTheInstanceKeyIsRefused() {
        assertThrows(RuntimeException.class, () -> new DeviceAttestationMinter(PLATFORM)
                .mint(instance, privateParams(enclaveKey), "ref", 300L, signer()));
    }

    @Test
    void aNonPositiveLifetimeIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> new DeviceAttestationMinter(
                PLATFORM, Duration.ZERO, KeyStorageLevel.MODERATE, KeyStorageLevel.MODERATE));
        assertThrows(IllegalArgumentException.class, () -> new DeviceAttestationMinter(
                PLATFORM, Duration.ofMinutes(-1), KeyStorageLevel.MODERATE, KeyStorageLevel.MODERATE));
    }

    @Test
    void mintedExpiryIsReportedForTheRegistryToRecord() {
        DeviceAttestationMinter.Minted minted = new DeviceAttestationMinter(PLATFORM)
                .mint(instance, enclavePublicJwk, "ref", 300L, signer());
        assertEquals(900L, minted.expiresInSeconds());
        assertTrue(minted.expiresAt().isAfter(Instant.now()));
    }

    // ---- helpers ---------------------------------------------------------------------------------

    private static Map<String, Object> publicParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    private static Map<String, Object> privateParams(JsonWebKey jwk) {
        return new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
    }
}
