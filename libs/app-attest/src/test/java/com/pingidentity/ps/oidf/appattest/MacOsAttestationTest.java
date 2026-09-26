package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * A real App Attest attestation from a Mac: macOS 27.2, SecureEnclaveSigner.app (team JH6RX4DRG2),
 * verified against Apple's actual App Attestation Root CA - the first proof that Apple's macOS attestation
 * objects parse and chain the way the iOS ones do. The credential certificate is valid for three days, so
 * the chain is validated as at the capture date.
 */
class MacOsAttestationTest {

    private static JsonNode fixture;
    private static byte[] attestationObject;
    private static byte[] keyId;
    private static byte[] clientDataHash;
    private static Instant capturedAt;

    @BeforeAll
    static void load() throws Exception {
        try (InputStream in = MacOsAttestationTest.class.getResourceAsStream("/fixtures/macos-27.2-attestation.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        Base64.Decoder b64 = Base64.getUrlDecoder();
        attestationObject = b64.decode(fixture.get("attestation_object").asText());
        keyId = b64.decode(fixture.get("key_id").asText());
        clientDataHash = sha256(fixture.get("jkt").asText() + "|" + fixture.get("challenge").asText());
        capturedAt = Instant.parse(fixture.get("validate_at").asText());
    }

    private static AppAttestVerifier verifier(String bundleId, Instant at) {
        return new AppAttestVerifier(AppAttestConfig.production("JH6RX4DRG2", bundleId).withValidationTime(at));
    }

    @Test
    void aRealMacAttestationVerifiesAgainstApplesRoot() throws Exception {
        AppAttestAttestation attested = verifier("info.makefish.fedconnector.sesigner", capturedAt)
                .verifyAttestation(attestationObject, clientDataHash, keyId);

        assertEquals(AppAttestEnvironment.PRODUCTION, attested.environment());
        assertEquals(fixture.get("key_id").asText(), attested.keyIdBase64Url());
        assertEquals(0L, attested.signCount());
        assertNull(attested.receipt(), "the fixture's receipt was removed; nothing depends on it");
    }

    @Test
    void theMacSaysSigningNeedsFullSecurity() throws Exception {
        AppAttestAttestation attested = verifier("info.makefish.fedconnector.sesigner", capturedAt)
                .verifyAttestation(attestationObject, clientDataHash, keyId);

        AppAttestKeyPolicy policy = attested.keyPolicy();
        assertNotNull(policy);
        assertEquals("11", policy.version());
        assertEquals(List.of("ok", "oa", "odel", "osgn"), List.copyOf(policy.operations().keySet()));
        assertTrue(policy.signingRequiresSecurity());
        assertEquals("ok oa odel osgn:rsec(6=1)", policy.summary());

        AppAttestPlatform platform = attested.platform();
        assertNotNull(platform);
        assertTrue(platform.isMac());
        assertEquals("27.2", platform.version());
        assertEquals("26B5091g", platform.build());
        assertEquals("macosx 27.2 (26B5091g)", platform.describe());
        assertTrue(attested.toString().contains("platform=macosx 27.2 (26B5091g)"));
        assertTrue(attested.toString().contains("keyPolicy=ok oa odel osgn:rsec(6=1)"));
    }

    @Test
    void anAttestationWithoutApplesMacExtensionsCarriesNoPolicy() throws Exception {
        AppAttestFixtures synthetic = new AppAttestFixtures();
        byte[] hash = sha256("jkt|challenge");
        AppAttestAttestation ios = new AppAttestVerifier(synthetic.config(Set.of(AppAttestEnvironment.PRODUCTION)))
                .verifyAttestation(synthetic.attestation(hash).cbor(), hash, null);
        assertNull(ios.keyPolicy());
        assertNull(ios.platform());
        assertEquals(-1, ios.toString().indexOf("platform="));

        AppAttestAttestation mac = new AppAttestVerifier(synthetic.config(Set.of(AppAttestEnvironment.PRODUCTION)))
                .verifyAttestation(synthetic.macAttestation(hash).cbor(), hash, null);
        assertTrue(mac.keyPolicy().signingRequiresSecurity());
        assertTrue(mac.platform().isMac());
    }

    @Test
    void theLeafExpiresAfterThreeDays() {
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> verifier("info.makefish.fedconnector.sesigner", Instant.parse("2026-09-29T12:00:00Z"))
                        .verifyAttestation(attestationObject, clientDataHash, keyId));
        assertEquals(AppAttestException.UNTRUSTED_CHAIN, e.reason());
    }

    @Test
    void itIsBoundToThisAppAlone() {
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> verifier("info.makefish.fedconnector.other", capturedAt)
                        .verifyAttestation(attestationObject, clientDataHash, keyId));
        assertEquals(AppAttestException.APP_ID_MISMATCH, e.reason());
    }

    @Test
    void itCommitsToThisKeyAndChallengeAlone() {
        byte[] otherChallenge = sha256(fixture.get("jkt").asText() + "|another-challenge");
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> verifier("info.makefish.fedconnector.sesigner", capturedAt)
                        .verifyAttestation(attestationObject, otherChallenge, keyId));
        assertEquals(AppAttestException.NONCE_MISMATCH, e.reason());
    }

    @Test
    void aProductionOnlyVerifierAcceptsIt() {
        assertEquals(Set.of(AppAttestEnvironment.PRODUCTION),
                AppAttestConfig.production("JH6RX4DRG2", "info.makefish.fedconnector.sesigner").acceptedEnvironments());
    }

    private static byte[] sha256(String input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
