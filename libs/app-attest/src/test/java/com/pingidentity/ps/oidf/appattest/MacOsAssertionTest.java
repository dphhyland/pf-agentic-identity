package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Real App Attest assertions from macOS 27.2. They are what exposed the verifier's assertion path, which
 * until then had only met assertions it built itself: Apple signs the nonce, SHA-256(authenticatorData ‖
 * clientDataHash), not the concatenation - and sets the attested-credential-data flag on an assertion that
 * carries no credential data, following the counter with an extensions map instead.
 */
class MacOsAssertionTest {

    private static byte[] first;
    private static byte[] second;
    private static byte[] clientDataHash;
    private static ECPublicKey key;
    private static AppAttestVerifier verifier;

    @BeforeAll
    static void load() throws Exception {
        JsonNode fixture;
        try (InputStream in = MacOsAssertionTest.class.getResourceAsStream("/fixtures/macos-27.2-assertions.json")) {
            fixture = new ObjectMapper().readTree(in);
        }
        Base64.Decoder b64 = Base64.getUrlDecoder();
        first = b64.decode(fixture.get("assertions").get(0).asText());
        second = b64.decode(fixture.get("assertions").get(1).asText());
        clientDataHash = MessageDigest.getInstance("SHA-256")
                .digest(fixture.get("client_data").asText().getBytes(StandardCharsets.UTF_8));
        key = (ECPublicKey) KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(b64.decode(fixture.get("attested_key_spki").asText())));
        verifier = new AppAttestVerifier(AppAttestConfig.production("JH6RX4DRG2", "info.makefish.fedconnector.sesigner"));
    }

    @Test
    void realAssertionsVerifyAndTheirCounterRises() throws Exception {
        assertEquals(1L, verifier.verifyAssertion(first, clientDataHash, key, 0L));
        assertEquals(2L, verifier.verifyAssertion(second, clientDataHash, key, 1L));
    }

    @Test
    void anOldAssertionIsAReplay() {
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> verifier.verifyAssertion(first, clientDataHash, key, 1L));
        assertEquals(AppAttestException.COUNTER_NOT_ADVANCED, e.reason());
    }

    @Test
    void anAssertionCoversOnlyWhatItWasMadeFor() throws Exception {
        byte[] other = MessageDigest.getInstance("SHA-256").digest("another request".getBytes(StandardCharsets.UTF_8));
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> verifier.verifyAssertion(first, other, key, 0L));
        assertEquals(AppAttestException.BAD_SIGNATURE, e.reason());
    }

    @Test
    void anAssertionIsBoundToThisApp() {
        AppAttestVerifier elsewhere = new AppAttestVerifier(AppAttestConfig.production("JH6RX4DRG2", "info.makefish.other"));
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> elsewhere.verifyAssertion(first, clientDataHash, key, 0L));
        assertEquals(AppAttestException.APP_ID_MISMATCH, e.reason());
    }

    @Test
    void theAssertionFormReadsOnlyItsHeader() throws Exception {
        // 32 bytes of rpIdHash, flags 0xc0 with no credential data behind them, counter 7, Apple's extensions.
        byte[] data = HexFormat.of().parseHex("00".repeat(32) + "c0" + "00000007"
                + "a1781c6170706c655f76616c69646174696f6e5f63617465676f72795f30314403000000");
        AuthenticatorData parsed = AuthenticatorData.parseAssertion(data);
        assertEquals(7L, parsed.signCount());
        assertEquals((byte) 0xc0, parsed.flags());
        assertThrows(AppAttestException.class, () -> AuthenticatorData.parse(data), "the attestation form trusts the flag");
        assertThrows(AppAttestException.class, () -> AuthenticatorData.parseAssertion(new byte[36]));
        assertThrows(AppAttestException.class, () -> AuthenticatorData.parseAssertion(null));
    }
}
