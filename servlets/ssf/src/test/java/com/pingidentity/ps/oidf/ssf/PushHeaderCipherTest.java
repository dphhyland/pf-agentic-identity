/*
 * H-SSF-7: a push stream's authorization_header sealed at rest with AES-256-GCM under a key id, rotated, migrated.
 */
package com.pingidentity.ps.oidf.ssf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import org.junit.jupiter.api.Test;

class PushHeaderCipherTest {

    static final String KEY_1 = key((byte) 1);
    static final String KEY_2 = key((byte) 2);

    static String key(byte fill) {
        byte[] raw = new byte[32];
        java.util.Arrays.fill(raw, fill);
        return Base64.getEncoder().encodeToString(raw);
    }

    @Test
    void aHeaderIsSealedUnderItsKeyIdAndOpensForItsStream() {
        PushHeaderCipher c = PushHeaderCipher.of(KEY_1, null, true);
        String sealed = c.seal("stream-1", "Bearer receiver-secret");
        assertTrue(sealed.startsWith("ssfenc:v1:" + c.kid() + ":"), sealed);
        assertFalse(sealed.contains("receiver-secret"));
        assertEquals("Bearer receiver-secret", c.open("stream-1", sealed));
        assertNotEquals(sealed, c.seal("stream-1", "Bearer receiver-secret"), "a fresh nonce each time");
        assertEquals(16, c.kid().length());
        assertTrue(c.hasKey());
    }

    @Test
    void aSealedHeaderCopiedToAnotherStreamDoesNotOpen() {
        PushHeaderCipher c = PushHeaderCipher.of(KEY_1, null, true);
        String sealed = c.seal("stream-1", "Bearer s");
        assertEquals(sealed, c.open("stream-2", sealed), "kept sealed rather than lost, and never opened for the wrong stream");
        String tampered = sealed.substring(0, sealed.length() - 2) + (sealed.endsWith("A") ? "BB" : "AA");
        assertEquals(tampered, c.open("stream-1", tampered));
        String garbage = "ssfenc:v1:" + c.kid() + ":***";
        assertEquals(garbage, c.open("stream-1", garbage));
        assertEquals("ssfenc:v1:nokid", c.open("stream-1", "ssfenc:v1:nokid"));
    }

    @Test
    void theStreamIdIsComparedInLowerCaseAsTheLdmStoreReadsItBack() {
        PushHeaderCipher c = PushHeaderCipher.of(KEY_1, null, true);
        assertEquals("Bearer s", c.open("0f6e0a8e-0000-4000-8000-00000000abcd",
                c.seal("0F6E0A8E-0000-4000-8000-00000000ABCD", "Bearer s")));
    }

    /** A second key decrypts during a rotation; what it opens is sealed under the new key on the next write. */
    @Test
    void aRotationKeepsOldValuesOpenUntilTheyAreRewritten() {
        PushHeaderCipher old = PushHeaderCipher.of(KEY_1, null, true);
        String sealedOld = old.seal("s", "Bearer old");
        PushHeaderCipher rotated = PushHeaderCipher.of(KEY_2, KEY_1, true);
        assertEquals("Bearer old", rotated.open("s", sealedOld));
        String resealed = rotated.seal("s", rotated.open("s", sealedOld));
        assertTrue(resealed.startsWith("ssfenc:v1:" + rotated.kid() + ":"));
        assertNotEquals(old.kid(), rotated.kid());

        PushHeaderCipher newOnly = PushHeaderCipher.of(KEY_2, null, true);
        assertEquals(sealedOld, newOnly.open("s", sealedOld), "the old key gone: left sealed, reported once");
        assertEquals(sealedOld, newOnly.open("s", sealedOld));
        assertEquals(sealedOld, newOnly.seal("s", sealedOld), "a value already sealed is written back as it is");
    }

    /** A clear value an earlier version stored reads as it is, and is sealed on the stream's next write. */
    @Test
    void aClearLegacyValueIsReadAndSealedOnTheNextWrite() {
        PushHeaderCipher c = PushHeaderCipher.of(KEY_1, null, true);
        assertEquals("Bearer legacy", c.open("s", "Bearer legacy"));
        assertTrue(PushHeaderCipher.isSealed(c.seal("s", c.open("s", "Bearer legacy"))));
        assertNull(c.seal("s", null));
        assertNull(c.open("s", null));
        assertFalse(PushHeaderCipher.isSealed(null));
    }

    @Test
    void withoutAKeyProductionRefusesAndDevelopmentStoresClear() {
        PushHeaderCipher production = PushHeaderCipher.of(null, null, true);
        PushHeaderCipher.KeyMissing e = assertThrows(PushHeaderCipher.KeyMissing.class, () -> production.seal("s", "Bearer x"));
        assertTrue(e.getMessage().contains("OIDF_SSF_SECRET_KEY"), e.getMessage());
        assertNull(production.seal("s", null), "no header, nothing to refuse");
        assertFalse(production.hasKey());
        assertNull(production.kid());

        PushHeaderCipher development = PushHeaderCipher.of(null, null, false);
        assertEquals("Bearer x", development.seal("s", "Bearer x"));
        assertEquals("Bearer y", development.seal("s", "Bearer y"), "warned once, stored clear each time");
        assertEquals("Bearer x", PushHeaderCipher.CLEAR.seal("s", "Bearer x"));
    }

    @Test
    void aKeyIsThirtyTwoBytesOfBase64() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PushHeaderCipher.of("c2hvcnQ=", null, true));
        assertTrue(e.getMessage().startsWith("OIDF_SSF_SECRET_KEY is 5 bytes"), e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> PushHeaderCipher.of("not base64!", null, true));
        assertTrue(e.getMessage().startsWith("OIDF_SSF_SECRET_KEY is not base64"), e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> PushHeaderCipher.of(KEY_1, "c2hvcnQ=", true));
        assertTrue(e.getMessage().startsWith("OIDF_SSF_SECRET_KEY_PREVIOUS"), e.getMessage());
        e = assertThrows(IllegalArgumentException.class, () -> PushHeaderCipher.of(null, KEY_1, true));
        assertTrue(e.getMessage().startsWith("OIDF_SSF_SECRET_KEY_PREVIOUS is set without"), e.getMessage());
        String urlSafe = Base64.getUrlEncoder().encodeToString(new byte[] {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13,
            -14, -15, -16, -17, -18, -19, -20, -21, -22, -23, -24, -25, -26, -27, -28, -29, -30, -31, -32});
        assertTrue(urlSafe.contains("_") || urlSafe.contains("-"));
        assertTrue(PushHeaderCipher.of(urlSafe, null, true).hasKey(), "base64url is taken too");
    }

    /** Production with no key refuses to start over a store that holds a header; with none, or a key, it starts. */
    @Test
    void productionWithoutAKeyRefusesAStoreThatHoldsAHeader() {
        InMemorySsfStore store = new InMemorySsfStore();
        PushHeaderCipher.of(null, null, true).refuseStoredWithoutKey(store);
        store.createStream(Stream.builder().id("p").audience("https://r").deliveryMethod(DeliveryMethod.PUSH)
                .pushEndpointUrl("https://r/events").eventsRequested(java.util.List.of()).eventsDelivered(java.util.List.of())
                .status(StreamStatus.ENABLED).build());
        PushHeaderCipher.of(null, null, true).refuseStoredWithoutKey(store);
        store.createStream(Stream.builder().id("q").audience("https://r").deliveryMethod(DeliveryMethod.PUSH)
                .pushEndpointUrl("https://r/events").pushAuthorizationHeader("Bearer x").eventsRequested(java.util.List.of())
                .eventsDelivered(java.util.List.of()).status(StreamStatus.ENABLED).build());
        PushHeaderCipher.KeyMissing e = assertThrows(PushHeaderCipher.KeyMissing.class,
                () -> PushHeaderCipher.of(null, null, true).refuseStoredWithoutKey(store));
        assertTrue(e.getMessage().contains("holds 1 push stream(s)"), e.getMessage());
        PushHeaderCipher.of(KEY_1, null, true).refuseStoredWithoutKey(store);
        PushHeaderCipher.of(null, null, false).refuseStoredWithoutKey(store);
    }

    @Test
    void theConfigurationBuildsTheCipherAndRefusesABadKeyNamingIt() {
        SsfConfiguration cfg = new SsfConfiguration.Builder().issuer("https://op.example.com").secretKey(KEY_2)
                .secretKeyPrevious(KEY_1).build();
        assertEquals(PushHeaderCipher.of(KEY_2, null, true).kid(), cfg.pushHeaderCipher(true).kid());
        assertEquals("Bearer z", cfg.pushHeaderCipher(true).open("s", PushHeaderCipher.of(KEY_1, null, true).seal("s", "Bearer z")));
        assertThrows(IllegalArgumentException.class,
                () -> new SsfConfiguration.Builder().issuer("https://op.example.com").secretKey("c2hvcnQ=").build());
        assertThrows(IllegalArgumentException.class,
                () -> new SsfConfiguration.Builder().issuer("https://op.example.com").secretKeyPrevious(KEY_1).build());
    }
}
