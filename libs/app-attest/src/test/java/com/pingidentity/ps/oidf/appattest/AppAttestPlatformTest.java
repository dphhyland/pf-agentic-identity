package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/** The OS facts Apple signs into a credential certificate. */
class AppAttestPlatformTest {

    private static byte[] asExtension(byte[] der) {
        byte[] out = new byte[der.length + 3];
        out[0] = 0x04;
        out[1] = (byte) 0x81;
        out[2] = (byte) der.length;
        System.arraycopy(der, 0, out, 3, der.length);
        return out;
    }

    private static byte[] hex(String h) {
        return HexFormat.of().parseHex(h);
    }

    @Test
    void readsTheMac() {
        AppAttestPlatform platform = AppAttestPlatform.parse(asExtension(AppAttestFixtures.MACOS_PLATFORM));
        assertNotNull(platform);
        assertEquals(new AppAttestPlatform("macosx", "27.2", "26B5091g"), platform);
    }

    @Test
    void describesWhatItHas() {
        assertEquals("unknown 18.0", new AppAttestPlatform(null, "18.0", null).describe());
        assertEquals("iphoneos", new AppAttestPlatform("iphoneos", null, null).describe());
        assertFalse(new AppAttestPlatform("iphoneos", "18.0", null).isMac());
        assertTrue(new AppAttestPlatform("macosx", null, null).isMac());
    }

    @Test
    void skipsFieldsItDoesNotRead() {
        // SEQUENCE { INTEGER 1, [1] primitive, [1400] { INTEGER 2 }, [1026] { OCTET STRING "macosx" }, [9] { OCTET STRING "x" } }
        byte[] der = hex("301d" + "020101" + "8100" + "bf8a7803020102" + "bf88020804066d61636f7378" + "a903040178");
        AppAttestPlatform platform = AppAttestPlatform.parse(asExtension(der));
        assertEquals(new AppAttestPlatform("macosx", null, null), platform);
    }

    @Test
    void aVersionWithoutANameIsStillRead() {
        byte[] der = hex("300a" + "bf8a7806040432372e32");
        assertEquals(new AppAttestPlatform(null, "27.2", null), AppAttestPlatform.parse(asExtension(der)));
    }

    @Test
    void anythingElseReadsAsNothing() {
        assertNull(AppAttestPlatform.parse(hex("ff")));
        assertNull(AppAttestPlatform.parse(asExtension(hex("0400"))));
        // A SEQUENCE with nothing this reads.
        assertNull(AppAttestPlatform.parse(asExtension(hex("3003020101"))));
        // A tag holding two values.
        assertNull(AppAttestPlatform.parse(asExtension(hex("3009bf8a7805040132 0400".replace(" ", "")))));
    }
}
