package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The macOS key access-control list, from Apple's bytes and from every way they can be wrong. */
class AppAttestKeyPolicyTest {

    /** What {@code getExtensionValue} hands back: an OCTET STRING around the extension's DER. */
    private static byte[] asExtension(byte[] der) {
        byte[] out = new byte[der.length + 2];
        out[0] = 0x04;
        out[1] = (byte) der.length;
        System.arraycopy(der, 0, out, 2, der.length);
        return out;
    }

    private static byte[] hex(String h) {
        return HexFormat.of().parseHex(h);
    }

    @Test
    void readsTheMacPolicy() {
        AppAttestKeyPolicy policy = AppAttestKeyPolicy.parse(asExtension(AppAttestFixtures.MACOS_KEY_POLICY));
        assertNotNull(policy);
        assertTrue(policy.signingRequiresSecurity());
        AppAttestKeyPolicy.Operation sign = policy.operations().get(AppAttestKeyPolicy.SIGN);
        assertEquals("rsec", sign.requirement());
        assertEquals(Map.of(6, 1L), sign.parameters());
        assertFalse(sign.alwaysAllowed());
        assertTrue(policy.operations().get("odel").alwaysAllowed());
    }

    @Test
    void signingThatIsAlwaysAllowedIsNotGated() {
        Map<String, AppAttestKeyPolicy.Operation> ops = new LinkedHashMap<>();
        ops.put("osgn", new AppAttestKeyPolicy.Operation("osgn", true, null, null));
        ops.put("oa", new AppAttestKeyPolicy.Operation("oa", false, null, Map.of()));
        AppAttestKeyPolicy policy = new AppAttestKeyPolicy("11", ops);
        assertFalse(policy.signingRequiresSecurity());
        assertEquals("osgn oa:denied", policy.summary());
    }

    @Test
    void signingGatedBySomethingElseIsNotFullSecurity() {
        AppAttestKeyPolicy policy = new AppAttestKeyPolicy("11",
                Map.of("osgn", new AppAttestKeyPolicy.Operation("osgn", false, "rbio", Map.of())));
        assertFalse(policy.signingRequiresSecurity());
        assertEquals("osgn:rbio", policy.summary());
    }

    @Test
    void aPolicyWithoutSigningIsNotGated() {
        assertFalse(new AppAttestKeyPolicy("11", null).signingRequiresSecurity());
        assertEquals("", new AppAttestKeyPolicy("11", null).summary());
    }

    @Test
    void anythingElseReadsAsNoPolicy() {
        // Not DER at all.
        assertNull(AppAttestKeyPolicy.parse(hex("ff")));
        // The wrapper holds something other than a SEQUENCE.
        assertNull(AppAttestKeyPolicy.parse(asExtension(hex("0400"))));
        // A SEQUENCE whose one element is not [3].
        assertNull(AppAttestKeyPolicy.parse(asExtension(hex("3004a4020400"))));
        // [3] around a body with only a version and no operations.
        assertNull(AppAttestKeyPolicy.parse(asExtension(hex("3008a306040430020c00"))));
        // An operation entry with no name.
        assertNull(AppAttestKeyPolicy.parse(asExtension(hex("300ca30a040830060c0030023000"))));
        // Truncated in the middle of an operation.
        byte[] cut = java.util.Arrays.copyOf(AppAttestFixtures.MACOS_KEY_POLICY, 40);
        assertNull(AppAttestKeyPolicy.parse(asExtension(cut)));
    }

    @Test
    void unknownFieldsInAnOperationAreSkipped() {
        // SEQUENCE { [3] { OCTET STRING { SEQUENCE { "1", SEQUENCE { SEQUENCE { "osgn", INTEGER 5 } } } } } }
        byte[] body = hex("3010" + "0c0131" + "300b" + "3009" + "0c046f73676e" + "020105");
        byte[] octets = new byte[body.length + 2];
        octets[0] = 0x04;
        octets[1] = (byte) body.length;
        System.arraycopy(body, 0, octets, 2, body.length);
        byte[] tagged = new byte[octets.length + 2];
        tagged[0] = (byte) 0xa3;
        tagged[1] = (byte) octets.length;
        System.arraycopy(octets, 0, tagged, 2, octets.length);
        byte[] seq = new byte[tagged.length + 2];
        seq[0] = 0x30;
        seq[1] = (byte) tagged.length;
        System.arraycopy(tagged, 0, seq, 2, tagged.length);
        AppAttestKeyPolicy policy = AppAttestKeyPolicy.parse(asExtension(seq));
        assertNotNull(policy);
        assertEquals("osgn:denied", policy.summary());
    }
}
