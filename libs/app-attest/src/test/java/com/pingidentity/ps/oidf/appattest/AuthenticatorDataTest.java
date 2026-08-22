package com.pingidentity.ps.oidf.appattest;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;

/**
 * {@link AuthenticatorData} parses an attacker-reachable byte layout (it comes straight off the wire
 * inside an attestation or assertion object, before any signature has been checked), so truncation at
 * every field boundary is worth pinning explicitly, not just the happy path exercised indirectly
 * through {@code AppAttestVerifierTest}.
 */
class AuthenticatorDataTest {

    private static final byte[] RP_ID_HASH = fill((byte) 0x11, 32);
    private static final byte[] AAGUID = AppAttestEnvironment.PRODUCTION.aaguid();
    private static final byte[] CREDENTIAL_ID = fill((byte) 0x22, 32);

    @Test
    void parsesAssertionFormWithNoAttestedCredentialData() throws Exception {
        byte[] data = assertionForm(7L);

        AuthenticatorData parsed = AuthenticatorData.parse(data);

        assertArrayEquals(RP_ID_HASH, parsed.rpIdHash());
        assertEquals(7L, parsed.signCount());
        assertFalse(parsed.hasAttestedCredentialData());
        assertNull(parsed.aaguid());
        assertNull(parsed.credentialId());
        assertNull(parsed.environment());
    }

    @Test
    void parsesAttestationFormWithAttestedCredentialData() throws Exception {
        byte[] data = attestationForm(0L, AAGUID, CREDENTIAL_ID);

        AuthenticatorData parsed = AuthenticatorData.parse(data);

        assertTrue(parsed.hasAttestedCredentialData());
        assertArrayEquals(AAGUID, parsed.aaguid());
        assertArrayEquals(CREDENTIAL_ID, parsed.credentialId());
        assertEquals(AppAttestEnvironment.PRODUCTION, parsed.environment());
    }

    @Test
    void signCountIsReadAsAnUnsignedThirtyTwoBitValue() throws Exception {
        // 0xFFFFFFFF as a signed int is -1; this must read back as the unsigned value, not go negative.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(RP_ID_HASH);
        out.write(0x00);
        out.write(new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF });

        AuthenticatorData parsed = AuthenticatorData.parse(out.toByteArray());
        assertEquals(0xFFFFFFFFL, parsed.signCount());
    }

    @Test
    void rejectsNullInput() {
        AppAttestException e = assertThrows(AppAttestException.class, () -> AuthenticatorData.parse(null));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void rejectsABufferShorterThanTheMinimum() {
        AppAttestException e = assertThrows(AppAttestException.class,
                () -> AuthenticatorData.parse(new byte[10]));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void rejectsAttestedCredentialDataTruncatedBeforeTheAaguidAndLength() throws Exception {
        // AT flag set, but nothing follows the counter.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(RP_ID_HASH);
        out.write(0x40);
        out.write(new byte[] { 0, 0, 0, 0 });

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> AuthenticatorData.parse(out.toByteArray()));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void rejectsACredentialIdLengthThatRunsPastTheBuffer() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(RP_ID_HASH);
        out.write(0x40);
        out.write(new byte[] { 0, 0, 0, 0 });
        out.write(AAGUID);
        // claims a 32-byte credential id but supplies none
        out.write(new byte[] { 0x00, 0x20 });

        AppAttestException e = assertThrows(AppAttestException.class,
                () -> AuthenticatorData.parse(out.toByteArray()));
        assertEquals(AppAttestException.MALFORMED, e.reason());
    }

    @Test
    void environmentIsNullForAnUnrecognisedAaguid() throws Exception {
        byte[] unknownAaguid = fill((byte) 0x99, 16);
        byte[] data = attestationForm(0L, unknownAaguid, CREDENTIAL_ID);

        AuthenticatorData parsed = AuthenticatorData.parse(data);
        assertNull(parsed.environment());
    }

    @Test
    void rawIsTheExactBytesReceivedAndIsDefensivelyCopied() throws Exception {
        byte[] data = assertionForm(0L);
        AuthenticatorData parsed = AuthenticatorData.parse(data);

        assertArrayEquals(data, parsed.raw());
        byte[] first = parsed.raw();
        first[0] = (byte) ~first[0];
        assertArrayEquals(data, parsed.raw(), "mutating a returned array must not affect the parsed value");
    }

    @Test
    void rpIdHashAndCredentialIdAccessorsAreDefensivelyCopied() throws Exception {
        byte[] data = attestationForm(0L, AAGUID, CREDENTIAL_ID);
        AuthenticatorData parsed = AuthenticatorData.parse(data);

        byte[] hash = parsed.rpIdHash();
        hash[0] = (byte) ~hash[0];
        assertArrayEquals(RP_ID_HASH, parsed.rpIdHash());

        byte[] credId = parsed.credentialId();
        credId[0] = (byte) ~credId[0];
        assertArrayEquals(CREDENTIAL_ID, parsed.credentialId());
    }

    // ---- helpers --------------------------------------------------------------------------------

    private static byte[] assertionForm(long signCount) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(RP_ID_HASH);
        out.write(0x00);
        out.write(intToBytes((int) signCount));
        return out.toByteArray();
    }

    private static byte[] attestationForm(long signCount, byte[] aaguid, byte[] credentialId) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(RP_ID_HASH);
        out.write(0x40);
        out.write(intToBytes((int) signCount));
        out.write(aaguid);
        out.write(new byte[] { (byte) (credentialId.length >> 8), (byte) credentialId.length });
        out.write(credentialId);
        return out.toByteArray();
    }

    private static byte[] intToBytes(int value) {
        return new byte[] { (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value };
    }

    private static byte[] fill(byte value, int length) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, value);
        return out;
    }
}
