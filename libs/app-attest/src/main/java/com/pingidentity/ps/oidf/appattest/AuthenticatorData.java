/*
 * The packed authenticator-data struct carried by an App Attest attestation or assertion.
 */
package com.pingidentity.ps.oidf.appattest;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * WebAuthn-shaped authenticator data, as Apple produces it for App Attest. Note this is a
 * <em>packed binary struct</em>, not CBOR — only the trailing credential public key is CBOR, and only
 * in an attestation. Getting that distinction wrong is the usual first bug.
 *
 * <pre>
 *   rpIdHash             32 bytes   SHA-256 of the App ID ("&lt;teamID&gt;.&lt;bundleID&gt;")
 *   flags                 1 byte
 *   signCount             4 bytes   big-endian
 *   -- attestation only, when the AT flag is set --
 *   aaguid               16 bytes   "appattest" or "appattestdevelop"
 *   credentialIdLength    2 bytes   big-endian
 *   credentialId          N bytes   32 for App Attest: SHA-256 of the attested public key
 *   credentialPublicKey   CBOR      COSE_Key
 * </pre>
 *
 * <p>An <em>assertion</em>'s authenticator data stops after {@code signCount}.
 */
public final class AuthenticatorData {

    /** Bit 6 of the flags byte: attested credential data is present. */
    private static final int FLAG_ATTESTED_CREDENTIAL_DATA = 0x40;

    private static final int RP_ID_HASH_LENGTH = 32;
    private static final int AAGUID_LENGTH = 16;
    private static final int MINIMUM_LENGTH = RP_ID_HASH_LENGTH + 1 + 4;

    private final byte[] rpIdHash;
    private final byte flags;
    private final long signCount;
    private final byte[] aaguid;
    private final byte[] credentialId;
    private final byte[] raw;

    private AuthenticatorData(byte[] rpIdHash, byte flags, long signCount, byte[] aaguid,
                              byte[] credentialId, byte[] raw) {
        this.rpIdHash = rpIdHash;
        this.flags = flags;
        this.signCount = signCount;
        this.aaguid = aaguid;
        this.credentialId = credentialId;
        this.raw = raw;
    }

    /**
     * Parses authenticator data. Tolerates the assertion form (no attested credential data) — callers
     * that require the attestation form check {@link #hasAttestedCredentialData()}.
     *
     * @throws AppAttestException {@code malformed_attestation} if the buffer is truncated
     */
    public static AuthenticatorData parse(byte[] data) throws AppAttestException {
        if (data == null || data.length < MINIMUM_LENGTH) {
            throw new AppAttestException(AppAttestException.MALFORMED,
                    "authenticator data is shorter than the " + MINIMUM_LENGTH + "-byte minimum");
        }
        ByteBuffer buffer = ByteBuffer.wrap(data);   // ByteBuffer is big-endian by default, as required
        byte[] rpIdHash = new byte[RP_ID_HASH_LENGTH];
        buffer.get(rpIdHash);
        byte flags = buffer.get();
        long signCount = Integer.toUnsignedLong(buffer.getInt());

        byte[] aaguid = null;
        byte[] credentialId = null;
        if ((flags & FLAG_ATTESTED_CREDENTIAL_DATA) != 0) {
            if (buffer.remaining() < AAGUID_LENGTH + 2) {
                throw new AppAttestException(AppAttestException.MALFORMED,
                        "authenticator data claims attested credential data but is truncated");
            }
            aaguid = new byte[AAGUID_LENGTH];
            buffer.get(aaguid);
            int credentialIdLength = Short.toUnsignedInt(buffer.getShort());
            if (buffer.remaining() < credentialIdLength) {
                throw new AppAttestException(AppAttestException.MALFORMED,
                        "credentialId length " + credentialIdLength + " exceeds the remaining "
                                + buffer.remaining() + " bytes");
            }
            credentialId = new byte[credentialIdLength];
            buffer.get(credentialId);
        }
        return new AuthenticatorData(rpIdHash, flags, signCount, aaguid, credentialId, data.clone());
    }

    /** SHA-256 of the App ID this authenticator data is bound to. */
    public byte[] rpIdHash() {
        return this.rpIdHash.clone();
    }

    public byte flags() {
        return this.flags;
    }

    /** The signature counter. Zero for an attestation; strictly increasing across assertions. */
    public long signCount() {
        return this.signCount;
    }

    public boolean hasAttestedCredentialData() {
        return (this.flags & FLAG_ATTESTED_CREDENTIAL_DATA) != 0;
    }

    /** The 16-byte aaguid, or null for an assertion. */
    public byte[] aaguid() {
        return this.aaguid == null ? null : this.aaguid.clone();
    }

    /** The credential id — for App Attest, SHA-256 of the attested public key. Null for an assertion. */
    public byte[] credentialId() {
        return this.credentialId == null ? null : this.credentialId.clone();
    }

    /** The environment named by the aaguid, or null if absent or unrecognised. */
    public AppAttestEnvironment environment() {
        return this.aaguid == null ? null : AppAttestEnvironment.fromAaguid(this.aaguid);
    }

    /** The bytes as received — the nonce is computed over these, so they must not be re-serialised. */
    public byte[] raw() {
        return this.raw.clone();
    }

    @Override
    public String toString() {
        return "AuthenticatorData{signCount=" + this.signCount
                + ", attested=" + hasAttestedCredentialData()
                + ", environment=" + environment()
                + ", credentialIdLength=" + (this.credentialId == null ? 0 : this.credentialId.length)
                + ", rpIdHash=" + Arrays.hashCode(this.rpIdHash) + '}';
    }
}
