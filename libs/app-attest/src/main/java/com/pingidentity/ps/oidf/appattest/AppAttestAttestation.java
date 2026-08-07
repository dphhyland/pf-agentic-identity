/*
 * The outcome of verifying an App Attest attestation.
 */
package com.pingidentity.ps.oidf.appattest;

import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * A verified App Attest attestation. Holding one of these means Apple vouched that a genuine,
 * unmodified build of the configured app, on genuine Apple hardware, generated {@link #attestedKey()}.
 *
 * <p>What it does <strong>not</strong> mean, and the distinction matters: nothing about <em>who</em>
 * the user is, and nothing about any key other than the one App Attest itself generated. App Attest
 * cannot attest a key the app produced independently — so if a Secure Enclave signing key is to be
 * bound to this device, that binding comes from the caller committing the key's thumbprint into
 * {@code clientDataHash}, and its strength is the strength of that commitment, not of Apple's
 * signature. See {@code docs/claim-dictionary.md}.
 */
public final class AppAttestAttestation {

    private final byte[] keyId;
    private final ECPublicKey attestedKey;
    private final AppAttestEnvironment environment;
    private final long signCount;
    private final byte[] receipt;

    AppAttestAttestation(byte[] keyId, ECPublicKey attestedKey, AppAttestEnvironment environment,
                         long signCount, byte[] receipt) {
        this.keyId = keyId;
        this.attestedKey = attestedKey;
        this.environment = environment;
        this.signCount = signCount;
        this.receipt = receipt;
    }

    /**
     * The App Attest key identifier: SHA-256 of the attested public key. Persist <em>this</em>, not the
     * attestation object — Apple's guidance, and the assertion path needs only the key id and key.
     */
    public byte[] keyId() {
        return this.keyId.clone();
    }

    /** The key id base64url-encoded, for storage and logging. */
    public String keyIdBase64Url() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(this.keyId);
    }

    /** The App Attest key Apple attested. Used to verify later assertions from this install. */
    public ECPublicKey attestedKey() {
        return this.attestedKey;
    }

    /**
     * Which Apple environment produced this. A {@link AppAttestEnvironment#DEVELOPMENT} value here means
     * the verifier was explicitly configured to allow it — record it against the instance so a
     * development enrolment is never mistaken for a production one later.
     */
    public AppAttestEnvironment environment() {
        return this.environment;
    }

    /** The attestation's signature counter — always zero, and checked to be so. */
    public long signCount() {
        return this.signCount;
    }

    /**
     * Apple's opaque receipt, which can be exchanged with Apple for a risk metric and fraud signals.
     * Not interpreted here.
     */
    public byte[] receipt() {
        return this.receipt == null ? null : this.receipt.clone();
    }

    @Override
    public String toString() {
        return "AppAttestAttestation{keyId=" + keyIdBase64Url()
                + ", environment=" + this.environment
                + ", signCount=" + this.signCount + '}';
    }
}
