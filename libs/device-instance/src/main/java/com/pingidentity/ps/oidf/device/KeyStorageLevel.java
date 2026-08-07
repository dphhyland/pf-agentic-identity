/*
 * The attack-potential resistance of a key store, per OpenID4VCI Appendix D.
 */
package com.pingidentity.ps.oidf.device;

/**
 * The resistance levels OpenID4VCI 1.0 Appendix D defines for the {@code key_storage} and
 * {@code user_authentication} claims, mapping to ISO/IEC 18045 attack-potential (AVA_VAN).
 *
 * <p><strong>An Apple Secure Enclave is {@link #MODERATE} at best, never {@link #HIGH}.</strong> The
 * EUDI ARF distinguishes a WSCD — a tamper-resistant device meeting LoA High — from a <em>keystore</em>,
 * "a hardware-backed repository and service that generates, stores, and uses non-critical cryptographic
 * assets", and lists secure enclaves explicitly in that second category. Only a WSCD may assert
 * {@code iso_18045_high}.
 *
 * <p>Claiming higher than the hardware supports would be a false security assertion, and a downstream
 * policy trusting it would be relying on assurance nobody can demonstrate. See
 * {@code docs/claim-dictionary.md}.
 */
public enum KeyStorageLevel {

    /** AVA_VAN.5. Reserved for a certified WSCD. Not reachable by a Secure Enclave. */
    HIGH("iso_18045_high"),

    /** AVA_VAN.4. The honest ceiling for a hardware keystore such as the Secure Enclave. */
    MODERATE("iso_18045_moderate"),

    /** AVA_VAN.3. */
    ENHANCED_BASIC("iso_18045_enhanced-basic"),

    /** AVA_VAN.2. */
    BASIC("iso_18045_basic");

    private final String claimValue;

    KeyStorageLevel(String claimValue) {
        this.claimValue = claimValue;
    }

    /** The value as it appears in the attestation, e.g. {@code iso_18045_moderate}. */
    public String claimValue() {
        return this.claimValue;
    }

    public static KeyStorageLevel fromClaimValue(String value) {
        for (KeyStorageLevel level : values()) {
            if (level.claimValue.equals(value)) {
                return level;
            }
        }
        throw new IllegalArgumentException("not an OpenID4VCI Appendix D resistance level: " + value);
    }
}
