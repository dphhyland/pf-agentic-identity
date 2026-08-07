/*
 * Which Apple App Attest environment produced an attestation, as named by its aaguid.
 */
package com.pingidentity.ps.oidf.appattest;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The App Attest environment, read from the authenticator data's 16-byte {@code aaguid}. Apple uses
 * {@code appattest} for production and {@code appattestdevelop} for development, both ASCII, the
 * shorter one zero-padded to 16 bytes.
 *
 * <p>This distinction is a security control, not a label. A development attestation is produced
 * against Apple's development attestation service and does not carry the same assurance as a
 * production one. A verifier that accepts both by default is a hole that survives into production, so
 * {@link AppAttestConfig} requires the development environment to be opted into explicitly.
 */
public enum AppAttestEnvironment {

    /** Production: aaguid is {@code appattest} padded with zero bytes to 16. */
    PRODUCTION("appattest"),

    /** Development: aaguid is exactly the 16 ASCII bytes {@code appattestdevelop}. */
    DEVELOPMENT("appattestdevelop");

    private final byte[] aaguid;

    AppAttestEnvironment(String label) {
        byte[] padded = new byte[16];
        byte[] ascii = label.getBytes(StandardCharsets.US_ASCII);
        if (ascii.length > 16) {
            throw new IllegalArgumentException("aaguid label exceeds 16 bytes: " + label);
        }
        System.arraycopy(ascii, 0, padded, 0, ascii.length);
        this.aaguid = padded;
    }

    /** The 16-byte aaguid this environment stamps into authenticator data. */
    public byte[] aaguid() {
        return this.aaguid.clone();
    }

    /** The environment matching an aaguid, or null if it is neither of Apple's. */
    public static AppAttestEnvironment fromAaguid(byte[] candidate) {
        for (AppAttestEnvironment env : values()) {
            if (Arrays.equals(env.aaguid, candidate)) {
                return env;
            }
        }
        return null;
    }
}
