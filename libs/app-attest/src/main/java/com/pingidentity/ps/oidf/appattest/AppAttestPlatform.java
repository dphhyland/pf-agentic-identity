/*
 * The operating system Apple says produced an App Attest attestation.
 */
package com.pingidentity.ps.oidf.appattest;

import java.security.cert.X509Certificate;

/**
 * The OS facts in extension {@code 1.2.840.113635.100.8.7} of the credential certificate: a SEQUENCE of
 * context-tagged values, of which three are read - {@code [1026]} the platform name ({@code macosx}),
 * {@code [1400]} the OS version and {@code [1403]} the build. Unlike the {@code platform} and
 * {@code os_version} a client sends with its enrolment, these are signed by Apple's attestation CA.
 *
 * <p>The tag numbers come from a real macOS 27.2 attestation; Apple has not documented the extension.
 *
 * @param name    {@code macosx} on a Mac; null when absent
 * @param version the OS version, e.g. {@code 27.2}; null when absent
 * @param build   the OS build, e.g. {@code 26B5091g}; null when absent
 */
public record AppAttestPlatform(String name, String version, String build) {

    public static final String OID = "1.2.840.113635.100.8.7";

    /** The name Apple gives macOS in this extension. */
    public static final String MACOS = "macosx";

    private static final int NAME = 1026;
    private static final int VERSION = 1400;
    private static final int BUILD = 1403;

    public boolean isMac() {
        return MACOS.equals(this.name);
    }

    /** {@code macosx 27.2 (26B5091g)}, leaving out what is absent. */
    public String describe() {
        StringBuilder out = new StringBuilder(this.name == null ? "unknown" : this.name);
        if (this.version != null) {
            out.append(' ').append(this.version);
        }
        if (this.build != null) {
            out.append(" (").append(this.build).append(')');
        }
        return out.toString();
    }

    /** The OS facts in a credential certificate; null when it carries none, or none this can read. */
    public static AppAttestPlatform from(X509Certificate credCert) {
        byte[] extension = credCert.getExtensionValue(OID);
        return extension == null ? null : parse(extension);
    }

    static AppAttestPlatform parse(byte[] extensionValue) {
        try {
            Der sequence = Der.read(Der.read(extensionValue).value());
            if (!sequence.is(Der.UNIVERSAL, Der.SEQUENCE)) {
                return null;
            }
            String name = null;
            String version = null;
            String build = null;
            for (Der field : sequence.children()) {
                if (field.tagClass() != Der.CONTEXT || !field.constructed()) {
                    continue;
                }
                Der value = field.only();
                if (!value.is(Der.UNIVERSAL, Der.OCTET_STRING)) {
                    continue;
                }
                switch (field.tag()) {
                    case NAME -> name = value.text();
                    case VERSION -> version = value.text();
                    case BUILD -> build = value.text();
                    default -> { }
                }
            }
            return name == null && version == null ? null : new AppAttestPlatform(name, version, build);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
