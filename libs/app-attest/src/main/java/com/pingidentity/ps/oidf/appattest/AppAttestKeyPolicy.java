/*
 * The access-control list Apple writes into a macOS App Attest credential certificate.
 */
package com.pingidentity.ps.oidf.appattest;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

/**
 * The conditions the Secure Enclave enforces on the App Attest key, read from extension
 * {@code 1.2.840.113635.100.8.6} of the credential certificate. Apple adds it from macOS 27: "a key
 * access control property, known as the ACL Blob OID ... the security conditions associated with the App
 * Attest key, that were enforced by the Secure Enclave when the attestation was collected". On macOS every
 * App Attest key carries "a policy that requires full security mode and System Integrity Protection"
 * (WWDC26 session 201).
 *
 * <p><strong>Apple has not published the format.</strong> This reads the shape of a real attestation from
 * macOS 27.2 on a Mac in Full Security with SIP on:
 *
 * <pre>
 * SEQUENCE { [3] { OCTET STRING { SEQUENCE {
 *     UTF8String "11",                                      -- version
 *     SEQUENCE {
 *       SEQUENCE { "ok",   [1] { BOOLEAN TRUE } },          -- operations always allowed
 *       SEQUENCE { "oa",   [1] { BOOLEAN TRUE } },
 *       SEQUENCE { "odel", [1] { BOOLEAN TRUE } },
 *       SEQUENCE { "osgn", [0] { "rsec" }, SEQUENCE { [6] { INTEGER 1 } } } } } } } }
 *                                                           -- signing gated by a requirement
 * </pre>
 *
 * Signing ({@code osgn}) is the only gated operation there, and its requirement {@code rsec} is read as
 * Apple's security-policy condition. That reading is provisional: it matches Apple's description and one
 * Mac, and should be checked against Apple's documentation when it appears, and against a Mac with
 * reduced security.
 *
 * @param version    the policy's version string ({@code "11"} on macOS 27.2)
 * @param operations each operation's condition, in the order Apple lists them
 */
public record AppAttestKeyPolicy(String version, Map<String, Operation> operations) {

    public static final String OID = "1.2.840.113635.100.8.6";

    /** Signing with the App Attest key: what produces every attestation and assertion. */
    public static final String SIGN = "osgn";

    /** The requirement Apple gates signing with on macOS: read as Full Security and SIP. */
    public static final String SECURITY_REQUIREMENT = "rsec";

    /**
     * One operation's condition.
     *
     * @param alwaysAllowed true for {@code [1] TRUE}: no condition
     * @param requirement   the named requirement gating the operation, or null
     * @param parameters    the requirement's parameters by context tag ({@code [6] 1} for {@code rsec})
     */
    public record Operation(String name, boolean alwaysAllowed, String requirement, Map<Integer, Long> parameters) {
        public Operation {
            parameters = parameters == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
        }
    }

    public AppAttestKeyPolicy {
        operations = operations == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(operations));
    }

    /** True when the Secure Enclave will only sign with this key under Apple's security requirement. */
    public boolean signingRequiresSecurity() {
        Operation sign = this.operations.get(SIGN);
        return sign != null && SECURITY_REQUIREMENT.equals(sign.requirement());
    }

    /** A compact form for the evidence a bank records: {@code "osgn:rsec(6=1) ok oa odel"}. */
    public String summary() {
        StringJoiner out = new StringJoiner(" ");
        for (Operation op : this.operations.values()) {
            if (op.requirement() == null) {
                out.add(op.alwaysAllowed() ? op.name() : op.name() + ":denied");
                continue;
            }
            StringJoiner params = new StringJoiner(",", "(", ")");
            op.parameters().forEach((tag, value) -> params.add(tag + "=" + value));
            out.add(op.name() + ":" + op.requirement() + (op.parameters().isEmpty() ? "" : params.toString()));
        }
        return out.toString();
    }

    /** The policy in a credential certificate; null when it carries none, or one this cannot read. */
    public static AppAttestKeyPolicy from(X509Certificate credCert) {
        byte[] extension = credCert.getExtensionValue(OID);
        return extension == null ? null : parse(extension);
    }

    /**
     * Reads the extension value as {@link X509Certificate#getExtensionValue} returns it: an OCTET STRING
     * wrapping the DER above. Null when the bytes are not that shape - the caller decides what an
     * unreadable policy means, and for a Mac it means "not proven".
     */
    static AppAttestKeyPolicy parse(byte[] extensionValue) {
        try {
            Der wrapped = Der.read(extensionValue);
            Der outer = Der.read(wrapped.value());
            if (!outer.is(Der.UNIVERSAL, Der.SEQUENCE)) {
                return null;
            }
            Der tagged = outer.only();
            if (!tagged.is(Der.CONTEXT, 3)) {
                return null;
            }
            Der body = Der.read(tagged.only().value());
            List<Der> parts = body.children();
            if (parts.size() < 2) {
                return null;
            }
            String version = parts.get(0).text();
            Map<String, Operation> operations = new LinkedHashMap<>();
            for (Der entry : parts.get(1).children()) {
                List<Der> fields = entry.children();
                String name = fields.get(0).text();
                boolean always = false;
                String requirement = null;
                Map<Integer, Long> parameters = new LinkedHashMap<>();
                for (Der field : fields.subList(1, fields.size())) {
                    if (field.is(Der.CONTEXT, 1)) {
                        always = field.only().bool();
                    } else if (field.is(Der.CONTEXT, 0)) {
                        requirement = field.only().text();
                    } else if (field.is(Der.UNIVERSAL, Der.SEQUENCE)) {
                        for (Der parameter : field.children()) {
                            parameters.put(parameter.tag(), parameter.only().integer());
                        }
                    }
                }
                operations.put(name, new Operation(name, always, requirement, parameters));
            }
            return new AppAttestKeyPolicy(version, operations);
        } catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            return null;
        }
    }
}
