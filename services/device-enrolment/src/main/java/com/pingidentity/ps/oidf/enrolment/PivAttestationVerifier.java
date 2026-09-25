/*
 * Verifies a YubiKey PIV key attestation: the evidence that a key was GENERATED on a genuine YubiKey
 * and cannot leave it. This is the one hardware backend in the Mac connector experiment whose key
 * storage the attester can actually verify rather than take on trust.
 */
package com.pingidentity.ps.oidf.enrolment;

import com.pingidentity.ps.oidf.jose.Jwks;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;

/**
 * YubiKey PIV attestation (https://developers.yubico.com/PIV/Introduction/PIV_attestation.html).
 *
 * <p>The chain is: the slot's attestation certificate, signed by the device's F9 attestation
 * certificate, signed by Yubico's PIV CA - {@code yubico-piv-ca-1.pem} for firmware before 5.7.4, or
 * {@code yubico-ca-1.pem} via {@code yubico-intermediate.pem} from 5.7.4. The roots are pinned by the
 * deployment ({@code YUBICO_PIV_ROOTS}); nothing here fetches them.
 *
 * <p>Signatures are chained manually rather than through PKIX path validation, the way Yubico's own
 * {@code openssl verify} instructions do it: F9 and slot certificates predate the constraint extensions
 * a strict PKIX validator insists on, so PKIX rejects genuine chains.
 *
 * <p>What it proves: the key was generated on-device on a genuine YubiKey (attestation is impossible for
 * an imported key), with the PIN and touch policies the certificate records. What it cannot prove on its
 * own: freshness - the certificate carries no nonce, so possession is proven separately, by a proof
 * signed with the key over the enrolment challenge.
 */
public final class PivAttestationVerifier {

    public static final String OID_FIRMWARE = "1.3.6.1.4.1.41482.3.3";
    public static final String OID_SERIAL = "1.3.6.1.4.1.41482.3.7";
    public static final String OID_POLICY = "1.3.6.1.4.1.41482.3.8";
    public static final String OID_FORM_FACTOR = "1.3.6.1.4.1.41482.3.9";
    public static final String OID_FIPS = "1.3.6.1.4.1.41482.3.10";
    public static final String OID_CSPN = "1.3.6.1.4.1.41482.3.11";

    private final List<X509Certificate> roots;

    public PivAttestationVerifier(List<X509Certificate> roots) {
        if (roots == null || roots.isEmpty()) {
            throw new IllegalArgumentException("at least one pinned Yubico root is required");
        }
        this.roots = List.copyOf(roots);
    }

    /** Roots from a PEM bundle (one or more certificates). */
    public static PivAttestationVerifier fromPemFile(Path bundle) throws IOException {
        try {
            return new PivAttestationVerifier(parseCertificates(Files.readString(bundle)));
        } catch (CertificateException e) {
            throw new IOException("unreadable Yubico root bundle " + bundle + ": " + e.getMessage(), e);
        }
    }

    /**
     * Verifies {@code slotPem} (leaf) -> {@code f9Pem} -> {@code intermediatesPem}... -> a pinned root, and
     * that the attested key is {@code expectedJwk}.
     */
    public Attested verify(String slotPem, String f9Pem, List<String> intermediatesPem, Map<String, Object> expectedJwk)
            throws EnrolmentException {
        List<X509Certificate> chain = new ArrayList<>();
        try {
            chain.add(single(slotPem, "slot attestation certificate"));
            chain.add(single(f9Pem, "F9 attestation certificate"));
            if (intermediatesPem != null) {
                for (String pem : intermediatesPem) {
                    chain.addAll(parseCertificates(pem));
                }
            }
        } catch (CertificateException e) {
            throw EnrolmentException.invalidAttestation("PIV attestation certificates are not parseable: " + e.getMessage());
        }
        verifyChain(chain);

        X509Certificate slot = chain.get(0);
        try {
            slot.checkValidity();
        } catch (CertificateException e) {
            throw EnrolmentException.invalidAttestation("PIV slot attestation certificate is outside its validity period");
        }
        // The attested key must be the key being enrolled - otherwise a genuine attestation of SOME key
        // on SOME YubiKey would vouch for a software key.
        String attestedJkt;
        String expectedJkt;
        try {
            PublicJsonWebKey attested = PublicJsonWebKey.Factory.newPublicJwk(slot.getPublicKey());
            attestedJkt = Jwks.thumbprint(attested.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
            expectedJkt = Jwks.thumbprint(expectedJwk);
        } catch (Exception e) {
            throw EnrolmentException.invalidAttestation("PIV attested key could not be compared: " + e.getMessage());
        }
        if (!attestedJkt.equals(expectedJkt)) {
            throw EnrolmentException.invalidAttestation("the PIV attestation is for a different key than the one being enrolled");
        }

        byte[] firmware = rawExtension(slot, OID_FIRMWARE);
        byte[] serialDer = rawExtension(slot, OID_SERIAL);
        byte[] policy = rawExtension(slot, OID_POLICY);
        byte[] formFactor = rawExtension(slot, OID_FORM_FACTOR);
        if (serialDer == null || policy == null || policy.length != 2) {
            throw EnrolmentException.invalidAttestation("PIV attestation lacks the Yubico serial or policy extension");
        }
        return new Attested(
                derInteger(serialDer).longValue(),
                firmware != null && firmware.length == 3
                        ? (firmware[0] & 0xFF) + "." + (firmware[1] & 0xFF) + "." + (firmware[2] & 0xFF) : null,
                PinPolicy.of(policy[0]),
                TouchPolicy.of(policy[1]),
                formFactor != null && formFactor.length == 1 ? formFactor[0] & 0xFF : -1,
                slot.getExtensionValue(OID_FIPS) != null,
                slot.getExtensionValue(OID_CSPN) != null);
    }

    private void verifyChain(List<X509Certificate> chain) throws EnrolmentException {
        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            PublicKey issuerKey;
            if (i + 1 < chain.size()) {
                issuerKey = chain.get(i + 1).getPublicKey();
            } else {
                X509Certificate root = this.roots.stream()
                        .filter(r -> r.getSubjectX500Principal().equals(cert.getIssuerX500Principal()))
                        .findFirst().orElse(null);
                if (root == null) {
                    throw EnrolmentException.invalidAttestation("PIV attestation does not chain to a pinned Yubico root (issuer "
                            + cert.getIssuerX500Principal().getName() + ")");
                }
                issuerKey = root.getPublicKey();
            }
            try {
                cert.verify(issuerKey);
            } catch (Exception e) {
                throw EnrolmentException.invalidAttestation("PIV attestation chain is broken at position " + i + ": " + e.getMessage());
            }
        }
    }

    /** {@code getExtensionValue} returns the DER OCTET STRING wrapping extnValue; unwrap it once. */
    private static byte[] rawExtension(X509Certificate cert, String oid) throws EnrolmentException {
        byte[] wrapped = cert.getExtensionValue(oid);
        if (wrapped == null) {
            return null;
        }
        if (wrapped.length < 2 || wrapped[0] != 0x04) {
            throw EnrolmentException.invalidAttestation("PIV extension " + oid + " is not an OCTET STRING");
        }
        int[] header = derLength(wrapped, 1);
        return Arrays.copyOfRange(wrapped, header[1], header[1] + header[0]);
    }

    private static BigInteger derInteger(byte[] der) throws EnrolmentException {
        if (der.length < 3 || der[0] != 0x02) {
            throw EnrolmentException.invalidAttestation("PIV serial is not a DER INTEGER");
        }
        int[] header = derLength(der, 1);
        return new BigInteger(1, Arrays.copyOfRange(der, header[1], header[1] + header[0]));
    }

    /** Returns {length, offsetOfContent} for the DER length starting at {@code at}. */
    private static int[] derLength(byte[] der, int at) {
        int first = der[at] & 0xFF;
        if (first < 0x80) {
            return new int[]{first, at + 1};
        }
        int n = first & 0x7F;
        int length = 0;
        for (int k = 0; k < n; k++) {
            length = (length << 8) | (der[at + 1 + k] & 0xFF);
        }
        return new int[]{length, at + 1 + n};
    }

    private static X509Certificate single(String pem, String what) throws CertificateException {
        List<X509Certificate> certs = parseCertificates(Objects.requireNonNull(pem, what));
        if (certs.size() != 1) {
            throw new CertificateException(what + " must be exactly one certificate");
        }
        return certs.get(0);
    }

    static List<X509Certificate> parseCertificates(String pem) throws CertificateException {
        Collection<? extends java.security.cert.Certificate> parsed = CertificateFactory.getInstance("X.509")
                .generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
        List<X509Certificate> out = new ArrayList<>();
        for (java.security.cert.Certificate c : parsed) {
            out.add((X509Certificate) c);
        }
        if (out.isEmpty()) {
            throw new CertificateException("no certificate found");
        }
        return out;
    }

    public enum PinPolicy {
        DEFAULT, NEVER, ONCE, ALWAYS, MATCH_ONCE, MATCH_ALWAYS, UNKNOWN;

        static PinPolicy of(byte b) {
            return switch (b) {
                case 0x00 -> DEFAULT;
                case 0x01 -> NEVER;
                case 0x02 -> ONCE;
                case 0x03 -> ALWAYS;
                case 0x04 -> MATCH_ONCE;
                case 0x05 -> MATCH_ALWAYS;
                default -> UNKNOWN;
            };
        }
    }

    public enum TouchPolicy {
        DEFAULT, NEVER, ALWAYS, CACHED, UNKNOWN;

        static TouchPolicy of(byte b) {
            return switch (b) {
                case 0x00 -> DEFAULT;
                case 0x01 -> NEVER;
                case 0x02 -> ALWAYS;
                case 0x03 -> CACHED;
                default -> UNKNOWN;
            };
        }
    }

    /** What a verified PIV attestation says about the key and the token it lives on. */
    public record Attested(long serial, String firmware, PinPolicy pinPolicy, TouchPolicy touchPolicy,
                           int formFactor, boolean fips, boolean cspn) {

        /** Every use of the key needs the PIN or a touch: someone was at the token for each signature. */
        public boolean userPresencePerUse() {
            return this.touchPolicy == TouchPolicy.ALWAYS
                    || this.pinPolicy == PinPolicy.ALWAYS || this.pinPolicy == PinPolicy.MATCH_ALWAYS;
        }
    }
}
