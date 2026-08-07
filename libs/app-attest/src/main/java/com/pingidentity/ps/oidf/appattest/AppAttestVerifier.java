/*
 * Verifies Apple App Attest attestation objects and assertions.
 */
package com.pingidentity.ps.oidf.appattest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies the two artefacts {@code DCAppAttestService} produces: the one-time <em>attestation</em>
 * from {@code attestKey}, and the per-request <em>assertion</em> from {@code generateAssertion}.
 *
 * <p>The attestation checks, in Apple's documented order:
 * <ol>
 *   <li>{@code fmt} is {@code apple-appattest};</li>
 *   <li>the {@code x5c} chain validates to Apple's App Attestation Root CA;</li>
 *   <li>the credCert's nonce extension (OID {@value #NONCE_OID}) equals
 *       {@code SHA-256(authenticatorData ‖ clientDataHash)};</li>
 *   <li>{@code SHA-256(attested public key)} equals the credential id;</li>
 *   <li>{@code rpIdHash} equals {@code SHA-256("<teamID>.<bundleID>")};</li>
 *   <li>the aaguid names an environment the configuration accepts;</li>
 *   <li>the signature counter is zero.</li>
 * </ol>
 *
 * <p>Every failure throws {@link AppAttestException} with a distinct {@code reason}, so an enrolment
 * refusal can be diagnosed from an audit log rather than guessed at.
 *
 * <p>Thread-safe and stateless; construct one per configuration and share it.
 */
public final class AppAttestVerifier {

    /** Apple's certificate extension carrying the attestation nonce. */
    public static final String NONCE_OID = "1.2.840.113635.100.8.2";

    private static final String EXPECTED_FORMAT = "apple-appattest";
    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());

    private final AppAttestConfig config;

    public AppAttestVerifier(AppAttestConfig config) {
        this.config = Objects.requireNonNull(config, "config");
    }

    /**
     * Verifies a one-time attestation object.
     *
     * @param attestationObject the raw CBOR from {@code DCAppAttestService.attestKey}
     * @param clientDataHash    the SHA-256 the app committed to. For this platform that is
     *                          {@code SHA-256(Secure Enclave JWK thumbprint ‖ server challenge)} —
     *                          the only thing tying App Attest's key to the key we actually care about
     * @param expectedKeyId     the key id the app claims, or null to skip the cross-check
     */
    public AppAttestAttestation verifyAttestation(byte[] attestationObject, byte[] clientDataHash,
                                                  byte[] expectedKeyId) throws AppAttestException {
        if (attestationObject == null || attestationObject.length == 0) {
            throw new AppAttestException(AppAttestException.MALFORMED, "no attestation object presented");
        }
        if (clientDataHash == null || clientDataHash.length == 0) {
            throw new AppAttestException(AppAttestException.MALFORMED, "no clientDataHash supplied");
        }

        JsonNode root = readCbor(attestationObject);
        String format = root.path("fmt").asText(null);
        if (!EXPECTED_FORMAT.equals(format)) {
            throw new AppAttestException(AppAttestException.UNSUPPORTED_FORMAT,
                    "attestation fmt is '" + format + "', expected '" + EXPECTED_FORMAT + "'");
        }

        JsonNode attStmt = root.path("attStmt");
        byte[] authDataBytes = binary(root, "authData");
        AuthenticatorData authData = AuthenticatorData.parse(authDataBytes);

        // 2. Chain to Apple's root. Pinned deliberately — the JVM trust store is not the question here.
        List<X509Certificate> chain = readChain(attStmt);
        validateChain(chain);
        X509Certificate credCert = chain.get(0);

        // 3. The nonce ties the attestation to this exact authData and this exact clientDataHash.
        byte[] expectedNonce = sha256(concat(authDataBytes, clientDataHash));
        byte[] presentedNonce = nonceFromCertificate(credCert);
        if (!MessageDigest.isEqual(expectedNonce, presentedNonce)) {
            throw new AppAttestException(AppAttestException.NONCE_MISMATCH,
                    "credCert nonce does not match SHA-256(authenticatorData ‖ clientDataHash)");
        }

        // 4. The credential id must be the hash of the attested key, so the key id cannot be swapped.
        if (!(credCert.getPublicKey() instanceof ECPublicKey attestedKey)) {
            throw new AppAttestException(AppAttestException.MALFORMED,
                    "credCert public key is not an EC key");
        }
        byte[] computedKeyId = sha256(uncompressedPoint(attestedKey));
        if (!authData.hasAttestedCredentialData()) {
            throw new AppAttestException(AppAttestException.MALFORMED,
                    "attestation authenticator data carries no attested credential data");
        }
        if (!MessageDigest.isEqual(computedKeyId, authData.credentialId())) {
            throw new AppAttestException(AppAttestException.KEY_ID_MISMATCH,
                    "credentialId is not SHA-256 of the attested public key");
        }
        if (expectedKeyId != null && !MessageDigest.isEqual(computedKeyId, expectedKeyId)) {
            throw new AppAttestException(AppAttestException.KEY_ID_MISMATCH,
                    "attested key id does not match the key id the client claimed");
        }

        // 5. The attestation is for OUR app, not merely some genuine Apple app.
        byte[] expectedRpIdHash = sha256(this.config.appId().getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedRpIdHash, authData.rpIdHash())) {
            throw new AppAttestException(AppAttestException.APP_ID_MISMATCH,
                    "rpIdHash does not match SHA-256 of the configured App ID");
        }

        // 6. Development attestations must have been opted into, never accepted by default.
        AppAttestEnvironment environment = authData.environment();
        if (environment == null) {
            throw new AppAttestException(AppAttestException.ENVIRONMENT_NOT_ACCEPTED,
                    "aaguid is neither 'appattest' nor 'appattestdevelop'");
        }
        if (!this.config.accepts(environment)) {
            throw new AppAttestException(AppAttestException.ENVIRONMENT_NOT_ACCEPTED,
                    "attestation is from the " + environment + " environment, which this verifier "
                            + "is not configured to accept");
        }

        // 7. A fresh attestation always starts at zero.
        if (authData.signCount() != 0L) {
            throw new AppAttestException(AppAttestException.BAD_COUNTER,
                    "attestation signCount is " + authData.signCount() + ", expected 0");
        }

        byte[] receipt = attStmt.hasNonNull("receipt") ? binary(attStmt, "receipt") : null;
        return new AppAttestAttestation(computedKeyId, attestedKey, environment, authData.signCount(), receipt);
    }

    /**
     * Verifies a per-request assertion against a previously attested key.
     *
     * @param assertionObject  the raw CBOR from {@code DCAppAttestService.generateAssertion}
     * @param clientDataHash   the SHA-256 of whatever the app committed to for this request
     * @param attestedKey      the key from the enrolment-time {@link AppAttestAttestation}
     * @param lastSignCount    the highest counter seen for this key; the assertion must exceed it
     * @return the new counter value, to persist
     */
    public long verifyAssertion(byte[] assertionObject, byte[] clientDataHash,
                                ECPublicKey attestedKey, long lastSignCount) throws AppAttestException {
        Objects.requireNonNull(attestedKey, "attestedKey");
        if (assertionObject == null || assertionObject.length == 0) {
            throw new AppAttestException(AppAttestException.MALFORMED, "no assertion object presented");
        }
        JsonNode root = readCbor(assertionObject);
        byte[] signature = binary(root, "signature");
        byte[] authDataBytes = binary(root, "authenticatorData");
        AuthenticatorData authData = AuthenticatorData.parse(authDataBytes);

        byte[] expectedRpIdHash = sha256(this.config.appId().getBytes(StandardCharsets.UTF_8));
        if (!MessageDigest.isEqual(expectedRpIdHash, authData.rpIdHash())) {
            throw new AppAttestException(AppAttestException.APP_ID_MISMATCH,
                    "assertion rpIdHash does not match the configured App ID");
        }

        byte[] signed = concat(authDataBytes, clientDataHash);
        try {
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initVerify(attestedKey);
            ecdsa.update(signed);
            if (!ecdsa.verify(signature)) {
                throw new AppAttestException(AppAttestException.BAD_SIGNATURE,
                        "assertion signature did not verify under the attested key");
            }
        } catch (AppAttestException e) {
            throw e;
        } catch (Exception e) {
            throw new AppAttestException(AppAttestException.BAD_SIGNATURE,
                    "assertion signature could not be verified", e);
        }

        if (authData.signCount() <= lastSignCount) {
            throw new AppAttestException(AppAttestException.COUNTER_NOT_ADVANCED,
                    "assertion signCount " + authData.signCount() + " did not advance beyond "
                            + lastSignCount + " — replay");
        }
        return authData.signCount();
    }

    // ---- internals ---------------------------------------------------------------------------

    private static JsonNode readCbor(byte[] bytes) throws AppAttestException {
        JsonNode node;
        try {
            node = CBOR.readTree(bytes);
        } catch (Exception e) {
            throw new AppAttestException(AppAttestException.MALFORMED, "not well-formed CBOR", e);
        }
        // Jackson's CBOR reader is lenient — arbitrary bytes often decode to *some* scalar rather than
        // throwing. Both artefacts are CBOR maps, so anything else is malformed input, not a bad format.
        if (node == null || !node.isObject()) {
            throw new AppAttestException(AppAttestException.MALFORMED,
                    "expected a CBOR map at the top level");
        }
        return node;
    }

    private static byte[] binary(JsonNode parent, String field) throws AppAttestException {
        JsonNode node = parent.get(field);
        if (node == null || node.isNull()) {
            throw new AppAttestException(AppAttestException.MALFORMED, "missing '" + field + "'");
        }
        try {
            return node.binaryValue();
        } catch (Exception e) {
            throw new AppAttestException(AppAttestException.MALFORMED,
                    "'" + field + "' is not a CBOR byte string", e);
        }
    }

    private static List<X509Certificate> readChain(JsonNode attStmt) throws AppAttestException {
        JsonNode x5c = attStmt.path("x5c");
        if (!x5c.isArray() || x5c.isEmpty()) {
            throw new AppAttestException(AppAttestException.MALFORMED, "attStmt.x5c is missing or empty");
        }
        List<X509Certificate> chain = new ArrayList<>();
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            for (JsonNode entry : x5c) {
                chain.add((X509Certificate) factory.generateCertificate(
                        new java.io.ByteArrayInputStream(entry.binaryValue())));
            }
        } catch (Exception e) {
            throw new AppAttestException(AppAttestException.MALFORMED, "attStmt.x5c is not a certificate chain", e);
        }
        return chain;
    }

    private void validateChain(List<X509Certificate> chain) throws AppAttestException {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            PKIXParameters params = new PKIXParameters(
                    Set.of(new TrustAnchor(this.config.trustRoot(), null)));
            // App Attest certificates carry no CRL or OCSP pointers; revocation checking would fail closed
            // on every valid attestation, so it is disabled deliberately rather than by oversight.
            params.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX")
                    .validate(factory.generateCertPath(chain), params);
        } catch (Exception e) {
            throw new AppAttestException(AppAttestException.UNTRUSTED_CHAIN,
                    "x5c did not validate to the configured App Attest root: " + e.getMessage(), e);
        }
    }

    /**
     * Reads the 32-byte nonce out of the credCert. The extension value is a DER OCTET STRING wrapping
     * {@code SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } }}.
     */
    static byte[] nonceFromCertificate(X509Certificate credCert) throws AppAttestException {
        byte[] extension = credCert.getExtensionValue(NONCE_OID);
        if (extension == null) {
            throw new AppAttestException(AppAttestException.NONCE_MISMATCH,
                    "credCert carries no " + NONCE_OID + " nonce extension");
        }
        try {
            DerReader outer = new DerReader(extension);
            byte[] inner = outer.readValue(0x04);                 // the wrapping OCTET STRING
            DerReader sequence = new DerReader(inner);
            byte[] seqBody = sequence.readValue(0x30);            // SEQUENCE
            DerReader tagged = new DerReader(seqBody);
            byte[] taggedBody = tagged.readValue(0xA1);           // [1] EXPLICIT
            DerReader octet = new DerReader(taggedBody);
            return octet.readValue(0x04);                         // OCTET STRING — the nonce
        } catch (Exception e) {
            throw new AppAttestException(AppAttestException.NONCE_MISMATCH,
                    "credCert nonce extension is malformed", e);
        }
    }

    /** The X9.62 uncompressed point, {@code 0x04 ‖ X ‖ Y}, which is what Apple hashes into the key id. */
    static byte[] uncompressedPoint(ECPublicKey key) {
        int fieldSize = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
        ECPoint point = key.getW();
        byte[] out = new byte[1 + 2 * fieldSize];
        out[0] = 0x04;
        writeFixed(point.getAffineX(), out, 1, fieldSize);
        writeFixed(point.getAffineY(), out, 1 + fieldSize, fieldSize);
        return out;
    }

    private static void writeFixed(BigInteger value, byte[] target, int offset, int length) {
        byte[] bytes = value.toByteArray();
        // BigInteger may prepend a sign byte, or be shorter than the field — normalise to fixed width.
        int from = Math.max(0, bytes.length - length);
        int count = bytes.length - from;
        System.arraycopy(bytes, from, target, offset + length - count, count);
    }

    private static byte[] sha256(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** Just enough DER to walk the nonce extension — no BouncyCastle dependency for four tags. */
    private static final class DerReader {
        private final byte[] buffer;
        private int position;

        DerReader(byte[] buffer) {
            this.buffer = buffer;
        }

        /** Reads one TLV, asserting the tag, and returns its value bytes. */
        byte[] readValue(int expectedTag) {
            int tag = this.buffer[this.position++] & 0xFF;
            if (tag != expectedTag) {
                throw new IllegalArgumentException(
                        String.format("expected DER tag 0x%02X but found 0x%02X", expectedTag, tag));
            }
            int length = this.buffer[this.position++] & 0xFF;
            if ((length & 0x80) != 0) {
                int lengthBytes = length & 0x7F;
                if (lengthBytes == 0 || lengthBytes > 4) {
                    throw new IllegalArgumentException("unsupported DER length encoding");
                }
                length = 0;
                for (int i = 0; i < lengthBytes; i++) {
                    length = (length << 8) | (this.buffer[this.position++] & 0xFF);
                }
            }
            if (length < 0 || this.position + length > this.buffer.length) {
                throw new IllegalArgumentException("DER length runs past the end of the buffer");
            }
            byte[] value = Arrays.copyOfRange(this.buffer, this.position, this.position + length);
            this.position += length;
            return value;
        }
    }

    /** The configuration this verifier enforces. */
    public AppAttestConfig config() {
        return this.config;
    }

    /** Unmodifiable view of Apple's documented attestation format name. */
    public static List<String> supportedFormats() {
        return Collections.singletonList(EXPECTED_FORMAT);
    }
}
