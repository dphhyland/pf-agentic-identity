/*
 * Builds synthetic, Apple-shaped App Attest artefacts so the verifier is testable without a device.
 */
package com.pingidentity.ps.oidf.appattest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Mints a self-signed root, an intermediate, and a leaf credCert carrying Apple's nonce extension,
 * then assembles a CBOR attestation object around them.
 *
 * <p>This is a <em>synthetic</em> chain, not an Apple one. It exercises every check the verifier makes
 * — chain validation, nonce binding, key-id derivation, rpIdHash, aaguid, counter — against a root the
 * test controls. What it deliberately cannot prove is that Apple's real objects parse: only a physical
 * device can, and that gap is recorded in {@code docs/unverified.md} and closed in milestone 1's
 * on-device acceptance test.
 */
final class AppAttestFixtures {

    static final String TEAM_ID = "ABCDE12345";
    static final String BUNDLE_ID = "com.example.agent";

    private static final ObjectMapper CBOR = new ObjectMapper(new CBORFactory());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final KeyPair rootKey;
    private final X509Certificate rootCert;

    AppAttestFixtures() throws Exception {
        this.rootKey = generateEcKeyPair();
        this.rootCert = selfSignedRoot(this.rootKey);
    }

    X509Certificate rootCertificate() {
        return this.rootCert;
    }

    /** A config trusting this fixture's root rather than Apple's, accepting the given environments. */
    AppAttestConfig config(java.util.Set<AppAttestEnvironment> accepted) {
        return AppAttestConfig.withTrustRoot(TEAM_ID, BUNDLE_ID, accepted, this.rootCert);
    }

    /** The default happy-path build: production environment, counter 0, correct everything. */
    Attestation attestation(byte[] clientDataHash) throws Exception {
        return attestation(clientDataHash, AppAttestEnvironment.PRODUCTION, 0L, TEAM_ID + "." + BUNDLE_ID, true);
    }

    /**
     * Builds an attestation object with each dimension independently spoilable, so negative tests
     * change exactly one thing.
     *
     * @param bindNonceCorrectly when false, the credCert commits to a different nonce
     */
    Attestation attestation(byte[] clientDataHash, AppAttestEnvironment environment, long signCount,
                            String appId, boolean bindNonceCorrectly) throws Exception {
        KeyPair attestedKey = generateEcKeyPair();
        byte[] keyId = sha256(AppAttestVerifier.uncompressedPoint((ECPublicKey) attestedKey.getPublic()));

        byte[] authData = authenticatorData(appId, environment, signCount, keyId);
        byte[] nonce = bindNonceCorrectly
                ? sha256(concat(authData, clientDataHash))
                : sha256("a different commitment entirely".getBytes(java.nio.charset.StandardCharsets.UTF_8));

        X509Certificate credCert = leafWithNonce(attestedKey, this.rootKey, this.rootCert, nonce);

        ObjectNode root = CBOR.createObjectNode();
        root.put("fmt", "apple-appattest");
        ObjectNode attStmt = root.putObject("attStmt");
        ArrayNode x5c = attStmt.putArray("x5c");
        x5c.add(credCert.getEncoded());
        x5c.add(this.rootCert.getEncoded());
        attStmt.put("receipt", "synthetic-receipt".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        root.put("authData", authData);

        return new Attestation(CBOR.writeValueAsBytes(root), keyId, attestedKey, authData);
    }

    /** A CBOR assertion signed by a previously attested key. */
    byte[] assertion(KeyPair attestedKey, byte[] clientDataHash, long signCount, String appId) throws Exception {
        byte[] authData = assertionAuthenticatorData(appId, signCount);
        Signature ecdsa = Signature.getInstance("SHA256withECDSA");
        ecdsa.initSign(attestedKey.getPrivate());
        ecdsa.update(concat(authData, clientDataHash));
        byte[] signature = ecdsa.sign();

        ObjectNode root = CBOR.createObjectNode();
        root.put("signature", signature);
        root.put("authenticatorData", authData);
        return CBOR.writeValueAsBytes(root);
    }

    /** Attestation-form authenticator data: rpIdHash ‖ flags ‖ counter ‖ aaguid ‖ credIdLen ‖ credId. */
    private static byte[] authenticatorData(String appId, AppAttestEnvironment environment,
                                            long signCount, byte[] credentialId) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(appId.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        out.write(0x40);                                   // AT flag: attested credential data present
        out.write(intToBytes((int) signCount));
        out.write(environment.aaguid());
        out.write(new byte[]{(byte) (credentialId.length >> 8), (byte) credentialId.length});
        out.write(credentialId);
        return out.toByteArray();
    }

    /** Assertion-form authenticator data: no attested credential data, so it stops after the counter. */
    private static byte[] assertionAuthenticatorData(String appId, long signCount) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(sha256(appId.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        out.write(0x00);
        out.write(intToBytes((int) signCount));
        return out.toByteArray();
    }

    private static X509Certificate selfSignedRoot(KeyPair key) throws Exception {
        X500Name name = new X500Name("CN=Synthetic App Attest Root, O=Test");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.ONE, notBefore(), notAfter(), name, key.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return convert(builder, key);
    }

    /** The leaf, carrying the nonce in Apple's SEQUENCE { [1] { OCTET STRING } } shape. */
    private static X509Certificate leafWithNonce(KeyPair subject, KeyPair issuerKey,
                                                 X509Certificate issuer, byte[] nonce) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(2), notBefore(), notAfter(),
                new X500Name("CN=Synthetic credCert, O=Test"), subject.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new DERTaggedObject(true, 1, new DEROctetString(nonce)));
        builder.addExtension(new ASN1ObjectIdentifier(AppAttestVerifier.NONCE_OID), false,
                new DERSequence(vector));

        return convert(builder, issuerKey);
    }

    private static X509Certificate convert(JcaX509v3CertificateBuilder builder, KeyPair signingKey)
            throws Exception {
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA")
                        .setProvider("BC").build(signingKey.getPrivate())));
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static Date notBefore() {
        return Date.from(Instant.now().minusSeconds(3600));
    }

    private static Date notAfter() {
        return Date.from(Instant.now().plusSeconds(86400));
    }

    private static byte[] intToBytes(int value) {
        return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    static byte[] sha256(byte[] input) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(input);
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    /** A built attestation plus the pieces a test needs to assert against it. */
    record Attestation(byte[] cbor, byte[] keyId, KeyPair attestedKey, byte[] authData) {
    }
}
