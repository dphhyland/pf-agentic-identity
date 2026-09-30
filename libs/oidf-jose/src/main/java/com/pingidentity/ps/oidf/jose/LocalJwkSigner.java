/*
 * JwsSigner backed by an in-process private JWK (dev/demo attester key).
 */
package com.pingidentity.ps.oidf.jose;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.LinkedHashMap;
import java.util.Map;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.EcdsaUsingShaAlgorithm;
import org.jose4j.lang.JoseException;

/**
 * {@link JwsSigner} that signs with an inline private JWK held in this JVM. This is the dev/demo
 * counterpart to {@link OpenBaoTransitSigner} — simple to configure (the attester key sits in the
 * client's {@code attestation_signing_jwk} extended property) but the private key lives in-process, so
 * production deployments should prefer the vault-backed signer.
 *
 * <p>What it accepts is RFC 7518's, checked when the signer is built rather than when it first signs:
 *
 * <ul>
 *   <li>EC keys on the three curves RFC 7518 §3.4 defines - "ECDSA with the P-256 curve and the SHA-256
 *       cryptographic hash function, ECDSA with the P-384 curve and the SHA-384 hash function, and ECDSA with the P-521
 *       curve and the SHA-512 hash function" - as {@code ES256}, {@code ES384} and {@code ES512}. A declared {@code alg}
 *       must be the one for the key's curve: RFC 8725 §3.1, "each key MUST be used with exactly one algorithm".</li>
 *   <li>RSA keys of 2048 bits or more - RFC 7518 §3.3 and §3.5 each say "A key of size 2048 bits or larger MUST be
 *       used" - as {@code RS256}/{@code RS384}/{@code RS512} (§3.3) or {@code PS256}/{@code PS384}/{@code PS512}
 *       (§3.5: MGF1 with the same hash, and a salt the size of the hash output). With no {@code alg}, {@code RS256}.</li>
 * </ul>
 *
 * <p>Emits the raw JWS signature bytes RFC 7518 requires: fixed-width {@code r||s} for ECDSA (§3.4), the raw
 * signature for RSA.
 */
public final class LocalJwkSigner implements JwsSigner {

    /** RFC 7518 §3.3 and §3.5: the smallest RSA modulus, in bits. */
    public static final int MIN_RSA_BITS = 2048;

    private static final java.util.Set<String> RSA_ALGORITHMS = java.util.Set.of("RS256", "RS384", "RS512", "PS256", "PS384", "PS512");

    private final PrivateKey privateKey;
    private final String algorithm;
    private final String jcaAlgorithm;
    private final PSSParameterSpec pss; // null unless PS256/384/512
    private final int ecConcatLength; // 0 for RSA
    private final String keyId;
    private final Map<String, Object> publicJwk;

    /**
     * @throws IllegalArgumentException for a JWK that is not a private EC or RSA key, an EC key off the three curves or
     *     declared with another curve's {@code alg}, an RSA key under {@value #MIN_RSA_BITS} bits, or an {@code alg}
     *     this signer does not produce. The message names the rule, never the key.
     */
    public LocalJwkSigner(Map<String, Object> privateJwk) {
        PublicJsonWebKey jwk;
        try {
            jwk = PublicJsonWebKey.Factory.newPublicJwk(privateJwk);
        } catch (JoseException e) {
            throw new IllegalArgumentException("attestation_signing_jwk is not a valid JWK", e);
        }
        if (jwk.getPrivateKey() == null) {
            throw new IllegalArgumentException("attestation_signing_jwk must carry private key material");
        }
        this.privateKey = jwk.getPrivateKey();

        String kty = jwk.getKeyType();
        String declaredAlg = privateJwk.get("alg") == null ? null : String.valueOf(privateJwk.get("alg"));
        if ("EC".equals(kty)) {
            this.algorithm = ecAlgorithm(((EllipticCurveJsonWebKey) jwk).getCurveName(), declaredAlg);
        } else if ("RSA".equals(kty)) {
            this.algorithm = rsaAlgorithm(((RSAKey) this.privateKey).getModulus().bitLength(), declaredAlg);
        } else {
            throw new IllegalArgumentException("Unsupported key type for attester signing: " + kty);
        }
        this.jcaAlgorithm = jcaAlgorithm(this.algorithm);
        this.pss = pssParameters(this.algorithm);
        this.ecConcatLength = ecConcatLength(this.algorithm);

        try {
            this.keyId = privateJwk.get("kid") != null ? String.valueOf(privateJwk.get("kid")) : Jwks.thumbprint(jwk);
        } catch (JoseException e) {
            throw new IllegalArgumentException("Unable to compute signing key thumbprint", e);
        }
        Map<String, Object> pub = new LinkedHashMap<>(jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        pub.put("kid", this.keyId);
        pub.put("alg", this.algorithm);
        this.publicJwk = pub;
    }

    @Override
    public String algorithm() {
        return this.algorithm;
    }

    @Override
    public String keyId() {
        return this.keyId;
    }

    @Override
    public Map<String, Object> publicJwk() {
        return new LinkedHashMap<>(this.publicJwk);
    }

    @Override
    public byte[] sign(byte[] signingInput) {
        try {
            Signature signature = Signature.getInstance(this.jcaAlgorithm);
            if (this.pss != null) {
                signature.setParameter(this.pss);
            }
            signature.initSign(this.privateKey);
            signature.update(signingInput);
            byte[] der = signature.sign();
            return this.ecConcatLength > 0
                    ? EcdsaUsingShaAlgorithm.convertDerToConcatenated(der, this.ecConcatLength)
                    : der;
        } catch (Exception e) {
            throw new IllegalStateException("Local JWK signing failed", e);
        }
    }

    /**
     * The one algorithm an EC key on {@code crv} signs (RFC 7518 §3.4), refusing another curve and a declared
     * {@code alg} that is not that curve's (RFC 8725 §3.1: "each key MUST be used with exactly one algorithm").
     */
    static String ecAlgorithm(String crv, String declaredAlg) {
        String algorithm;
        if ("P-256".equals(crv)) {
            algorithm = "ES256";
        } else if ("P-384".equals(crv)) {
            algorithm = "ES384";
        } else if ("P-521".equals(crv)) {
            algorithm = "ES512";
        } else {
            throw new IllegalArgumentException("Unsupported EC curve for signing: " + crv
                    + " (RFC 7518 §3.4 defines P-256, P-384 and P-521)");
        }
        if (declaredAlg != null && !declaredAlg.equals(algorithm)) {
            throw new IllegalArgumentException("an EC key on " + crv + " signs " + algorithm + ", not " + declaredAlg
                    + " (RFC 7518 §3.4; RFC 8725 §3.1: one algorithm per key)");
        }
        return algorithm;
    }

    /**
     * The algorithm an RSA key of {@code bits} signs: its declared {@code alg}, else {@code RS256}; refusing a key
     * under {@value #MIN_RSA_BITS} bits (RFC 7518 §3.3, §3.5) and an {@code alg} that is not RS or PS 256/384/512.
     */
    static String rsaAlgorithm(int bits, String declaredAlg) {
        if (bits < MIN_RSA_BITS) {
            throw new IllegalArgumentException("an RSA signing key must be " + MIN_RSA_BITS + " bits or larger; this one is "
                    + bits + " (RFC 7518 §3.3, §3.5)");
        }
        String algorithm = declaredAlg != null ? declaredAlg : "RS256";
        if (!RSA_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException("Unsupported RSA alg for signing: " + algorithm);
        }
        return algorithm;
    }

    /** The JCA signature name for one of this signer's algorithms. */
    static String jcaAlgorithm(String algorithm) {
        return switch (algorithm) {
            case "ES256" -> "SHA256withECDSA";
            case "ES384" -> "SHA384withECDSA";
            case "ES512" -> "SHA512withECDSA";
            case "RS256" -> "SHA256withRSA";
            case "RS384" -> "SHA384withRSA";
            case "RS512" -> "SHA512withRSA";
            default -> "RSASSA-PSS";
        };
    }

    /**
     * RFC 7518 §3.5's parameters for PS256/384/512 - "the same hash function for both the RSASSA-PSS hash function
     * and the MGF1 hash function", a salt "the same size as the hash function output" - or null for any other.
     */
    static PSSParameterSpec pssParameters(String algorithm) {
        return switch (algorithm) {
            case "PS256" -> new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
            case "PS384" -> new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
            case "PS512" -> new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
            default -> null;
        };
    }

    /** RFC 7518 §3.4: the length of {@code R || S} for an ECDSA algorithm; 0 for RSA. */
    static int ecConcatLength(String algorithm) {
        return switch (algorithm) {
            case "ES256" -> 64;
            case "ES384" -> 96;
            case "ES512" -> 132;
            default -> 0;
        };
    }
}
