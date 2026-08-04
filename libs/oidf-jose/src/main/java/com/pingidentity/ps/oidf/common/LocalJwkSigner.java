/*
 * JwsSigner backed by an in-process private JWK (dev/demo attester key).
 */
package com.pingidentity.ps.oidf.common;

import java.security.PrivateKey;
import java.security.Signature;
import java.util.LinkedHashMap;
import java.util.Map;
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
 * <p>Supports EC keys ({@code P-256/384/521} → {@code ES256/384/512}) and RSA keys ({@code RS256/384/512},
 * default {@code RS256}). Emits the raw JWS signature bytes RFC 7515 §3.4 requires: fixed-width
 * {@code r||s} for ECDSA, the raw signature for RSA.
 */
public final class LocalJwkSigner implements JwsSigner {

    private final PrivateKey privateKey;
    private final String algorithm;
    private final String jcaAlgorithm;
    private final int ecConcatLength; // 0 for RSA
    private final String keyId;
    private final Map<String, Object> publicJwk;

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
            String crv = String.valueOf(privateJwk.get("crv"));
            switch (crv) {
                case "P-256" -> { this.algorithm = "ES256"; this.jcaAlgorithm = "SHA256withECDSA"; this.ecConcatLength = 64; }
                case "P-384" -> { this.algorithm = "ES384"; this.jcaAlgorithm = "SHA384withECDSA"; this.ecConcatLength = 96; }
                case "P-521" -> { this.algorithm = "ES512"; this.jcaAlgorithm = "SHA512withECDSA"; this.ecConcatLength = 132; }
                default -> throw new IllegalArgumentException("Unsupported EC curve for signing: " + crv);
            }
        } else if ("RSA".equals(kty)) {
            this.algorithm = declaredAlg != null ? declaredAlg : "RS256";
            this.jcaAlgorithm = switch (this.algorithm) {
                case "RS256" -> "SHA256withRSA";
                case "RS384" -> "SHA384withRSA";
                case "RS512" -> "SHA512withRSA";
                default -> throw new IllegalArgumentException("Unsupported RSA alg for signing: " + this.algorithm);
            };
            this.ecConcatLength = 0;
        } else {
            throw new IllegalArgumentException("Unsupported key type for attester signing: " + kty);
        }

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
}
