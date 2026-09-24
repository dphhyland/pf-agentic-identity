/*
 * Key generation and JWK Set helpers for federation tests.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import com.pingidentity.ps.oidf.jose.SigningKeyProvider;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.OkpJwkGenerator;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

/** Keys for tests: EC P-256 (ES256), RSA 2048 (RS256/PS256) and Ed25519 (EdDSA), each with a {@code kid}. */
public final class Keys {
    private Keys() {
    }

    public static PublicJsonWebKey ec(String kid) {
        try {
            PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
            jwk.setKeyId(kid);
            return jwk;
        } catch (JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PublicJsonWebKey rsa(String kid) {
        try {
            PublicJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
            jwk.setKeyId(kid);
            return jwk;
        } catch (JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    public static PublicJsonWebKey okp(String kid) {
        try {
            PublicJsonWebKey jwk = OkpJwkGenerator.generateJwk("Ed25519");
            jwk.setKeyId(kid);
            return jwk;
        } catch (JoseException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The JWS {@code alg} a key signs with by default. */
    public static String defaultAlg(PublicJsonWebKey key) {
        return switch (key.getKeyType()) {
            case "RSA" -> "RS256";
            case "OKP" -> "EdDSA";
            default -> "ES256";
        };
    }

    public static Map<String, Object> publicJwk(JsonWebKey key) {
        return key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    public static Map<String, Object> privateJwk(JsonWebKey key) {
        return key.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    /** {@code {"keys":[<public JWKs>]}}. */
    public static Map<String, Object> publicJwks(JsonWebKey... keys) {
        return publicJwks(List.of(keys));
    }

    public static Map<String, Object> publicJwks(List<? extends JsonWebKey> keys) {
        List<Map<String, Object>> list = new ArrayList<>();
        for (JsonWebKey key : keys) {
            list.add(publicJwk(key));
        }
        return Map.of("keys", list);
    }

    /** An RSA key as the {@link SigningKeyProvider} a {@code FederationService} signs its own statements with. */
    public static SigningKeyProvider signingKeys(PublicJsonWebKey rsa) {
        return new SigningKeyProvider() {
            @Override
            public String keyId() {
                return rsa.getKeyId();
            }

            @Override
            public RSAPrivateKey privateKey() {
                return (RSAPrivateKey) rsa.getPrivateKey();
            }

            @Override
            public RSAPublicKey publicKey() {
                return (RSAPublicKey) rsa.getPublicKey();
            }
        };
    }
}
