/*
 * Test helpers for building keys and signed JWTs used by the attestation tests.
 */
package com.pingidentity.ps.oidf.common;

import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

final class TestJwts {
    private TestJwts() {
    }

    static PublicJsonWebKey ec(String kid) throws JoseException {
        PublicJsonWebKey jwk = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        if (kid != null) {
            jwk.setKeyId(kid);
        }
        return jwk;
    }

    static RsaJsonWebKey rsa(String kid) throws JoseException {
        RsaJsonWebKey jwk = RsaJwkGenerator.generateJwk(2048);
        if (kid != null) {
            jwk.setKeyId(kid);
        }
        return jwk;
    }

    /** Public-only JWK parameters (suitable for a {@code cnf.jwk} or DPoP {@code jwk} header). */
    static Map<String, Object> publicParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    /** Public-only JWK parameters including private material (to test rejection of private keys). */
    static Map<String, Object> privateParams(JsonWebKey jwk) {
        return jwk.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE);
    }

    static String sign(PublicJsonWebKey signingKey, String alg, String typ, JwtClaims claims) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(alg);
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        if (signingKey.getKeyId() != null) {
            jws.setKeyIdHeaderValue(signingKey.getKeyId());
        }
        return jws.getCompactSerialization();
    }

    /** Signs a JWT and embeds the signing key's public JWK in the {@code jwk} header (DPoP-style). */
    static String signWithJwkHeader(PublicJsonWebKey signingKey, String alg, String typ, JwtClaims claims) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(alg);
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        PublicJsonWebKey publicOnly = (PublicJsonWebKey) JsonWebKey.Factory.newJwk(TestJwts.publicParams(signingKey));
        jws.setJwkHeader(publicOnly);
        return jws.getCompactSerialization();
    }
}
