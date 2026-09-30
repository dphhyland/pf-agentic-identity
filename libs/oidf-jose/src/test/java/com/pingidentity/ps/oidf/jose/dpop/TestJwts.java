/*
 * Keys and DPoP-style signed JWTs for the DPoP proof tests.
 */
package com.pingidentity.ps.oidf.jose.dpop;

import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.lang.JoseException;

/** The part of the jose package's test helper the DPoP tests use, which moved here with them from client-attestation. */
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

    /** Signs a JWT and embeds the signing key's public JWK in the {@code jwk} header (DPoP-style). */
    static String signWithJwkHeader(PublicJsonWebKey signingKey, String alg, String typ, JwtClaims claims) throws JoseException {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signingKey.getPrivateKey());
        jws.setAlgorithmHeaderValue(alg);
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        PublicJsonWebKey publicOnly = (PublicJsonWebKey) JsonWebKey.Factory.newJwk(
                signingKey.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
        jws.setJwkHeader(publicOnly);
        return jws.getCompactSerialization();
    }
}
