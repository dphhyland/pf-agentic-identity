package com.pingidentity.ps.oidf.rs;

import com.pingidentity.ps.oidf.jose.Jwks;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.NumericDate;
import org.jose4j.keys.EllipticCurves;

/** Keys, tokens and proofs for the rs-validation tests. */
final class Fixture {
    static final String ISSUER = "https://pf.example.com";
    static final String AUDIENCE = "https://rs.example.com";
    static final String BASE = "https://rs.example.com";
    static final String URL = BASE + "/orders";
    static final String HUMAN = "pingone|alice";
    static final String INSTANCE = "8Kx2_opaque_instance_id";

    final PublicJsonWebKey asKey;
    final PublicJsonWebKey clientKey;

    Fixture() throws Exception {
        this.asKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.asKey.setKeyId("pf-1");
        this.clientKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
    }

    static JsonWebKey publicOnly(PublicJsonWebKey key) throws Exception {
        return JsonWebKey.Factory.newJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    DelegatedTokenValidator.Builder builder(ReplayStore store) throws Exception {
        return DelegatedTokenValidator.builder(ISSUER, AUDIENCE).keys(List.of(publicOnly(this.asKey))).replayStore(store);
    }

    static String thumbprint(PublicJsonWebKey key) throws Exception {
        return Jwks.thumbprint(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    /** Claims for a delegated token bound to the client key. */
    JwtClaims claims() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer(ISSUER);
        claims.setAudience(AUDIENCE);
        claims.setSubject(HUMAN);
        claims.setIssuedAtToNow();
        claims.setExpirationTime(NumericDate.fromSeconds(NumericDate.now().getValue() + 300));
        claims.setClaim("scope", "orders:read");
        claims.setClaim("act", Map.of("sub", INSTANCE));
        Map<String, Object> cnf = new LinkedHashMap<>();
        cnf.put("jkt", thumbprint(this.clientKey));
        claims.setClaim("cnf", cnf);
        return claims;
    }

    /** A token signed by the AS key, typ at+jwt; {@code headers} may change the JWS before it is signed. */
    String token(JwtClaims claims, Consumer<JsonWebSignature> headers) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(this.asKey.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(this.asKey.getKeyId());
        jws.setHeader("typ", "at+jwt");
        headers.accept(jws);
        return jws.getCompactSerialization();
    }

    String token(JwtClaims claims) throws Exception {
        return this.token(claims, jws -> { });
    }

    String token() throws Exception {
        return this.token(this.claims());
    }

    /** A proof by the client key for {@code token}; {@code change} may alter the claims before signing. */
    String proof(String token, String method, String url, Consumer<JwtClaims> change) throws Exception {
        return proof(this.clientKey, token, method, url, change);
    }

    String proof(String token) throws Exception {
        return this.proof(token, "GET", URL, c -> { });
    }

    static String proof(PublicJsonWebKey key, String token, String method, String url, Consumer<JwtClaims> change)
            throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("htm", method);
        claims.setClaim("htu", url);
        claims.setClaim("jti", UUID.randomUUID().toString());
        claims.setIssuedAtToNow();
        if (token != null) {
            claims.setClaim("ath", DelegatedTokenValidator.accessTokenHash(token));
        }
        change.accept(claims);
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "dpop+jwt");
        jws.getHeaders().setJwkHeaderValue("jwk",
                PublicJsonWebKey.Factory.newPublicJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY)));
        return jws.getCompactSerialization();
    }

    static DelegatedTokenValidator.Presentation dpop(String token, List<String> proofs) {
        return new DelegatedTokenValidator.Presentation(DelegatedTokenValidator.Scheme.DPOP, token, proofs, "GET", URL,
                null);
    }
}
