package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.keys.EllipticCurves;
import org.junit.jupiter.api.Test;

/**
 * {@link ExplicitRegistrationRequest} is a pure parser: it turns a signed entity statement (or a
 * trust-chain body) into an immutable request and touches nothing else. Whether an existing client
 * exists, and what to do about it, is {@link RegistrationService}'s decision - made only after the
 * trust chain has been validated. These tests pin that split: an unverified or forged JWT produces an
 * exception and no side effect, because the parser has nothing to have a side effect on.
 */
class ExplicitRegistrationRequestTest {

    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://as.example.com";

    private static EllipticCurveJsonWebKey key(String kid) throws Exception {
        EllipticCurveJsonWebKey k = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        k.setKeyId(kid);
        return k;
    }

    private static JwtClaims entityConfiguration(EllipticCurveJsonWebKey key, String iss, String sub, String aud) {
        JwtClaims c = new JwtClaims();
        c.setIssuer(iss);
        c.setSubject(sub);
        c.setAudience(aud);
        c.setIssuedAtToNow();
        c.setExpirationTimeMinutesInTheFuture(10.0f);
        c.setClaim("jwks", Map.of("keys", List.of(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        c.setClaim("authority_hints", List.of("https://anchor.example.com"));
        c.setClaim("metadata", Map.of("openid_relying_party", Map.of(
                "client_registration_types", List.of("explicit"),
                "redirect_uris", List.of(RP + "/cb"))));
        return c;
    }

    /** Signed by {@code signer}, but advertising {@code advertised}'s public key in {@code jwks}. */
    private static String sign(JwtClaims claims, EllipticCurveJsonWebKey signer, List<String> trustChain) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signer.getPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        if (trustChain != null) jws.setHeader("trust_chain", trustChain);
        return jws.getCompactSerialization();
    }

    private static String unsigned(JwtClaims claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setAlgorithmHeaderValue("none");
        jws.setAlgorithmConstraints(org.jose4j.jwa.AlgorithmConstraints.NO_CONSTRAINTS);
        return jws.getCompactSerialization();
    }

    @Test
    void parsesAVerifiedSelfSignedEntityStatement() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, RP, OP), k, List.of("leaf", "anchor"));

        ExplicitRegistrationRequest req = ExplicitRegistrationRequest.fromJwt(jwt, OP);

        assertEquals(RP, req.issuer());
        assertEquals(RP, req.sub());
        assertEquals(List.of("leaf", "anchor"), req.trustChain());
        assertTrue(req.metadata().containsKey("openid_relying_party"));
    }

    @Test
    void anUnsignedJwtIsRejected() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = unsigned(entityConfiguration(k, RP, RP, OP));

        assertThrows(Exception.class, () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
    }

    @Test
    void aJwtSignedByAKeyOtherThanItsOwnJwksIsRejected() throws Exception {
        EllipticCurveJsonWebKey advertised = key("rp-1");
        EllipticCurveJsonWebKey attacker = key("rp-1");   // same kid, different key
        String jwt = sign(entityConfiguration(advertised, RP, RP, OP), attacker, null);

        assertThrows(Exception.class, () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
    }

    @Test
    void audienceIsCheckedOnTheVerifiedClaims() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, RP, "https://someone-else.example"), k, null);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
        assertTrue(e.getMessage().toLowerCase().contains("aud"), e.getMessage());
    }

    @Test
    void subjectMustEqualIssuerForASelfStatement() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, "https://other.example.com", OP), k, null);

        assertThrows(IllegalArgumentException.class, () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
    }

    @Test
    void trustChainBodyOnlySelectsTheLeafAndCarriesTheChain() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String leaf = sign(entityConfiguration(k, RP, RP, OP), k, null);
        String body = "[\"" + leaf + "\"]";

        ExplicitRegistrationRequest req = ExplicitRegistrationRequest.fromTrustChainJson(body);

        assertEquals(RP, req.issuer());
        assertEquals(RP, req.sub());
        assertEquals(List.of(leaf), req.trustChain());
        assertTrue(req.metadata().isEmpty(), "metadata comes from chain resolution, not the raw body");
    }

    @Test
    void trustChainBodyIsBounded() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < 64; i++) sb.append(i > 0 ? "," : "").append("\"a.b.c\"");
        sb.append("]");

        assertThrows(IllegalArgumentException.class, () -> ExplicitRegistrationRequest.fromTrustChainJson(sb.toString()));
    }
}
