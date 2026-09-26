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
import com.pingidentity.ps.oidf.conformance.Requirement;
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
        return sign(claims, signer, trustChain, "entity-statement+jwt");
    }

    /** @param typ the header value, or {@code null} to leave the header off entirely */
    private static String sign(JwtClaims claims, EllipticCurveJsonWebKey signer, List<String> trustChain, String typ) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(signer.getPrivateKey());
        jws.setKeyIdHeaderValue(signer.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        if (typ != null) jws.setHeader("typ", typ);
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
    @Requirement("OIDFED §12.2.2(2.2)")
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
    @Requirement("OIDFED §12.2.2(2.2)")
    void anUnsignedJwtIsRejected() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = unsigned(entityConfiguration(k, RP, RP, OP));

        assertThrows(Exception.class, () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
    }

    @Test
    @Requirement("OIDFED §12.2.2(2.2)")
    void aJwtSignedByAKeyOtherThanItsOwnJwksIsRejected() throws Exception {
        EllipticCurveJsonWebKey advertised = key("rp-1");
        EllipticCurveJsonWebKey attacker = key("rp-1");   // same kid, different key
        String jwt = sign(entityConfiguration(advertised, RP, RP, OP), attacker, null);

        assertThrows(Exception.class, () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
    }

    @Test
    @Requirement({"OIDFED §12.2.2(2.2)", "OIDFED §12.2.1(4.12)"})
    void audienceIsCheckedOnTheVerifiedClaims() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, RP, "https://someone-else.example"), k, null);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
        assertTrue(e.getMessage().toLowerCase().contains("aud"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §12.2.1(4.4)")
    void subjectMustEqualIssuerForASelfStatement() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, "https://other.example.com", OP), k, null);

        assertThrows(IllegalArgumentException.class, () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
    }

    /**
     * OpenID Federation 1.0 §3: an Entity Statement with no {@code typ} MUST be rejected, and §12.2.2
     * applies "all the normal Entity Statement validation rules" to this request. The body never
     * reaches TrustChainValidator - the chain it validates is the body's own {@code trust_chain}
     * header, which cannot contain the body - so this parser is the only place the rule can be applied.
     * The statement is otherwise valid: signed by its own key, right audience, sub == iss.
     */
    @Test
    @Requirement("OIDFED §3(2)")
    void aStatementWithNoTypIsRejected() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, RP, OP), k, List.of("leaf", "anchor"), null);

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
        assertTrue(e.getMessage().contains("typ"), e.getMessage());
    }

    /** The generic value a JOSE library writes when nobody set one: a JWT, but not an Entity Statement. */
    @Test
    @Requirement("OIDFED §3(2)")
    void aStatementWithAnotherTypIsRejected() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String jwt = sign(entityConfiguration(k, RP, RP, OP), k, List.of("leaf", "anchor"), "JWT");

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> ExplicitRegistrationRequest.fromJwt(jwt, OP));
        assertTrue(e.getMessage().contains("typ"), e.getMessage());
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

    // ---- what is validated: the posted configuration, not the RP's copy of it in the header --------------

    private static String statement(String iss, String sub) {
        return com.pingidentity.ps.oidf.federation.testkit.Statements.spec("entity-statement+jwt").claim("iss", iss).claim("sub", sub)
                .unsigned().sign(null, java.time.Clock.systemUTC());
    }

    /**
     * §12.2.2 step 5: the RP's configuration in the header "is only used to establish that there is a path"; "it
     * is the metadata, etc. in the request Entity Configuration ... that is used". So the chain validated starts
     * with the posted configuration, and the RP's own copy in the header is dropped.
     */
    @Test
    @Requirement("OIDFED §12.2.2(2.5)")
    void theChainValidatedStartsWithThePostedConfiguration() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String ownCopy = statement(RP, RP);
        String aboutRp = statement("https://anchor.example.com", RP);
        String byRpAboutAnother = statement(RP, "https://another.example.com");
        String jwt = sign(entityConfiguration(k, RP, RP, OP), k, List.of(ownCopy, aboutRp, byRpAboutAnother, "not-a-jwt"));

        ExplicitRegistrationRequest req = ExplicitRegistrationRequest.fromJwt(jwt, OP);

        assertEquals(List.of(jwt, aboutRp, byRpAboutAnother, "not-a-jwt"), req.presentedChain(),
                "only the RP's configuration of itself is replaced by the posted one");
        assertEquals(List.of(ownCopy, aboutRp, byRpAboutAnother, "not-a-jwt"), req.trustChain(), "the header as sent");
    }

    /** With no chain in the header, discovery starts from the posted configuration (§12.2.2 step 3). */
    @Test
    @Requirement("OIDFED §12.2.2(2.3)")
    void thePeerTrustChainHeaderIsCarriedToValidation() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(entityConfiguration(k, RP, RP, OP).toJson());
        jws.setKey(k.getPrivateKey());
        jws.setKeyIdHeaderValue(k.getKeyId());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setHeader("typ", "entity-statement+jwt");
        jws.setHeader("peer_trust_chain", List.of("op-ec", "op-ss"));

        String jwt = jws.getCompactSerialization();

        ExplicitRegistrationRequest req = ExplicitRegistrationRequest.fromJwt(jwt, OP);

        assertEquals(List.of("op-ec", "op-ss"), req.peerTrustChain());
        assertEquals(List.of(jwt), req.presentedChain(), "no trust_chain header: the posted configuration alone");
    }

    @Test
    void aTrustChainBodyIsValidatedAsSent() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        String leaf = sign(entityConfiguration(k, RP, RP, OP), k, null);
        String aboutRp = statement("https://anchor.example.com", RP);

        ExplicitRegistrationRequest req = ExplicitRegistrationRequest.fromTrustChainJson("[\"" + leaf + "\",\"" + aboutRp + "\"]");

        assertEquals(List.of(leaf, aboutRp), req.presentedChain());
        assertEquals(List.of(), req.peerTrustChain());
    }

    @Test
    void aRequestBuiltWithoutHeadersHasNone() {
        ExplicitRegistrationRequest req = new ExplicitRegistrationRequest(RP, RP, null, null, null, null);

        assertEquals(List.of(), req.trustChain());
        assertEquals(List.of(), req.peerTrustChain());
        assertEquals(Map.of(), req.metadata());
    }
}
