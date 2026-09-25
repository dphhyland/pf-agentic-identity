package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;

/**
 * What an RP's request at the authorization or PAR endpoint must be before it can register the RP: OpenID Federation
 * 1.0 §12.1.1.1 for a request object, §12.1.1.2 for a client assertion - read before anything is fetched, verified
 * with the RP's own keys before anything is written.
 */
class RequestObjectTest {

    private static final String RP = "https://rp.example.com";
    private static final String OP = "https://op.example.com";
    private static final long NOW = 1_800_000_000L;
    private static final int MAX = 65_536;

    private static EllipticCurveJsonWebKey key(String kid) throws Exception {
        EllipticCurveJsonWebKey key = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        key.setKeyId(kid);
        return key;
    }

    private static JsonWebKey publicOf(EllipticCurveJsonWebKey key) throws Exception {
        return JsonWebKey.Factory.newJwk(key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY));
    }

    /** A request object as §12.1.1.1 wants it, then {@code change}d. */
    private static Map<String, Object> requestClaims(Consumer<Map<String, Object>> change) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("client_id", RP);
        claims.put("iss", RP);
        claims.put("aud", OP);
        claims.put("jti", "jti-1");
        claims.put("exp", NOW + 300);
        claims.put("iat", NOW);
        claims.put("response_type", "code");
        change.accept(claims);
        return claims;
    }

    private static String sign(EllipticCurveJsonWebKey key, Map<String, Object> claims, Map<String, Object> headers) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(claims));
        jws.setKey(key.getPrivateKey());
        jws.setAlgorithmHeaderValue("ES256");
        jws.setKeyIdHeaderValue(key.getKeyId());
        for (Map.Entry<String, Object> header : headers.entrySet()) {
            jws.getHeaders().setObjectHeaderValue(header.getKey(), header.getValue());
        }
        return jws.getCompactSerialization();
    }

    private static RequestObject request(EllipticCurveJsonWebKey key, Consumer<Map<String, Object>> change) throws Exception {
        return RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, sign(key, requestClaims(change), Map.of()));
    }

    private static String jwe(Map<String, Object> header) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(JsonUtil.toJson(header).getBytes(StandardCharsets.UTF_8)) + ".a.b.c.d";
    }

    private static void assertRefused(RequestObject object, String error, int status, String mentioning) {
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> object.checkProfile(RP, OP, NOW, MAX));
        assertEquals(error, e.error());
        assertEquals(status, e.status());
        assertEquals(RegistrationRejectedException.Kind.REQUEST, e.kind(), "never held against the client");
        assertTrue(e.getMessage().contains(mentioning), e.getMessage());
    }

    // ---- reading ----------------------------------------------------------------------------------------

    @Test
    void somethingThatIsNotAJwsOrJweIsAnInvalidRequestObject() {
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, "not a jwt"));
        assertEquals("invalid_request_object", e.error());
        RegistrationRejectedException assertion = assertThrows(RegistrationRejectedException.class,
                () -> RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION, "x.y"));
        assertEquals("invalid_client", assertion.error());
    }

    @Test
    @Requirement({"OIDFED §4.3(1)", "OIDFED §12.1.1.1(2.16)"})
    void theChainHintComesFromTheHeaderElseTheClaim() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        RequestObject inHeader = RequestObject.read(RequestObject.Kind.REQUEST_OBJECT,
                sign(k, requestClaims(c -> c.put("trust_chain", List.of("from-claim"))), Map.of("trust_chain", List.of("a", "", "b"))));
        RequestObject inClaim = request(k, c -> c.put("trust_chain", List.of("from-claim", 7)));
        RequestObject neither = request(k, c -> { });
        RequestObject assertion = RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION,
                sign(k, requestClaims(c -> c.put("trust_chain", List.of("ignored"))), Map.of()));

        assertEquals(List.of("a", "b"), inHeader.trustChain(), "the header wins, and blanks are nothing");
        assertEquals(List.of("from-claim"), inClaim.trustChain());
        assertEquals(List.of(), neither.trustChain());
        assertEquals(List.of(), assertion.trustChain(), "only a request object has the claim");
        assertEquals("ES256", neither.algorithm());
        assertFalse(neither.encrypted());
    }

    @Test
    void anEncryptedRequestObjectIsReadAsFarAsItsHeader() throws Exception {
        RequestObject encrypted = RequestObject.read(RequestObject.Kind.REQUEST_OBJECT,
                jwe(Map.of("alg", "RSA-OAEP-256", "enc", "A256GCM", "trust_chain", List.of("x"))));

        assertTrue(encrypted.encrypted());
        assertEquals(List.of("x"), encrypted.trustChain());
        assertEquals("RSA-OAEP-256", encrypted.algorithm());
        assertDoesNotThrow(() -> encrypted.checkProfile(RP, OP, NOW, MAX), "its claims are PingFederate's to check once decrypted");
        assertDoesNotThrow(() -> encrypted.verify(List.of(), RP, (c, j, t) -> false, NOW));
        RequestObject noAlg = RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, jwe(Map.of("enc", "A256GCM")));
        assertNull(noAlg.algorithm());
    }

    // ---- the profile (§12.1.1.1) --------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §12.1.1.1(2.2)", "OIDFED §12.1.1.1(2.4)", "OIDFED §12.1.1.1(2.6)", "OIDFED §12.1.1.1(2.10)", "OIDFED §12.1.1.1(2.12)"})
    void aRequestObjectAsTheProfileWantsItPasses() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");

        assertDoesNotThrow(() -> request(k, c -> { }).checkProfile(RP, OP, NOW, MAX));
        assertDoesNotThrow(() -> request(k, c -> c.put("aud", List.of(OP))).checkProfile(RP, OP, NOW, MAX));
        assertDoesNotThrow(() -> request(k, c -> c.remove("iat")).checkProfile(RP, OP, NOW, MAX), "iat is OPTIONAL");
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(2.2)")
    void itsAudienceIsThisOpAndNothingElse() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        assertRefused(request(k, c -> c.put("aud", "https://other.example")), "invalid_request_object", 400, "aud");
        assertRefused(request(k, c -> c.put("aud", List.of(OP, "https://other.example"))), "invalid_request_object", 400, "aud");
        assertRefused(request(k, c -> c.put("aud", List.of(7))), "invalid_request_object", 400, "aud");
        assertRefused(request(k, c -> c.remove("aud")), "invalid_request_object", 400, "aud");
    }

    @Test
    @Requirement({"OIDFED §12.1.1.1(2.4)", "OIDFED §12.1.1.1(2.6)"})
    void itsClientIdAndIssuerAreTheRp() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        assertRefused(request(k, c -> c.put("client_id", "https://other.example")), "invalid_request_object", 400, "client_id");
        assertRefused(request(k, c -> c.put("iss", "https://other.example")), "invalid_request_object", 400, "iss");
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(2.8)")
    void itCarriesNoSubject() throws Exception {
        assertRefused(request(key("rp-1"), c -> c.put("sub", RP)), "invalid_request_object", 400, "sub");
    }

    @Test
    @Requirement({"OIDFED §12.1.1.1(2.10)", "OIDFED §12.1.1.1(2.12)", "OIDFED §12.1.1.1(2.14)"})
    void itIsIdentifiedAndCurrent() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        assertRefused(request(k, c -> c.remove("jti")), "invalid_request_object", 400, "jti");
        assertRefused(request(k, c -> c.put("jti", " ")), "invalid_request_object", 400, "jti");
        assertRefused(request(k, c -> c.remove("exp")), "invalid_request_object", 400, "exp");
        assertRefused(request(k, c -> c.put("exp", "soon")), "invalid_request_object", 400, "exp");
        assertRefused(request(k, c -> c.put("exp", NOW - 61)), "invalid_request_object", 400, "expired");
        assertDoesNotThrow(() -> request(k, c -> c.put("exp", NOW - 59)).checkProfile(RP, OP, NOW, MAX), "within the skew");
        assertRefused(request(k, c -> c.put("iat", NOW + 61)), "invalid_request_object", 400, "iat");
        assertRefused(request(k, c -> c.put("iat", "now")), "invalid_request_object", 400, "iat");
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(1)")
    void itIsSignedWithAnAsymmetricKey() throws Exception {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String payload = b64.encodeToString(JsonUtil.toJson(requestClaims(c -> { })).getBytes(StandardCharsets.UTF_8));
        String none = b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "." + payload + ".";
        String noAlg = b64.encodeToString("{\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8)) + "." + payload + ".";
        JsonWebSignature mac = new JsonWebSignature();
        mac.setPayload(JsonUtil.toJson(requestClaims(c -> { })));
        mac.setKey(new HmacKey(new byte[32]));
        mac.setAlgorithmHeaderValue("HS256");

        for (String jwt : List.of(none, noAlg, mac.getCompactSerialization())) {
            assertRefused(RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, jwt), "invalid_request_object", 400, "signed");
        }
    }

    @Test
    void itsTypeIfAnyIsARequestObjects() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        for (String typ : List.of("oauth-authz-req+jwt", "JWT", "jwt")) {
            assertDoesNotThrow(() -> RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, sign(k, requestClaims(c -> { }), Map.of("typ", typ)))
                    .checkProfile(RP, OP, NOW, MAX), typ);
        }
        assertRefused(RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, sign(k, requestClaims(c -> { }), Map.of("typ", "entity-statement+jwt"))),
                "invalid_request_object", 400, "typ");
        assertRefused(RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, sign(k, requestClaims(c -> { }), Map.of("typ", 7))),
                "invalid_request_object", 400, "typ");
    }

    @Test
    void anythingLargerThanTheLimitIsRefusedBeforeItIsRead() throws Exception {
        RequestObject object = request(key("rp-1"), c -> { });
        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> object.checkProfile(RP, OP, NOW, 10));
        assertTrue(e.getMessage().contains("larger than the 10 bytes"), e.getMessage());
        RequestObject encrypted = RequestObject.read(RequestObject.Kind.REQUEST_OBJECT, jwe(Map.of("alg", "RSA-OAEP-256")));
        assertThrows(RegistrationRejectedException.class, () -> encrypted.checkProfile(RP, OP, NOW, 5));
    }

    /** §12.1.1.2: a PAR client assertion is private_key_jwt - sub and iss the RP, aud this OP alone - and a failure is a failed authentication. */
    @Test
    @Requirement({"OIDFED §12.1.1.2(2)", "OIDFED §12.1.1.2(4.1)"})
    void aClientAssertionAtParIsHeldToPrivateKeyJwt() throws Exception {
        EllipticCurveJsonWebKey k = key("rp-1");
        Consumer<Map<String, Object>> asAssertion = c -> {
            c.remove("client_id");
            c.put("sub", RP);
        };
        RequestObject good = RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION, sign(k, requestClaims(asAssertion), Map.of()));
        assertDoesNotThrow(() -> good.checkProfile(RP, OP, NOW, MAX));
        assertEquals(RequestObject.Kind.CLIENT_ASSERTION, good.kind());

        RequestObject wrongSub = RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION,
                sign(k, requestClaims(asAssertion.andThen(c -> c.put("sub", "https://other.example"))), Map.of()));
        assertRefused(wrongSub, "invalid_client", 401, "sub");
        RequestObject twoAudiences = RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION,
                sign(k, requestClaims(asAssertion.andThen(c -> c.put("aud", List.of(OP, OP + "/as/token.oauth2")))), Map.of()));
        assertRefused(twoAudiences, "invalid_client", 401, "aud");
        RequestObject anyTyp = RequestObject.read(RequestObject.Kind.CLIENT_ASSERTION, sign(k, requestClaims(asAssertion), Map.of("typ", "whatever")));
        assertDoesNotThrow(() -> anyTyp.checkProfile(RP, OP, NOW, MAX), "a client assertion's typ is not a request object's");
    }

    // ---- the proof (§12.1.1.1.2) ------------------------------------------------------------------------

    @Test
    @Requirement({"OIDFED §12.1.1.1.2(7)", "OIDFED §12.1.1(2)"})
    void itMustBeSignedByOneOfTheRpsKeys() throws Exception {
        EllipticCurveJsonWebKey rp = key("rp-1");
        EllipticCurveJsonWebKey stranger = key("rp-1");
        List<String> spent = new ArrayList<>();
        RequestObject.ReplayGuard replay = (client, jti, ttl) -> spent.add(client + " " + jti + " " + ttl);

        assertDoesNotThrow(() -> request(rp, c -> { }).verify(List.of(publicOf(rp)), RP, replay, NOW));
        assertEquals(List.of(RP + " jti-1 360"), spent, "spent for its remaining life plus the skew");

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> request(stranger, c -> { }).verify(List.of(publicOf(rp)), RP, replay, NOW));
        assertEquals(401, e.status());
        assertEquals("invalid_client", e.error());
        assertEquals(RegistrationRejectedException.Kind.REQUEST, e.kind());
        assertEquals(1, spent.size(), "a jti is spent only once the signature verified");
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(2.10)")
    void aSpentJtiIsRefused() throws Exception {
        EllipticCurveJsonWebKey rp = key("rp-1");

        RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class,
                () -> request(rp, c -> { }).verify(List.of(publicOf(rp)), RP, (client, jti, ttl) -> false, NOW));

        assertEquals("invalid_request_object", e.error());
        assertTrue(e.getMessage().contains("used before"), e.getMessage());
    }

    @Test
    void theReplayWindowIsBoundedBothWays() throws Exception {
        EllipticCurveJsonWebKey rp = key("rp-1");
        List<Long> windows = new ArrayList<>();
        RequestObject.ReplayGuard replay = (client, jti, ttl) -> windows.add(ttl);

        request(rp, c -> c.put("exp", NOW - 30)).verify(List.of(publicOf(rp)), RP, replay, NOW);
        request(rp, c -> c.put("exp", NOW + 10 * 86_400L)).verify(List.of(publicOf(rp)), RP, replay, NOW);

        assertEquals(List.of(RequestObject.CLOCK_SKEW_SECONDS, RequestObject.MAX_REPLAY_WINDOW_SECONDS), windows);
    }

    @Test
    @Requirement("OIDFED §12.1.1.1(2.2)")
    void aSingleAudienceThatIsAnotherOpIsStillTheWrongOne() throws Exception {
        assertRefused(request(key("rp-1"), c -> c.put("aud", List.of("https://other.example"))), "invalid_request_object", 400, "aud");
    }
}
