/*
 * Receiver-side SET verification, claim by claim: typ, alg, iat, jti, exp, events and sub_id.
 */
package com.pingidentity.ps.oidf.signals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.LocalJwkSigner;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwk.EcJwkGenerator;
import org.jose4j.jwk.EllipticCurveJsonWebKey;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.EllipticCurves;
import org.jose4j.keys.HmacKey;
import org.junit.jupiter.api.Test;

class SetVerifierClaimsTest {

    private static final String ISS = "https://transmitter.example.com";
    private static final String AUD = "https://receiver.example.com";
    private static final long NOW = 1_800_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);
    private static final String EVENT = EventTypes.CAEP_SESSION_REVOKED;

    private final TestSigningKeyProvider keys = new TestSigningKeyProvider("tx-key");

    private SetVerifier.JwksSource source() {
        return refresh -> {
            RsaJsonWebKey jwk = new RsaJsonWebKey(this.keys.publicKey());
            jwk.setKeyId(this.keys.keyId());
            return List.<JsonWebKey>of(jwk);
        };
    }

    private SetVerifier verifier() {
        return new SetVerifier(ISS, AUD, source(), CLOCK, SubjectId.FORMATS);
    }

    private Map<String, Object> claims() {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("iss", ISS);
        c.put("aud", AUD);
        c.put("iat", NOW);
        c.put("jti", "jti-1");
        c.put("events", Map.of(EVENT, Map.of()));
        return c;
    }

    private String sign(String typ, Map<String, Object> claims) throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(claims));
        jws.setKey(this.keys.privateKey());
        jws.setAlgorithmHeaderValue("RS256");
        jws.setKeyIdHeaderValue(this.keys.keyId());
        if (typ != null) {
            jws.setHeader("typ", typ);
        }
        return jws.getCompactSerialization();
    }

    private String sign(Map<String, Object> claims) throws Exception {
        return sign("secevent+jwt", claims);
    }

    private String refusal(String jws) {
        return assertThrows(SetVerifier.SetVerificationException.class, () -> verifier().verify(jws)).errorCode();
    }

    /**
     * RFC 8417 §2.3: the type "MUST be included if the SET could be used in an application context in which it
     * could be confused with other kinds of JWTs"; SSF 1.0 §4.1.1: "SSF events MUST use explicit typing". RFC 7515
     * §4.1.9: media types are case insensitive, and a recipient "MUST treat it as if "application/" were prepended
     * to any "typ" value not containing a '/'".
     */
    @Test
    @Requirement({"RFC8417 §2.3", "SSF §4.1.1", "RFC7515 §4.1.9"})
    void theTypeIsSeceventJwtInEitherSpellingAndAnyCase() throws Exception {
        assertEquals("jti-1", verifier().verify(sign("secevent+jwt", claims())).jti());
        assertEquals("jti-1", verifier().verify(sign("application/secevent+jwt", claims())).jti());
        assertEquals("jti-1", verifier().verify(sign("SecEvent+JWT", claims())).jti());
        assertEquals("invalid_request", refusal(sign(null, claims())));
        assertEquals("invalid_request", refusal(sign("JWT", claims())));
        assertEquals("invalid_request", refusal(sign("notsecevent+jwt", claims())));
        assertEquals("invalid_request", refusal(sign("text/secevent+jwt", claims())));
        assertFalse(SetVerifier.isSetType("at+jwt"));
    }

    @Test
    @Requirement("RFC8725 §3.1")
    void onlyAsymmetricAlgorithmsAreAccepted() throws Exception {
        JsonWebSignature none = new JsonWebSignature();
        none.setPayload(JsonUtil.toJson(claims()));
        none.setAlgorithmConstraints(org.jose4j.jwa.AlgorithmConstraints.NO_CONSTRAINTS);
        none.setAlgorithmHeaderValue("none");
        none.setHeader("typ", "secevent+jwt");
        assertEquals("invalid_request", refusal(none.getCompactSerialization()));

        JsonWebSignature hs = new JsonWebSignature();
        hs.setPayload(JsonUtil.toJson(claims()));
        hs.setAlgorithmHeaderValue("HS256");
        hs.setKey(new HmacKey(new byte[32]));
        hs.setHeader("typ", "secevent+jwt");
        assertEquals("invalid_request", refusal(hs.getCompactSerialization()));
    }

    /** RFC 8417 §2.2, "iat": "This claim is REQUIRED." */
    @Test
    @Requirement("RFC8417 §2.2")
    void iatIsRequiredAndANumber() throws Exception {
        Map<String, Object> noIat = claims();
        noIat.remove("iat");
        assertEquals("invalid_request", refusal(sign(noIat)));
        Map<String, Object> textIat = claims();
        textIat.put("iat", "yesterday");
        assertEquals("invalid_request", refusal(sign(textIat)));
        assertEquals(NOW, verifier().verify(sign(claims())).issuedAt());
    }

    /** RFC 8417 §2.2, "jti": "This claim is REQUIRED." */
    @Test
    @Requirement("RFC8417 §2.2")
    void jtiIsRequiredAndNotBlank() throws Exception {
        Map<String, Object> noJti = claims();
        noJti.remove("jti");
        assertEquals("invalid_request", refusal(sign(noJti)));
        Map<String, Object> blank = claims();
        blank.put("jti", " ");
        assertEquals("invalid_request", refusal(sign(blank)));
        Map<String, Object> number = claims();
        number.put("jti", 7);
        assertEquals("invalid_request", refusal(sign(number)));
    }

    /**
     * RFC 8417 §2.2, "exp": "the time after which the JWT MUST NOT be accepted for processing"; RFC 7519 §4.1.4:
     * "Implementers MAY provide for some small leeway, usually no more than a few minutes".
     */
    @Test
    @Requirement({"RFC8417 §2.2", "RFC7519 §4.1.4"})
    void anExpIsHonouredWhenPresent() throws Exception {
        Map<String, Object> future = claims();
        future.put("exp", NOW + 300);
        assertEquals("jti-1", verifier().verify(sign(future)).jti());
        Map<String, Object> withinLeeway = claims();
        withinLeeway.put("exp", NOW - SetVerifier.EXP_LEEWAY_SECONDS + 1);
        assertEquals("jti-1", verifier().verify(sign(withinLeeway)).jti());
        Map<String, Object> past = claims();
        past.put("exp", NOW - SetVerifier.EXP_LEEWAY_SECONDS);
        assertEquals("invalid_request", refusal(sign(past)));
        Map<String, Object> text = claims();
        text.put("exp", "tomorrow");
        assertEquals("invalid_request", refusal(sign(text)));
    }

    /**
     * RFC 8417 §2: "The "events" claim value MUST be a JSON object that contains at least one member"; §2.2: "For
     * each name present, the corresponding value MUST be a JSON object."
     */
    @Test
    @Requirement({"RFC8417 §2", "RFC8417 §2.2"})
    void eventsIsANonEmptyObjectOfObjects() throws Exception {
        Map<String, Object> none = claims();
        none.remove("events");
        assertEquals("invalid_request", refusal(sign(none)));
        Map<String, Object> empty = claims();
        empty.put("events", Map.of());
        assertEquals("invalid_request", refusal(sign(empty)));
        Map<String, Object> array = claims();
        array.put("events", List.of(EVENT));
        assertEquals("invalid_request", refusal(sign(array)));
        Map<String, Object> scalar = claims();
        scalar.put("events", Map.of(EVENT, "revoked"));
        assertEquals("invalid_request", refusal(sign(scalar)));
    }

    @Test
    @Requirement("SSF §4.1.8")
    void audMayBeAnArrayAndAnotherTypeIsNotOurs() throws Exception {
        Map<String, Object> array = claims();
        array.put("aud", List.of("https://other.example.com", AUD));
        assertEquals("jti-1", verifier().verify(sign(array)).jti());
        Map<String, Object> others = claims();
        others.put("aud", List.of("https://other.example.com"));
        assertEquals("invalid_audience", refusal(sign(others)));
        Map<String, Object> numeric = claims();
        numeric.put("aud", 42);
        assertEquals("invalid_audience", refusal(sign(numeric)));
        Map<String, Object> missing = claims();
        missing.remove("aud");
        assertEquals("invalid_audience", refusal(sign(missing)));
        assertEquals("jti-1", new SetVerifier(ISS, null, source(), CLOCK, SubjectId.FORMATS).verify(sign(missing)).jti());
    }

    @Test
    @Requirement({"SSF §3.1", "SSF §3.3"})
    void subIdIsParsedInTheFormatsTheVerifierAccepts() throws Exception {
        Map<String, Object> complex = claims();
        complex.put("sub_id", Map.of("format", "complex",
                "user", Map.of("format", "email", "email", "bar@example.com"),
                "tenant", Map.of("format", "iss_sub", "iss", "https://example.com/idp1", "sub", "1234")));
        ReceivedSet received = verifier().verify(sign(complex));
        assertTrue(received.subjectId().isComplex());
        assertEquals(SubjectId.email("bar@example.com"), received.subjectId().member("user"));

        SetVerifier fiveFormats = new SetVerifier(ISS, AUD, source(), CLOCK, Set.of(SubjectId.FORMAT_EMAIL));
        SetVerifier.SetVerificationException e = assertThrows(SetVerifier.SetVerificationException.class,
                () -> fiveFormats.verify(sign(complex)));
        assertEquals("invalid_request", e.errorCode());
        assertTrue(e.getMessage().contains("unsupported subject identifier format: complex"), e.getMessage());

        Map<String, Object> scalar = claims();
        scalar.put("sub_id", "alice");
        assertEquals("invalid_request", refusal(sign(scalar)));
        assertNull(verifier().verify(sign(claims())).subjectId());
    }

    @Test
    void aPayloadThatIsNotJsonIsRefused() throws Exception {
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("not json");
        jws.setKey(this.keys.privateKey());
        jws.setAlgorithmHeaderValue("RS256");
        jws.setHeader("typ", "secevent+jwt");
        assertEquals("invalid_request", refusal(jws.getCompactSerialization()));
    }

    @Test
    void aKeySourceThatFailsAndAKeyOfTheWrongTypeAreBothInvalidKey() throws Exception {
        SetVerifier failing = new SetVerifier(ISS, AUD, refresh -> {
            throw new IllegalStateException("down");
        }, CLOCK, SubjectId.FORMATS);
        assertEquals("invalid_key", assertThrows(SetVerifier.SetVerificationException.class,
                () -> failing.verify(sign(claims()))).errorCode());

        EllipticCurveJsonWebKey ec = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        SetVerifier wrongType = new SetVerifier(ISS, AUD, refresh -> List.<JsonWebKey>of(ec), CLOCK,
                SubjectId.FORMATS);
        assertEquals("invalid_key", assertThrows(SetVerifier.SetVerificationException.class,
                () -> wrongType.verify(sign(claims()))).errorCode());
    }

    @Test
    void aKeyWithTheRightKidAndTheWrongMaterialDoesNotVerify() throws Exception {
        TestSigningKeyProvider impostor = new TestSigningKeyProvider("tx-key");
        RsaJsonWebKey jwk = new RsaJsonWebKey(impostor.publicKey());
        jwk.setKeyId("tx-key");
        SetVerifier v = new SetVerifier(ISS, AUD, refresh -> List.<JsonWebKey>of(jwk), CLOCK, SubjectId.FORMATS);
        assertEquals("invalid_key", assertThrows(SetVerifier.SetVerificationException.class,
                () -> v.verify(sign(claims()))).errorCode());
    }

    @Test
    void aKeyWithoutAKidIsTriedAndAHeaderWithoutAKidTriesEveryKey() throws Exception {
        RsaJsonWebKey noKid = new RsaJsonWebKey(this.keys.publicKey());
        SetVerifier v = new SetVerifier(ISS, AUD, refresh -> List.<JsonWebKey>of(noKid), CLOCK, SubjectId.FORMATS);
        assertEquals("jti-1", v.verify(sign(claims())).jti());

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(JsonUtil.toJson(claims()));
        jws.setKey(this.keys.privateKey());
        jws.setAlgorithmHeaderValue("RS256");
        jws.setHeader("typ", "secevent+jwt");
        assertEquals("jti-1", verifier().verify(jws.getCompactSerialization()).jti());
    }

    /** A SET minted behind a JwsSigner (ES256 here) verifies against the signer's public JWK. */
    @Test
    @Requirement("RFC8417 §2.3")
    void aSetMintedByAJwsSignerVerifies() throws Exception {
        EllipticCurveJsonWebKey ec = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        ec.setKeyId("ec-key");
        LocalJwkSigner signer = new LocalJwkSigner(ec.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        SetMinter minter = new SetMinter(signer);
        assertEquals("ES256", minter.algorithm());
        String jws = minter.sign(SecurityEventToken.builder().issuer(ISS).audience(AUD).jti("j").issuedAt(NOW)
                .subjectId(SubjectId.opaque("x")).event(EVENT, Map.of()).build());
        JsonWebKey pub = JsonWebKey.Factory.newJwk(signer.publicJwk());
        ReceivedSet r = new SetVerifier(ISS, AUD, refresh -> List.of(pub), CLOCK, SubjectId.FORMATS).verify(jws);
        assertEquals(SubjectId.opaque("x"), r.subjectId());
        assertEquals("secevent+jwt", JsonUtil.parseJson(new String(java.util.Base64.getUrlDecoder()
                .decode(jws.substring(0, jws.indexOf('.'))), java.nio.charset.StandardCharsets.UTF_8)).get("typ"));
    }
}
