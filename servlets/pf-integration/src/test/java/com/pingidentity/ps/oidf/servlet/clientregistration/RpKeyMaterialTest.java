package com.pingidentity.ps.oidf.servlet.clientregistration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.jose.HttpGetClient;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The keys an RP publishes for {@code openid_relying_party} (OpenID Federation 1.0 §5.2.1): by value, as a signed JWK
 * Set, or by reference - distinct from the Federation Entity Keys that sign its statements, and what its request
 * objects are verified with.
 */
class RpKeyMaterialTest {

    private static final String RP = "https://rp.example.com";
    private static final long NOW = 1_800_000_000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);

    private EllipticCurveJsonWebKey federationKey;
    private EllipticCurveJsonWebKey rpKey;
    private final Map<String, String> served = new LinkedHashMap<>();
    private final List<String> fetched = new ArrayList<>();
    private final HttpGetClient http = (url, accept) -> {
        this.fetched.add(url + " " + accept);
        String body = this.served.get(url);
        if (body == null) {
            throw new java.io.IOException("404 " + url);
        }
        return body;
    };
    private final RpKeyMaterial material = new RpKeyMaterial(this.http, CLOCK);

    @BeforeEach
    void keys() throws Exception {
        this.federationKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.federationKey.setKeyId("fed-1");
        this.rpKey = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        this.rpKey.setKeyId("rp-1");
        this.rpKey.setUse("sig");
    }

    private static Map<String, Object> publicJwk(EllipticCurveJsonWebKey key) {
        return key.toParams(JsonWebKey.OutputControlLevel.PUBLIC_ONLY);
    }

    private Map<String, Object> federationJwks() {
        return Map.of("keys", List.of(publicJwk(this.federationKey)));
    }

    private Map<String, Object> rpJwks() {
        return Map.of("keys", List.of(publicJwk(this.rpKey)));
    }

    /** A jwk-set+jwt as §5.2.1 wants it, then {@code change}d. */
    private String signedJwks(Consumer<Map<String, Object>> claims, Consumer<JsonWebSignature> jws) throws Exception {
        return this.signedJwks(claims, jws, "jwk-set+jwt", "fed-1");
    }

    /** As above, with this {@code typ} and {@code kid} header (null: none). */
    private String signedJwks(Consumer<Map<String, Object>> claims, Consumer<JsonWebSignature> jws, String typ, String kid) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("keys", List.of(publicJwk(this.rpKey)));
        payload.put("iss", RP);
        payload.put("sub", RP);
        payload.put("iat", NOW - 10);
        payload.put("exp", NOW + 3600);
        claims.accept(payload);
        JsonWebSignature signed = new JsonWebSignature();
        signed.setPayload(JsonUtil.toJson(payload));
        signed.setKey(this.federationKey.getPrivateKey());
        signed.setAlgorithmHeaderValue("ES256");
        if (kid != null) {
            signed.setKeyIdHeaderValue(kid);
        }
        if (typ != null) {
            signed.setHeader("typ", typ);
        }
        jws.accept(signed);
        return signed.getCompactSerialization();
    }

    private RegistrationRejectedException refused(Map<String, Object> metadata) {
        return assertThrows(RegistrationRejectedException.class, () -> this.material.resolve(metadata, this.federationJwks(), RP));
    }

    @Test
    @Requirement("OIDFED §5.2.1(2.14)")
    void keysPublishedByValueAreRegisteredAsTheyAre() throws Exception {
        RpKeyMaterial.Keys keys = this.material.resolve(Map.of("jwks", this.rpJwks()), this.federationJwks(), RP);

        assertEquals("jwks", keys.source());
        assertEquals(List.of("rp-1"), keys.verificationKeys().stream().map(JsonWebKey::getKeyId).toList());
        assertEquals(this.rpJwks().get("keys"), JsonUtil.parseJson(keys.jwks()).get("keys"));
        assertNull(keys.jwksUri());
        assertEquals(List.of(), this.fetched, "nothing fetched");
    }

    @Test
    @Requirement({"OIDFED §5.2.1(2.2)", "OIDFED §5.2.1(2.4)", "OIDFED §5.2.1(2.6)"})
    void aSignedJwkSetIsVerifiedWithTheFederationKeysAndRegisteredAsVerified() throws Exception {
        this.served.put(RP + "/signed-jwks", this.signedJwks(c -> { }, j -> { }));

        RpKeyMaterial.Keys keys = this.material.resolve(Map.of("signed_jwks_uri", RP + "/signed-jwks", "jwks_uri", RP + "/jwks"),
                this.federationJwks(), RP);

        assertEquals("signed_jwks_uri", keys.source());
        assertEquals(List.of("rp-1"), keys.verificationKeys().stream().map(JsonWebKey::getKeyId).toList());
        assertEquals(List.of(RP + "/signed-jwks application/jwk-set+jwt"), this.fetched, "jwks_uri is not needed");
        assertNull(keys.jwksUri(), "the snapshot that verified is what is registered");
    }

    @Test
    @Requirement({"OIDFED §5.2.1(2.4)", "OIDFED §5.2.1(2.6)"})
    void aSignedJwkSetMustBeTypedCarryAKidAndBeSignedByAFederationKey() throws Exception {
        EllipticCurveJsonWebKey stranger = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        List<String> bad = List.of(
                this.signedJwks(c -> { }, j -> { }, "JWT", "fed-1"),
                this.signedJwks(c -> { }, j -> { }, null, "fed-1"),
                this.signedJwks(c -> { }, j -> { }, "jwk-set+jwt", null),
                this.signedJwks(c -> { }, j -> j.setKey(stranger.getPrivateKey())));
        for (String jwt : bad) {
            this.served.put(RP + "/signed-jwks", jwt);
            RegistrationRejectedException e = this.refused(Map.of("signed_jwks_uri", RP + "/signed-jwks"));
            assertEquals("invalid_client_metadata", e.error());
            assertEquals(RegistrationRejectedException.Kind.METADATA, e.kind());
        }
    }

    @Test
    @Requirement({"OIDFED §5.2.1(2.8.2.4)", "OIDFED §5.2.1(2.8.2.6)", "OIDFED §5.2.1(2.8.2.10)"})
    void aSignedJwkSetMustBeTheRpsOwnAndCurrent() throws Exception {
        List<Consumer<Map<String, Object>>> changes = List.of(
                c -> c.put("iss", "https://other.example"),
                c -> c.put("sub", "https://other.example"),
                c -> c.remove("sub"),
                c -> c.put("exp", NOW - 61),
                c -> c.put("exp", "later"),
                c -> c.put("iat", NOW + 61),
                c -> c.put("iat", "earlier"));
        for (Consumer<Map<String, Object>> change : changes) {
            this.served.put(RP + "/signed-jwks", this.signedJwks(change, j -> { }));
            assertEquals("invalid_client_metadata", this.refused(Map.of("signed_jwks_uri", RP + "/signed-jwks")).error());
        }
        this.served.put(RP + "/signed-jwks", this.signedJwks(c -> {
            c.remove("exp");
            c.remove("iat");
        }, j -> { }));
        assertEquals("signed_jwks_uri", this.material.resolve(Map.of("signed_jwks_uri", RP + "/signed-jwks"), this.federationJwks(), RP).source(),
                "iat and exp are OPTIONAL");
    }

    @Test
    @Requirement("OIDFED §5.2.1(2.12)")
    void keysByReferenceAreFetchedToVerifyAndRegisteredByReference() throws Exception {
        this.served.put(RP + "/jwks", JsonUtil.toJson(this.rpJwks()));

        RpKeyMaterial.Keys keys = this.material.resolve(Map.of("jwks_uri", RP + "/jwks"), this.federationJwks(), RP);

        assertEquals("jwks_uri", keys.source());
        assertEquals(RP + "/jwks", keys.jwksUri(), "PingFederate follows the RP's rotations");
        assertNull(keys.jwks());
        assertEquals(List.of(RP + "/jwks application/json"), this.fetched);
        assertEquals(1, keys.verificationKeys().size());
    }

    @Test
    @Requirement({"OIDFED §5.2.1(2.2)", "OIDFED §5.2.1(2.12)"})
    void keySetsAreOnlyFetchedOverHttps() {
        for (Map<String, Object> metadata : List.<Map<String, Object>>of(Map.of("jwks_uri", "http://rp.example.com/jwks"),
                Map.of("signed_jwks_uri", "ftp://rp.example.com/x"), Map.of("jwks_uri", "https://"), Map.of("jwks_uri", "not a url at all"))) {
            assertTrue(this.refused(metadata).getMessage().contains("https"), metadata.toString());
        }
        assertEquals(List.of(), this.fetched);
    }

    @Test
    void aKeySetThatCannotBeFetchedIsWorthTryingAgain() {
        RegistrationRejectedException e = this.refused(Map.of("jwks_uri", RP + "/missing"));

        assertEquals(503, e.status());
        assertEquals("temporarily_unavailable", e.error());
        assertTrue(e.isTransport());
    }

    @Test
    void aKeySetThatIsNotOneIsRefused() {
        this.served.put(RP + "/jwks", "<html>not json</html>");
        assertEquals("invalid_client_metadata", this.refused(Map.of("jwks_uri", RP + "/jwks")).error());
        assertEquals("invalid_client_metadata", this.refused(Map.of("jwks", "not a set")).error());
    }

    @Test
    @Requirement("OIDFED §12.1.1.1.2(7)")
    void anRpThatPublishesNoKeysHasNoneToRegister() {
        RegistrationRejectedException e = this.refused(Map.of("client_name", "RP"));

        assertEquals("invalid_client_metadata", e.error());
        assertTrue(e.getMessage().contains("openid_relying_party"), e.getMessage());
    }

    @Test
    @Requirement("OIDFED §5.2.1(2.14)")
    void onlyPublicSigningKeysVerifyAndABadKeySpoilsTheSet() throws Exception {
        EllipticCurveJsonWebKey encryption = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        encryption.setKeyId("enc-1");
        encryption.setUse("enc");
        List<JsonWebKey> signing = RpKeyMaterial.signingKeys(Map.of("keys", List.of(publicJwk(this.rpKey), publicJwk(encryption))), "jwks");
        assertEquals(List.of("rp-1"), signing.stream().map(JsonWebKey::getKeyId).toList(), "an encryption key never verifies a signature");

        Map<String, Object> withPrivate = new LinkedHashMap<>(this.rpKey.toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE));
        List<Map<String, Object>> bad = List.of(
                Map.of("keys", List.of()),
                Map.of("keys", "none"),
                Map.of("keys", List.of("not a jwk")),
                Map.of("keys", List.of(withPrivate)),
                Map.of("keys", List.of(Map.of("kty", "oct", "k", "c2VjcmV0"))),
                Map.of("keys", List.of(Map.of("kty", "EC", "crv", "P-256"))),
                Map.of("keys", List.of(publicJwk(this.rpKey), publicJwk(this.rpKey))),
                Map.of("keys", List.of(publicJwk(encryption))));
        for (Map<String, Object> set : bad) {
            RegistrationRejectedException e = assertThrows(RegistrationRejectedException.class, () -> RpKeyMaterial.signingKeys(set, "jwks"));
            assertEquals("invalid_client_metadata", e.error(), set.toString());
        }
    }

    @Test
    void keysNeedNoKidToBeUsedAndAnHttpsUrlNeedsAHost() throws Exception {
        EllipticCurveJsonWebKey anonymous = EcJwkGenerator.generateJwk(EllipticCurves.P256);
        assertEquals(2, RpKeyMaterial.signingKeys(Map.of("keys", List.of(publicJwk(anonymous), publicJwk(this.rpKey))), "jwks").size());

        assertTrue(this.refused(Map.of("jwks_uri", "https:///jwks")).getMessage().contains("https"));
    }

    @Test
    void aRegisteredClientsKeysAreItsJwkSetOrWhatItsJwksUriServes() throws Exception {
        java.util.concurrent.atomic.AtomicInteger fetches = new java.util.concurrent.atomic.AtomicInteger();
        org.jose4j.jwk.EllipticCurveJsonWebKey key = org.jose4j.jwk.EcJwkGenerator.generateJwk(org.jose4j.keys.EllipticCurves.P256);
        key.setKeyId("k1");
        String jwks = org.jose4j.json.JsonUtil.toJson(java.util.Map.of("keys", java.util.List.of(key.toParams(
                org.jose4j.jwk.JsonWebKey.OutputControlLevel.PUBLIC_ONLY))));
        RpKeyMaterial material = new RpKeyMaterial((url, accept) -> {
            fetches.incrementAndGet();
            if (url.endsWith("/down")) {
                throw new java.io.IOException("down");
            }
            return jwks;
        }, java.time.Clock.systemUTC());

        assertEquals("k1", material.registered(jwks, null).get(0).getKeyId());
        assertEquals(0, fetches.get(), "a JWK Set by value needs no fetch");
        assertEquals("k1", material.registered(null, "https://rp.example/jwks").get(0).getKeyId());
        assertEquals("k1", material.registered(" ", "https://rp.example/jwks").get(0).getKeyId());
        assertEquals(1, fetches.get(), "kept a minute");
        assertEquals(401, org.junit.jupiter.api.Assertions.assertThrows(RegistrationRejectedException.class,
                () -> material.registered(null, " ")).status(), "registered with no keys: nothing can prove it");
        assertEquals(401, org.junit.jupiter.api.Assertions.assertThrows(RegistrationRejectedException.class,
                () -> material.registered(null, null)).status());
        assertEquals(503, org.junit.jupiter.api.Assertions.assertThrows(RegistrationRejectedException.class,
                () -> material.registered(null, "https://rp.example/down")).status());
    }
}
