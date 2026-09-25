package com.pingidentity.ps.oidf.federation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import com.pingidentity.ps.oidf.federation.testkit.Keys;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * The small types every federation decision is expressed in: Entity Identifiers, the §8.9 error codes,
 * the anchor set and live anchors.
 */
class FederationFoundationsTest {
    private static final String TA = "https://ta.example.com";
    private static final String TA2 = "https://ta2.example.com/federation";

    // ---- EntityId -------------------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §9(1)")
    void aTrailingSlashIsRemovedBeforeTheWellKnownPathIsAppended() {
        assertEquals("https://e.example/.well-known/openid-federation", EntityId.wellKnownUrl("https://e.example/"));
        assertEquals("https://e.example/p/.well-known/openid-federation", EntityId.wellKnownUrl("https://e.example/p"));
        assertTrue(EntityId.same("https://e.example/", "https://e.example"));
        assertFalse(EntityId.same("https://e.example/a", "https://e.example/A"));
        assertFalse(EntityId.same(null, "https://e.example"));
        assertNull(EntityId.comparable(null));
    }

    @Test
    @Requirement("OIDFED §1.2")
    void anEntityIdentifierIsAnHttpsUrlWithAHost() {
        assertEquals("https://e.example:8443/x", EntityId.normalize(" https://e.example:8443/x/ "));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize("http://e.example"));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize("https:///nohost"));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize("https://e.example/#frag"));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize("https://u:p@e.example"));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize("https://e.example/?q=1"));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize("https://e .example"));
        assertThrows(IllegalArgumentException.class, () -> EntityId.normalize(null));
        assertTrue(EntityId.isValid("https://e.example"));
        assertFalse(EntityId.isValid("file:///etc/passwd"));
        assertEquals("e.example", EntityId.host("https://E.Example/path"));
    }

    // ---- FederationError / exceptions ---------------------------------------------------------------

    @Test
    @Requirement("OIDFED §8.9")
    void everyErrorCodeCarriesTheStatusTheSpecificationGivesIt() {
        assertEquals(400, FederationError.INVALID_REQUEST.httpStatus());
        assertEquals(500, FederationError.SERVER_ERROR.httpStatus());
        assertEquals(503, FederationError.TEMPORARILY_UNAVAILABLE.httpStatus());
        assertEquals(401, FederationError.INVALID_CLIENT.httpStatus());
        assertEquals(404, FederationError.INVALID_ISSUER.httpStatus());
        assertEquals(404, FederationError.INVALID_SUBJECT.httpStatus());
        assertEquals(404, FederationError.INVALID_TRUST_ANCHOR.httpStatus());
        assertEquals(400, FederationError.INVALID_TRUST_CHAIN.httpStatus());
        assertEquals(400, FederationError.INVALID_METADATA.httpStatus());
        assertEquals(404, FederationError.NOT_FOUND.httpStatus());
        assertEquals(400, FederationError.UNSUPPORTED_PARAMETER.httpStatus());
        assertEquals("invalid_trust_chain", FederationError.INVALID_TRUST_CHAIN.code());
    }

    @Test
    void aChainRefusalMapsItsKindToTheErrorAnEndpointAnswers() {
        assertEquals(FederationError.INVALID_METADATA,
                new TrustChainValidationException(TrustChainValidationException.Kind.POLICY, "i", "s", "d").error());
        assertEquals(FederationError.INVALID_TRUST_ANCHOR,
                new TrustChainValidationException(TrustChainValidationException.Kind.ANCHOR, null, null, "d").error());
        assertEquals(FederationError.TEMPORARILY_UNAVAILABLE,
                new TrustChainValidationException(TrustChainValidationException.Kind.TRANSPORT, null, null, "d").error());
        TrustChainValidationException sig = new TrustChainValidationException(
                TrustChainValidationException.Kind.SIGNATURE, "https://i", "https://s", "bad", new IllegalStateException());
        assertEquals(FederationError.INVALID_TRUST_CHAIN, sig.error());
        assertEquals("signature", sig.kind().code());
        assertEquals("https://i", sig.issuer());
        assertEquals("https://s", sig.subject());
        assertEquals("bad", sig.description());
        FederationEntityNotFoundException missing = new FederationEntityNotFoundException("gone");
        assertEquals(FederationError.NOT_FOUND, missing.error());
        assertThrows(NullPointerException.class, () -> new FederationException(null, "x"));
        assertThrows(NullPointerException.class, () -> new FederationException(null, "x", null));
    }

    // ---- TrustAnchorSet -----------------------------------------------------------------------------

    @Test
    @Requirement("OIDFED §10.3")
    void aRequestedAnchorOrderIsHonouredButNeverWidensTheSet() throws Exception {
        TrustAnchor a = TrustAnchor.of(TA, Keys.publicJwks(Keys.ec("a-1")));
        TrustAnchor b = TrustAnchor.of(TA2, Keys.publicJwks(Keys.ec("b-1")));
        TrustAnchorSet set = TrustAnchorSet.of(a, b);

        assertEquals(List.of(a, b), set.select(null));
        assertEquals(List.of(a, b), set.select(List.of()));
        assertEquals(List.of(b, a), set.select(List.of(TA2 + "/", "https://unknown.example", TA, TA)));
        FederationException none = assertThrows(FederationException.class, () -> set.select(List.of("https://unknown.example")));
        assertEquals(FederationError.INVALID_TRUST_ANCHOR, none.error());
    }

    @Test
    void theSetFindsAnchorsByNormalisedIdAndReplacesInPlace() throws Exception {
        TrustAnchor a = TrustAnchor.of(TA, Keys.publicJwks(Keys.ec("a-1")));
        TrustAnchor b = TrustAnchor.of(TA2, Keys.publicJwks(Keys.ec("b-1")));
        TrustAnchor aRotated = TrustAnchor.of(TA + "/", Keys.publicJwks(Keys.ec("a-2")));
        TrustAnchorSet set = TrustAnchorSet.of(List.of(a, b));

        assertSame(a, set.find(TA + "/").orElseThrow());
        assertTrue(set.contains(TA2));
        assertFalse(set.contains("https://x.example"));
        TrustAnchorSet replaced = set.plus(aRotated);
        assertEquals(2, replaced.size());
        assertSame(aRotated, replaced.anchors().get(0));
        assertEquals(3, set.plus(TrustAnchor.of("https://c.example", Keys.publicJwks(Keys.ec("c-1")))).size());
        assertEquals(List.of(TA, TA2), set.entityIds());
        assertTrue(set.toString().contains(TA2));
        assertTrue(TrustAnchorSet.empty().isEmpty());
        assertThrows(IllegalArgumentException.class, () -> TrustAnchorSet.of(a, aRotated));
    }

    @Test
    void anAnchorSetParsesFromAJsonMapInOrder() throws Exception {
        PublicJsonWebKey k1 = Keys.ec("k1");
        PublicJsonWebKey k2 = Keys.rsa("k2");
        String json = "{\"" + TA2 + "\":" + org.jose4j.json.JsonUtil.toJson(Keys.publicJwks(k2))
                + ",\"" + TA + "\":" + org.jose4j.json.JsonUtil.toJson(Keys.publicJwks(k1)) + "}";

        TrustAnchorSet set = TrustAnchorSet.parseJson(json);

        assertEquals(List.of(TA2, TA), set.entityIds());
        assertTrue(TrustAnchorSet.looksLikeAnchorMap(json));
        assertFalse(TrustAnchorSet.looksLikeAnchorMap(org.jose4j.json.JsonUtil.toJson(Keys.publicJwks(k1))));
        assertFalse(TrustAnchorSet.looksLikeAnchorMap("not json"));
        assertFalse(TrustAnchorSet.looksLikeAnchorMap(null));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchorSet.parseJson(""));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchorSet.parseJson("[1]"));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchorSet.parseJson("{\"" + TA + "\":\"keys\"}"));
        assertThrows(IllegalArgumentException.class, () -> TrustAnchorSet.parseJson(
                "{\"" + TA + "\":" + org.jose4j.json.JsonUtil.toJson(Map.of("keys", List.of(Keys.privateJwk(k1)))) + "}"));
    }

    @Test
    @Requirement("OIDFED §3.2(2.11)")
    void anAnchorVerifiesItsStatementsUnderTheEntityStatementPolicy() throws Exception {
        PublicJsonWebKey key = Keys.ec("ta-1");
        TrustAnchor anchor = TrustAnchor.of(TA, Keys.publicJwks(key));
        java.time.Clock clock = java.time.Clock.systemUTC();
        String good = com.pingidentity.ps.oidf.federation.testkit.Statements.spec("entity-statement+jwt")
                .claim("iss", TA).claim("sub", TA).claim("jwks", Keys.publicJwks(key)).sign(key, clock);
        String noKid = com.pingidentity.ps.oidf.federation.testkit.Statements.spec("entity-statement+jwt")
                .kid(null).claim("iss", TA).claim("sub", TA).sign(key, clock);

        com.pingidentity.ps.oidf.jose.VerificationPolicy policy = com.pingidentity.ps.oidf.jose.VerificationPolicy.entityStatement();
        assertEquals(TA, anchor.verify(good, java.util.Set.of(), policy).getIssuer());
        assertThrows(com.pingidentity.ps.oidf.jose.JwtVerificationException.class,
                () -> anchor.verify(noKid, java.util.Set.of(), policy));
        assertEquals(TA, anchor.verify(noKid, java.util.Set.of()).getIssuer());
    }

    // ---- live anchors -------------------------------------------------------------------------------

    @Test
    void aLiveAnchorReadsItsKeysEachTime() throws Exception {
        PublicJsonWebKey first = Keys.ec("self-1");
        PublicJsonWebKey second = Keys.ec("self-2");
        AtomicReference<Map<String, Object>> current = new AtomicReference<>(Keys.publicJwks(first));
        TrustAnchor self = TrustAnchor.live(TA, current::get);

        assertTrue(self.isLive());
        assertEquals("self-1", self.keys().get(0).getKeyId());
        current.set(Keys.publicJwks(second));
        assertEquals("self-2", self.keys().get(0).getKeyId());
        assertTrue(self.toString().contains("live"));
        assertFalse(TrustAnchor.of(TA, Keys.publicJwks(first)).isLive());
        assertThrows(IllegalArgumentException.class, () -> TrustAnchor.live(" ", current::get));
        assertThrows(NullPointerException.class, () -> TrustAnchor.live(TA, null));
        current.set(Map.of("keys", List.of()));
        assertThrows(IllegalArgumentException.class, self::keys);
    }
}
