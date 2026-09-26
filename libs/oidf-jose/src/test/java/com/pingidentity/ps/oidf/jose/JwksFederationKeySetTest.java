package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

/**
 * {@link Jwks#parseFederationKeySet}: the gate every Entity Statement's {@code jwks} passes before any of
 * its keys is trusted to verify anything.
 */
class JwksFederationKeySetTest {

    @Test
    @Requirement("OIDFED §3.1.1")
    void readsAPublicSetWithUniqueKids() throws Exception {
        PublicJsonWebKey ec = TestJwts.ec("ec-1");
        PublicJsonWebKey rsa = TestJwts.rsa("rsa-1");

        List<JsonWebKey> keys = Jwks.parseFederationKeySet(Map.of("keys",
                List.of(TestJwts.publicParams(ec), TestJwts.publicParams(rsa))));

        assertEquals(2, keys.size());
        assertEquals("ec-1", keys.get(0).getKeyId());
        assertThrows(UnsupportedOperationException.class, () -> keys.add(keys.get(0)));
    }

    @Test
    @Requirement("OIDFED §3.1.1")
    void refusesAKeyWithoutAKid() throws Exception {
        Map<String, Object> noKid = new HashMap<>(TestJwts.publicParams(TestJwts.ec(null)));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Jwks.parseFederationKeySet(Map.of("keys", List.of(noKid))));
        assertTrue(e.getMessage().contains("kid"), e.getMessage());

        noKid.put("kid", " ");
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of("keys", List.of(noKid))));
    }

    @Test
    @Requirement("OIDFED §3.1.1")
    void refusesADuplicateKid() throws Exception {
        Map<String, Object> a = TestJwts.publicParams(TestJwts.ec("same"));
        Map<String, Object> b = TestJwts.publicParams(TestJwts.ec("same"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Jwks.parseFederationKeySet(Map.of("keys", List.of(a, b))));
        assertTrue(e.getMessage().contains("duplicate"), e.getMessage());
    }

    @Test
    void refusesPrivateAndSymmetricKeys() throws Exception {
        Map<String, Object> withPrivate = TestJwts.privateParams(TestJwts.ec("p"));
        Map<String, Object> oct = Map.of("kty", "oct", "kid", "s", "k", "AAAAAAAAAAAAAAAAAAAAAA");

        IllegalArgumentException priv = assertThrows(IllegalArgumentException.class,
                () -> Jwks.parseFederationKeySet(Map.of("keys", List.of(withPrivate))));
        assertFalse(priv.getMessage().contains(String.valueOf(withPrivate.get("d"))), "the message must not echo key material");
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of("keys", List.of(oct))));
    }

    @Test
    void refusesAnEmptyMissingOrMisshapenSet() {
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(null));
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of()));
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of("keys", List.of())));
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of("keys", "nope")));
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of("keys", List.of("nope"))));
    }

    @Test
    void refusesAKeyThatDoesNotParse() {
        Map<String, Object> broken = Map.of("kty", "XYZ", "kid", "b");
        assertThrows(IllegalArgumentException.class, () -> Jwks.parseFederationKeySet(Map.of("keys", List.of(broken))));
    }
}
