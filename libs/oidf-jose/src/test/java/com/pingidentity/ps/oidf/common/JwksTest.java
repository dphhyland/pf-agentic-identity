package com.pingidentity.ps.oidf.common;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.junit.jupiter.api.Test;

class JwksTest {

    @Test
    void assertSameKeyAcceptsMatchingThumbprints() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        Map<String, Object> pub = TestJwts.publicParams(key);
        JsonWebKey other = JsonWebKey.Factory.newJwk(TestJwts.publicParams(key));
        assertDoesNotThrow(() -> Jwks.assertSameKey(pub, other));
    }

    @Test
    void assertSameKeyRejectsDifferentKeys() throws Exception {
        Map<String, Object> pub = TestJwts.publicParams(TestJwts.ec("k1"));
        JsonWebKey other = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("k2")));
        assertThrows(IllegalArgumentException.class, () -> Jwks.assertSameKey(pub, other));
    }

    @Test
    void assertPublicOnlyRejectsPrivateMaterial() throws Exception {
        Map<String, Object> withPrivate = TestJwts.privateParams(TestJwts.ec("k1"));
        assertThrows(IllegalArgumentException.class, () -> Jwks.assertPublicOnly(withPrivate));
    }

    @Test
    void assertPublicOnlyRejectsSymmetricKeys() {
        Map<String, Object> oct = Map.of("kty", "oct", "k", "c2VjcmV0");
        assertThrows(IllegalArgumentException.class, () -> Jwks.assertPublicOnly(oct));
    }

    @Test
    void assertPublicOnlyAcceptsPublicKey() throws Exception {
        Map<String, Object> pub = TestJwts.publicParams(TestJwts.ec("k1"));
        assertDoesNotThrow(() -> Jwks.assertPublicOnly(pub));
    }

    @Test
    void publicKeyRejectsSymmetric() {
        Map<String, Object> oct = Map.of("kty", "oct", "k", "c2VjcmV0");
        assertThrows(Exception.class, () -> Jwks.publicKey(oct));
    }
}
