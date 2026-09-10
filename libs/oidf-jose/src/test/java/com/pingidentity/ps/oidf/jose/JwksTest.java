package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import com.pingidentity.ps.oidf.conformance.Requirement;
import org.junit.jupiter.api.Test;

class JwksTest {

    @Test
    @Requirement("ABCA-10 §7.3")
    void assertSameKeyAcceptsMatchingThumbprints() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        Map<String, Object> pub = TestJwts.publicParams(key);
        JsonWebKey other = JsonWebKey.Factory.newJwk(TestJwts.publicParams(key));
        assertDoesNotThrow(() -> Jwks.assertSameKey(pub, other));
    }

    @Test
    @Requirement("ABCA-10 §7.3")
    void assertSameKeyRejectsDifferentKeys() throws Exception {
        Map<String, Object> pub = TestJwts.publicParams(TestJwts.ec("k1"));
        JsonWebKey other = JsonWebKey.Factory.newJwk(TestJwts.publicParams(TestJwts.ec("k2")));
        assertThrows(IllegalArgumentException.class, () -> Jwks.assertSameKey(pub, other));
    }

    @Test
    @Requirement({"ABCA-10 §7.1", "RFC9449 §4.2"})
    void assertPublicOnlyRejectsPrivateMaterial() throws Exception {
        Map<String, Object> withPrivate = TestJwts.privateParams(TestJwts.ec("k1"));
        assertThrows(IllegalArgumentException.class, () -> Jwks.assertPublicOnly(withPrivate));
    }

    @Test
    @Requirement("RFC9449 §4.2")
    void assertPublicOnlyRejectsSymmetricKeys() {
        Map<String, Object> oct = Map.of("kty", "oct", "k", "c2VjcmV0");
        assertThrows(IllegalArgumentException.class, () -> Jwks.assertPublicOnly(oct));
    }

    @Test
    @Requirement("ABCA-10 §7.1")
    void assertPublicOnlyAcceptsPublicKey() throws Exception {
        Map<String, Object> pub = TestJwts.publicParams(TestJwts.ec("k1"));
        assertDoesNotThrow(() -> Jwks.assertPublicOnly(pub));
    }

    @Test
    @Requirement("RFC9449 §4.2")
    void publicKeyRejectsSymmetric() {
        Map<String, Object> oct = Map.of("kty", "oct", "k", "c2VjcmV0");
        assertThrows(Exception.class, () -> Jwks.publicKey(oct));
    }
}
