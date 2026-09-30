package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.pingidentity.ps.oidf.conformance.Requirement;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Map;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * {@link UnverifiedClaims}: what {@link JwtCodec#parseUnverifiedClaims} returns. The boundary it draws is a compile-time
 * one - it is not a {@link JwtClaims} and hands none out, so no caller can pass it where verified claims are expected -
 * and Java cannot state "this does not compile" in a test, so the first two tests hold the shape that makes it so.
 */
class UnverifiedClaimsTest {

    @Test
    @Requirement("RFC8725 §3.2")
    void isNotAJwtClaimsAndHandsNoneOut() {
        assertFalse(JwtClaims.class.isAssignableFrom(UnverifiedClaims.class), "an UnverifiedClaims must not be a JwtClaims");
        assertTrue(Modifier.isFinal(UnverifiedClaims.class.getModifiers()), "no subclass may add a way back to JwtClaims");
        for (Method method : UnverifiedClaims.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers())) {
                assertFalse(JwtClaims.class.isAssignableFrom(method.getReturnType()), method.getName() + " returns verified claims");
            }
        }
        for (var constructor : UnverifiedClaims.class.getDeclaredConstructors()) {
            assertFalse(Modifier.isPublic(constructor.getModifiers()), "only JwtCodec makes one");
        }
    }

    @Test
    @Requirement("RFC8725 §3.2")
    void everyPublicAccessorSaysItIsUnverified() {
        for (Method method : UnverifiedClaims.class.getDeclaredMethods()) {
            if (Modifier.isPublic(method.getModifiers()) && !method.getName().equals("toString")) {
                assertTrue(method.getName().toLowerCase(java.util.Locale.ROOT).contains("unverified"), method.getName());
            }
        }
    }

    @Test
    void readsWhatTheSenderWroteWithoutCheckingTheSignature() throws Exception {
        PublicJsonWebKey key = TestJwts.ec("k1");
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://iss.example");
        claims.setSubject("https://sub.example");
        claims.setClaim("exp", 1_900_000_000L);
        claims.setClaim("jwks", Map.of("keys", List.of()));
        claims.setStringListClaim("authority_hints", "https://a.example", "https://b.example");
        claims.setClaim("n", "not a number");
        String jwt = TestJwts.sign(key, "ES256", "entity-statement+jwt", claims);
        String tampered = jwt.substring(0, jwt.lastIndexOf('.') + 1) + "AAAA";

        UnverifiedClaims read = JwtCodec.parseUnverifiedClaims(tampered);

        assertEquals("https://iss.example", read.unverifiedIssuer());
        assertEquals("https://sub.example", read.unverifiedSubject());
        assertEquals("https://sub.example", read.unverifiedString("sub"));
        assertEquals(1_900_000_000L, read.unverifiedNumericDate("exp"));
        assertNull(read.unverifiedNumericDate("n"), "a claim that is not a number has no date");
        assertNull(read.unverifiedNumericDate("iat"));
        assertEquals(Map.of("keys", List.of()), read.unverifiedMap("jwks"));
        assertEquals(Map.of(), read.unverifiedMap("iss"), "a claim that is not an object is an empty map");
        assertEquals(List.of("https://a.example", "https://b.example"), read.unverifiedStringList("authority_hints"));
        assertEquals(List.of(), read.unverifiedStringList("iss"), "a claim that is not an array is an empty list");
        assertTrue(read.hasUnverifiedClaim("jwks"));
        assertFalse(read.hasUnverifiedClaim("metadata"));
        assertEquals("not a number", read.unverifiedClaim("n"));
        assertNull(read.unverifiedString("exp"), "a number is not a string");
        assertEquals(6, read.unverifiedClaimsMap().size());
    }

    @Test
    void anIssuerOrSubjectThatIsNotAStringIsNull() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("iss", 42);
        UnverifiedClaims read = JwtCodec.parseUnverifiedClaims(TestJwts.sign(TestJwts.ec("k1"), "ES256", null, claims));

        assertNull(read.unverifiedIssuer());
        assertNull(read.unverifiedSubject());
    }

    @Test
    void theClaimsMapIsACopy() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://iss.example");
        UnverifiedClaims read = JwtCodec.parseUnverifiedClaims(TestJwts.sign(TestJwts.ec("k1"), "ES256", null, claims));

        read.unverifiedClaimsMap().put("iss", "https://other.example");

        assertEquals("https://iss.example", read.unverifiedIssuer());
    }

    @Test
    void toStringNamesNoClaim() throws Exception {
        JwtClaims claims = new JwtClaims();
        claims.setIssuer("https://secret-issuer.example");
        UnverifiedClaims read = JwtCodec.parseUnverifiedClaims(TestJwts.sign(TestJwts.ec("k1"), "ES256", null, claims));

        assertFalse(read.toString().contains("secret-issuer"), read.toString());
        assertTrue(read.toString().contains("not checked"), read.toString());
    }

    @Test
    void nothingThatIsNotAJwsIsRead() {
        JwtVerificationException e = assertThrows(JwtVerificationException.class, () -> JwtCodec.parseUnverifiedClaims("a.b"));
        assertEquals(JwtVerificationException.Reason.MALFORMED, e.reason());
        assertThrows(JwtVerificationException.class, () -> JwtCodec.parseUnverifiedClaims(null));
        assertThrows(NullPointerException.class, () -> new UnverifiedClaims(null));
    }
}
