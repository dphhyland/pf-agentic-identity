package com.pingidentity.ps.oidf.jose;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;
import org.junit.jupiter.api.Test;

/**
 * {@link Claims} is the null-safe accessor layer every claim read in the attestation and federation
 * paths goes through, so a claim of the wrong JSON shape (an attacker-controlled JWT payload) must
 * degrade to "absent", not throw an unchecked cast exception mid-verification.
 */
class ClaimsTest {

    @Test
    void stringListReadsAJsonArrayOfStrings() {
        JwtClaims claims = new JwtClaims();
        claims.setStringListClaim("aud", "a", "b");
        assertEquals(List.of("a", "b"), Claims.stringList(claims, "aud"));
    }

    @Test
    void stringListReturnsEmptyWhenTheClaimIsAbsent() {
        JwtClaims claims = new JwtClaims();
        assertEquals(List.of(), Claims.stringList(claims, "missing"));
    }

    @Test
    void stringListReturnsEmptyWhenTheClaimIsNotAList() {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("aud", "not-a-list");
        assertEquals(List.of(), Claims.stringList(claims, "aud"));
    }

    @Test
    void requiredMapReturnsTheNestedObject() {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("cnf", Map.of("jwk", Map.of("kty", "EC")));
        Map<String, Object> cnf = Claims.requiredMap(claims, "cnf");
        assertTrue(cnf.containsKey("jwk"));
    }

    @Test
    void requiredMapThrowsWhenTheClaimIsMissing() {
        JwtClaims claims = new JwtClaims();
        assertThrows(IllegalArgumentException.class, () -> Claims.requiredMap(claims, "cnf"));
    }

    @Test
    void requiredMapThrowsWhenTheClaimIsNotAnObject() {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("cnf", "not-an-object");
        assertThrows(IllegalArgumentException.class, () -> Claims.requiredMap(claims, "cnf"));
    }

    @Test
    void optionalMapReturnsEmptyWhenAbsentOrWrongType() {
        JwtClaims claims = new JwtClaims();
        assertEquals(Map.of(), Claims.optionalMap(claims, "missing"));

        claims.setClaim("wrong_type", List.of("a"));
        assertEquals(Map.of(), Claims.optionalMap(claims, "wrong_type"));
    }

    @Test
    void optionalMapReturnsThePresentObject() {
        JwtClaims claims = new JwtClaims();
        claims.setClaim("device", Map.of("model", "iPhone"));
        assertEquals("iPhone", Claims.optionalMap(claims, "device").get("model"));
    }

    @Test
    void optionalNestedMapReadsAChildKeyOfAParentMap() {
        Map<String, Object> parent = Map.of("jwk", Map.of("kty", "EC"));
        assertEquals("EC", Claims.optionalNestedMap(parent, "jwk").get("kty"));
    }

    @Test
    void optionalNestedMapReturnsEmptyWhenTheChildIsAbsentOrWrongType() {
        Map<String, Object> parent = Map.of("jwk", "not-an-object");
        assertEquals(Map.of(), Claims.optionalNestedMap(parent, "jwk"));
        assertEquals(Map.of(), Claims.optionalNestedMap(parent, "missing"));
    }

    @Test
    void requireNonBlankReturnsTheValueWhenPresent() {
        assertEquals("value", Claims.requireNonBlank("value", "field"));
    }

    @Test
    void requireNonBlankRejectsNullAndBlank() {
        IllegalArgumentException nullEx =
                assertThrows(IllegalArgumentException.class, () -> Claims.requireNonBlank(null, "software_id"));
        assertTrue(nullEx.getMessage().contains("software_id"));

        assertThrows(IllegalArgumentException.class, () -> Claims.requireNonBlank("   ", "software_id"));
    }
}
