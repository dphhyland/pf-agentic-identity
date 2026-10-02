package com.pingidentity.ps.oidf.jose;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.jose4j.jwt.JwtClaims;

/**
 * Null-safe accessors for reading loosely-typed JWT claims and nested JSON
 * objects. The map accessors return an empty map rather than {@code null} when
 * a claim is absent or of the wrong type, so callers can chain without
 * defensive null checks.
 *
 * <p>The {@link JwtClaims} these take are verified ones: a verifier in {@link JwtCodec} is the only way to one. The
 * claims of a JWT whose signature has not been checked are an {@link UnverifiedClaims}, which has accessors of its
 * own, each named for what it returns.
 */
public final class Claims {

    private Claims() {
    }

    public static List<String> stringList(JwtClaims claims, String claimName) {
        Object value = claims.getClaimValue(claimName);
        if (!(value instanceof List)) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (Object item : (List<?>) value) {
            result.add(String.valueOf(item));
        }
        return result;
    }

    public static Map<String, Object> requiredMap(JwtClaims claims, String claimName) {
        Object value = claims.getClaimValue(claimName);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("Required claim '" + claimName + "' is missing or not an object");
        }
        return asStringObjectMap(value);
    }

    public static Map<String, Object> optionalMap(JwtClaims claims, String claimName) {
        Object value = claims.getClaimValue(claimName);
        return value instanceof Map ? asStringObjectMap(value) : Map.of();
    }

    public static Map<String, Object> optionalNestedMap(Map<String, Object> parent, String childKey) {
        Object value = parent.get(childKey);
        return value instanceof Map ? asStringObjectMap(value) : Map.of();
    }

    public static String requireNonBlank(String value, String fieldName) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing required field: " + fieldName);
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asStringObjectMap(Object value) {
        return (Map<String, Object>) value;
    }
}
