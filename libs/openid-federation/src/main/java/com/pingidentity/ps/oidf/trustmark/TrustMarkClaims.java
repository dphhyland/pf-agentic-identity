/*
 * The Trust Mark claims an operator can have this entity publish.
 */
package com.pingidentity.ps.oidf.trustmark;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.pingidentity.ps.oidf.federation.EntityId;
import com.pingidentity.ps.oidf.federation.TrustMarkValidator;
import com.pingidentity.ps.oidf.jose.Jwks;
import com.pingidentity.ps.oidf.jose.JwtCodec;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Parses the Trust Mark claims (§3.1.2) this entity publishes from configuration: {@code trust_marks} it carries
 * from other issuers, and - as a trust anchor - {@code trust_mark_issuers} and {@code trust_mark_owners}. Each is
 * held to the shape the statement checks demand of a received configuration, so this entity never publishes one
 * other entities would refuse. Every parser treats blank as none and throws {@link IllegalArgumentException} for
 * anything else it cannot use.
 */
public final class TrustMarkClaims {
    private TrustMarkClaims() {
    }

    /** {@code [{"trust_mark_type": "<type>", "trust_mark": "<jwt>"}, ...]}: each JWT a {@code trust-mark+jwt} of the type it is listed under. */
    public static List<Map<String, Object>> parseMarks(String json) {
        if (json == null || json.isBlank()) {
            return List.of();
        }
        List<Object> parsed;
        try {
            parsed = new ObjectMapper().readValue(json, new TypeReference<List<Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Trust Marks are not a JSON array: expected [{\"trust_mark_type\": \"<type>\", \"trust_mark\": \"<jwt>\"}]");
        }
        List<Map<String, Object>> marks = new ArrayList<>();
        for (Object item : parsed) {
            if (!(item instanceof Map<?, ?> entry) || !(entry.get("trust_mark_type") instanceof String type)
                    || !(entry.get("trust_mark") instanceof String jwt)) {
                throw new IllegalArgumentException("each Trust Mark needs a trust_mark_type and a trust_mark");
            }
            if (!isMarkOfType(jwt, type)) {
                throw new IllegalArgumentException("the Trust Mark listed as " + type + " is not a " + TrustMarkValidator.TRUST_MARK_TYP
                        + " of that type (§3.1.2)");
            }
            marks.add(Map.of("trust_mark_type", type, "trust_mark", jwt));
        }
        return List.copyOf(marks);
    }

    private static boolean isMarkOfType(String jwt, String type) {
        try {
            return TrustMarkValidator.TRUST_MARK_TYP.equals(JwtCodec.getJwtHeaders(jwt).get("typ"))
                    && type.equals(JwtCodec.parseUnverifiedClaims(jwt).getClaimValue("trust_mark_type"));
        } catch (Exception e) {
            return false;
        }
    }

    /** {@code {"<type>": ["<entity id>", ...]}}; {@code []} lets anyone issue the type. */
    public static Map<String, List<String>> parseIssuers(String json) {
        Map<String, Object> parsed = object(json, "Trust Mark issuers", "{\"<trust mark type>\": [\"<entity id>\"]}");
        Map<String, List<String>> issuers = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : parsed.entrySet()) {
            if (!(entry.getValue() instanceof List<?> list)) {
                throw new IllegalArgumentException("Trust Mark issuers of " + entry.getKey() + " are not an array");
            }
            List<String> ids = new ArrayList<>();
            for (Object id : list) {
                if (!(id instanceof String s) || !EntityId.isValid(s)) {
                    throw new IllegalArgumentException("Trust Mark issuers of " + entry.getKey() + " hold something other than an Entity Identifier");
                }
                ids.add(s);
            }
            issuers.put(entry.getKey(), List.copyOf(ids));
        }
        return issuers;
    }

    /** {@code {"<type>": {"sub": "<owner entity id>", "jwks": {"keys": [...]}}}}, the owner's public Federation Entity Keys. */
    public static Map<String, Object> parseOwners(String json) {
        Map<String, Object> parsed = object(json, "Trust Mark owners", "{\"<trust mark type>\": {\"sub\": \"<entity id>\", \"jwks\": {\"keys\": [...]}}}");
        for (Map.Entry<String, Object> entry : parsed.entrySet()) {
            if (!(entry.getValue() instanceof Map<?, ?> owner) || !(owner.get("sub") instanceof String sub) || !EntityId.isValid(sub)) {
                throw new IllegalArgumentException("the owner of " + entry.getKey() + " needs a sub that is an Entity Identifier");
            }
            if (!(owner.get("jwks") instanceof Map<?, ?> jwks)) {
                throw new IllegalArgumentException("the owner of " + entry.getKey() + " needs its jwks");
            }
            @SuppressWarnings("unchecked")
            Map<String, Object> keys = (Map<String, Object>) jwks;
            Jwks.parseFederationKeySet(keys);
        }
        return parsed;
    }

    private static Map<String, Object> object(String json, String what, String shape) {
        if (json == null || json.isBlank()) {
            return new LinkedHashMap<>();
        }
        try {
            return new ObjectMapper().readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException(what + " are not a JSON object: expected " + shape);
        }
    }
}
