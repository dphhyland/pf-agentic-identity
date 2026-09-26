/*
 * The Trust Marks a deployment requires before it registers an entity.
 */
package com.pingidentity.ps.oidf.federation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The Trust Marks an entity must carry, by the Entity Type it is registered as:
 * {@code {"*": ["<type>", ...], "openid_relying_party": ["<type>", ...]}}.
 *
 * <p>The {@code "*"} list applies whatever the Entity Type; a type's own list adds to it. Every mark listed is
 * required - all of them, not one of them - and only a mark {@link TrustMarkValidator} verified counts. OpenID
 * Federation leaves what a mark is required for to the federation (§7: marks are "statements of conformance"),
 * so this is local policy, not a protocol rule.
 */
public final class TrustMarkPolicy {
    /** The key whose list applies to every Entity Type. */
    public static final String EVERY_TYPE = "*";
    private static final TrustMarkPolicy NONE = new TrustMarkPolicy(Map.of());

    private final Map<String, List<String>> required;

    private TrustMarkPolicy(Map<String, List<String>> required) {
        this.required = required;
    }

    /** Requires nothing. */
    public static TrustMarkPolicy none() {
        return NONE;
    }

    /**
     * Parses the policy; blank means none.
     *
     * @throws IllegalArgumentException for anything but a JSON object whose members are arrays of non-blank strings
     */
    public static TrustMarkPolicy parse(String json) {
        if (json == null || json.isBlank()) {
            return NONE;
        }
        Map<String, Object> parsed;
        try {
            parsed = new ObjectMapper().readValue(json, new TypeReference<LinkedHashMap<String, Object>>() {});
        } catch (Exception e) {
            throw new IllegalArgumentException("Required Trust Marks are not a JSON object: expected {\"*\": [\"<trust mark type>\", ...],"
                    + " \"<entity type>\": [...]}");
        }
        Map<String, List<String>> required = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : parsed.entrySet()) {
            if (!(entry.getValue() instanceof List<?> types)) {
                throw new IllegalArgumentException("Required Trust Marks for " + entry.getKey() + " are not an array of Trust Mark types");
            }
            List<String> listed = new ArrayList<>();
            for (Object type : types) {
                if (!(type instanceof String s) || s.isBlank()) {
                    throw new IllegalArgumentException("Required Trust Marks for " + entry.getKey() + " hold something other than a Trust Mark type");
                }
                listed.add(s);
            }
            required.put(entry.getKey(), List.copyOf(listed));
        }
        return new TrustMarkPolicy(Map.copyOf(required));
    }

    /** Whether nothing is required of any Entity Type. */
    public boolean isEmpty() {
        return this.required.values().stream().allMatch(List::isEmpty);
    }

    /** The mark types required of an entity registered as {@code entityType}: the {@code "*"} list, then the type's own. */
    public List<String> requiredFor(String entityType) {
        Set<String> types = new LinkedHashSet<>(this.required.getOrDefault(EVERY_TYPE, List.of()));
        types.addAll(this.required.getOrDefault(entityType, List.of()));
        return List.copyOf(types);
    }

    /** The required mark types {@code marks} lacks a verified mark of; empty when the entity may be registered. */
    public List<String> missing(TrustMarkValidator.Result marks, String entityType) {
        return this.requiredFor(entityType).stream().filter(type -> !marks.has(type)).toList();
    }
}
