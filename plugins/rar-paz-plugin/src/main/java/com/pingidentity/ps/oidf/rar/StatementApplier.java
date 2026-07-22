/*
 * Applies governance-engine statements (obligations / enrichment) back into an authorization detail.
 */
package com.pingidentity.ps.oidf.rar;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Merges each returned {@link DecisionResponse.Statement} into the detail map, placing the payload at the
 * dot-separated path named by the statement (e.g. {@code access.limits} → {@code detail["access"]["limits"]}).
 * String payloads that parse as JSON are parsed first. This is how policy downscopes or annotates the grant.
 */
public final class StatementApplier {

    private StatementApplier() { }

    public static void apply(List<DecisionResponse.Statement> statements, Map<String, Object> detail, ObjectMapper mapper) {
        if (statements == null || detail == null) {
            return;
        }
        for (DecisionResponse.Statement s : statements) {
            if (s.getName() == null || s.getName().isBlank()) {
                continue;
            }
            addNested(detail, s.getName(), coerce(s.getPayload(), mapper));
        }
    }

    private static Object coerce(Object payload, ObjectMapper mapper) {
        if (payload instanceof String str) {
            String trimmed = str.trim();
            if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
                try {
                    return mapper.readValue(str, Object.class);
                } catch (Exception ignored) {
                    // not JSON; keep the raw string
                }
            }
        }
        return payload;
    }

    @SuppressWarnings("unchecked")
    private static void addNested(Map<String, Object> root, String path, Object value) {
        String[] parts = path.split("\\.");
        Map<String, Object> current = root;
        for (int i = 0; i < parts.length - 1; i++) {
            Object next = current.get(parts[i]);
            if (!(next instanceof Map)) {
                next = new HashMap<String, Object>();
                current.put(parts[i], next);
            }
            current = (Map<String, Object>) next;
        }
        current.put(parts[parts.length - 1], value);
    }
}
