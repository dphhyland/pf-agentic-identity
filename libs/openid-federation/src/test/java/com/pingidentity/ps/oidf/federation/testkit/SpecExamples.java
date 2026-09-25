/*
 * The worked examples of OpenID Federation 1.0 Final, as fixtures.
 */
package com.pingidentity.ps.oidf.federation.testkit;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Loads the JSON figures of the specification's worked examples from {@code src/test/resources/oidfed/}.
 * They were extracted from the Final text mechanically, not retyped, so a test asserting against them
 * asserts against the specification's own answer.
 *
 * <p>{@link #canonical} renders JSON with sorted object keys for comparison. Arrays keep their order,
 * unless {@code arraysAsSets} is set: the specification leaves "the order of the result of such an operator
 * value merge" undefined (§6.1.3), so a merged policy is compared with arrays as sets.
 */
public final class SpecExamples {
    private static final ObjectMapper JSON = new ObjectMapper().configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

    private SpecExamples() {
    }

    /** A fixture as a map, e.g. {@code load("6.1.5-trust-anchor-policy.json")}. */
    public static Map<String, Object> load(String name) {
        try (InputStream in = SpecExamples.class.getResourceAsStream("/oidfed/" + name)) {
            if (in == null) {
                throw new IllegalArgumentException("no fixture " + name);
            }
            return JSON.readValue(in, new TypeReference<Map<String, Object>>() {});
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> path(Map<String, Object> root, String... keys) {
        Map<String, Object> current = root;
        for (String key : keys) {
            current = (Map<String, Object>) current.get(key);
        }
        return current;
    }

    /** Sorted-key JSON; with {@code arraysAsSets}, every array is also sorted by its JSON rendering. */
    public static String canonical(Object value, boolean arraysAsSets) {
        try {
            return JSON.writeValueAsString(normalize(value, arraysAsSets));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Object normalize(Object value, boolean arraysAsSets) throws IOException {
        if (value instanceof Map<?, ?> map) {
            TreeMap<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                sorted.put(String.valueOf(e.getKey()), normalize(e.getValue(), arraysAsSets));
            }
            return sorted;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>();
            for (Object item : list) {
                out.add(normalize(item, arraysAsSets));
            }
            if (arraysAsSets) {
                List<String> rendered = new ArrayList<>();
                for (Object item : out) {
                    rendered.add(JSON.writeValueAsString(item));
                }
                List<Object> ordered = new ArrayList<>();
                List<Integer> index = new ArrayList<>();
                for (int i = 0; i < out.size(); i++) {
                    index.add(i);
                }
                index.sort((a, b) -> rendered.get(a).compareTo(rendered.get(b)));
                for (int i : index) {
                    ordered.add(out.get(i));
                }
                return ordered;
            }
            return out;
        }
        return value;
    }
}
