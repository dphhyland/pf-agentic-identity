/*
 * A subordinate listing request.
 */
package com.pingidentity.ps.oidf.federation;

import java.util.List;

/**
 * The parameters of an OpenID Federation 1.0 §8.2.1 list request.
 *
 * @param entityTypes   the {@code entity_type} values; a subordinate must have every one (the parameter
 *                      "MAY occur multiple times" and the result must "include all specified Entity Types")
 * @param trustMarked   {@code trust_marked}, or null when absent
 * @param trustMarkType {@code trust_mark_type}, or null when absent
 * @param intermediate  {@code intermediate}, or null when absent
 */
public record ListRequest(List<String> entityTypes, Boolean trustMarked, String trustMarkType, Boolean intermediate) {

    public ListRequest {
        entityTypes = nonBlank(entityTypes);
    }

    /** The values trimmed, with null and blank ones dropped: they are nothing the caller asked for. */
    static List<String> nonBlank(List<String> values) {
        List<String> out = new java.util.ArrayList<>();
        if (values != null) {
            for (String value : values) {
                if (value != null && !value.isBlank()) {
                    out.add(value.trim());
                }
            }
        }
        return List.copyOf(out);
    }

    /** No filters: every Immediate Subordinate. */
    public static ListRequest all() {
        return new ListRequest(List.of(), null, null, null);
    }
}
