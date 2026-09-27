/*
 * One authorization_details type: its fields and their rules.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The fields an {@code authorization_details} type (or an object inside one) may carry, each with
 * its {@link FieldRule}. RFC 9396 §2.1 makes the type the owner of its fields ("The value of the type
 * field determines the allowable contents of the object that contains it"), and §6.1 leaves comparison
 * to the type's definition; this is that definition, written down.
 *
 * <p>A field the model does not declare is refused ({@link RarModelException.Reason#UNDECLARED_FIELD}):
 * a field nobody compares is a field anybody can put anything in. {@code type} itself is implicit at
 * the top level and cannot be declared. A field the ceiling does not carry is unconstrained (CAS §7
 * rule 1: "absent ceiling field: unconstrained"); a field the ceiling carries and the candidate omits
 * is not contained.
 */
public final class TypeModel {

    private final String type;
    private final Map<String, FieldRule> fields;

    /**
     * @param type   the type name, or {@code null} for the fields of a nested object
     * @param fields the fields in declaration order
     */
    TypeModel(String type, Map<String, FieldRule> fields) {
        this.type = type;
        this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String name = e.getKey();
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("a field name is blank");
            }
            if ("type".equals(name)) {
                throw new IllegalArgumentException("'type' is implicit and cannot be a field");
            }
            String unit = e.getValue().unitField();
            if (unit != null) {
                FieldRule unitRule = fields.get(unit);
                if (unitRule == null || unitRule.rule() != Rule.EQUAL) {
                    throw new IllegalArgumentException("field '" + name + "' names unit_field '" + unit
                            + "', which must be a field of the same object with rule equal");
                }
            }
        }
    }

    /** The type name; {@code null} for a nested object's fields. */
    public String type() {
        return type;
    }

    /** The fields, in declaration order. */
    public Map<String, FieldRule> fields() {
        return fields;
    }

    /**
     * Refuses a detail (or nested object) that carries an undeclared field, a forbidden field, a
     * malformed value, or a limit without its unit.
     *
     * @param detail the object, with {@code type} allowed only at the top level
     * @param where  the detail, for the message
     */
    void check(Map<String, Object> detail, String where) throws RarModelException {
        checkValues(detail, where);
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String unit = e.getValue().unitField();
            if (unit != null && detail.containsKey(e.getKey()) && !detail.containsKey(unit)) {
                throw RarModelException.malformed(where + "." + e.getKey() + " needs " + unit + " beside it");
            }
        }
    }

    /**
     * The part of {@link #check} that does not depend on what else the detail carries: no undeclared
     * field, no forbidden field, every value the shape its rule compares. What {@link RarModels#authorize}
     * checks under {@link Omission#INHERIT} before inheritance, so that a malformed candidate is refused as
     * malformed whatever the ceiling holds, and a limit sent without its unit is not refused for a unit
     * the ceiling is about to supply.
     */
    void checkValues(Map<String, Object> detail, String where) throws RarModelException {
        for (Map.Entry<String, Object> e : detail.entrySet()) {
            String name = e.getKey();
            if (type != null && "type".equals(name)) {
                continue;
            }
            FieldRule rule = fields.get(name);
            if (rule == null) {
                throw RarModelException.undeclared(where + " carries " + RarModelException.quote(name) + ", which " + owner()
                        + " does not declare");
            }
            rule.check(e.getValue(), where + "." + name);
        }
    }

    /**
     * Whether the candidate is within the ceiling: every field the ceiling carries, the candidate
     * carries too, within the ceiling's value. Both have passed {@link #check}.
     */
    boolean contains(Map<String, Object> ceiling, Map<String, Object> candidate) {
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String name = e.getKey();
            if (!ceiling.containsKey(name)) {
                continue;
            }
            if (!candidate.containsKey(name)) {
                return false;
            }
            if (!e.getValue().contains(ceiling.get(name), candidate.get(name))) {
                return false;
            }
        }
        return true;
    }

    /**
     * The candidate with every field the ceiling carries and the candidate omits copied in from the
     * ceiling, and objects the ceiling constrains filled the same way. The ceiling has passed
     * {@link #check}; the candidate has not yet - a value of the wrong shape is left as it is for the
     * check that follows to refuse.
     */
    Map<String, Object> inherit(Map<String, Object> ceiling, Map<String, Object> candidate) {
        Map<String, Object> out = asMap(Json.copy(candidate));
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String name = e.getKey();
            if (!ceiling.containsKey(name)) {
                continue;
            }
            if (!candidate.containsKey(name)) {
                out.put(name, Json.copy(ceiling.get(name)));
            } else if (e.getValue().rule() == Rule.OBJECT && candidate.get(name) instanceof Map<?, ?>) {
                out.put(name, e.getValue().nested().inherit(asMap(ceiling.get(name)), asMap(candidate.get(name))));
            }
        }
        return out;
    }

    /**
     * The largest object within both: a field one side omits takes the other's value (absent is
     * unconstrained), a field both carry takes the rule's meet, and a field with no meet means there
     * is no object within both. Both have passed {@link #check}. Fields come out in declaration order,
     * with {@code type} first when this is a type's model.
     */
    Optional<Map<String, Object>> meet(Map<String, Object> a, Map<String, Object> b) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (type != null) {
            out.put("type", a.get("type"));
        }
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String name = e.getKey();
            boolean inA = a.containsKey(name);
            boolean inB = b.containsKey(name);
            if (!inA && !inB) {
                continue;
            }
            if (inA && !inB) {
                out.put(name, Json.copy(a.get(name)));
            } else if (!inA) {
                out.put(name, Json.copy(b.get(name)));
            } else {
                Optional<Object> m = e.getValue().meet(a.get(name), b.get(name));
                if (m.isEmpty()) {
                    return Optional.empty();
                }
                out.put(name, m.get());
            }
        }
        return Optional.of(out);
    }

    /** The fields as the fingerprint sees them, by name. */
    Map<String, Object> describeFields() {
        Map<String, Object> out = new TreeMap<>();
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            out.put(e.getKey(), e.getValue().describe());
        }
        return out;
    }

    private String owner() {
        return type == null ? "the object" : "type " + RarModelException.quote(type);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return (Map<String, Object>) value;
    }
}
