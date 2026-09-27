/*
 * One authorization_details type: its fields and their rules.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

/**
 * The fields an {@code authorization_details} type (or an object inside one) may carry, each with
 * its {@link FieldRule}. RFC 9396 §2 makes the type the owner of its fields ("The value of the type
 * field determines the allowable contents of the object that contains it"), §2.1 has the AS control "the
 * object fields that the type parameter allows", and §6.1 leaves comparison to the type ("The details of
 * this comparison are dependent on the definition of the type of authorization request"); this is that
 * definition, written down.
 *
 * <p>A field the model does not declare is refused ({@link RarModelException.Reason#UNDECLARED_FIELD}):
 * a field nobody compares is a field anybody can put anything in. {@code type} itself is implicit at
 * the top level and cannot be declared. A field the ceiling does not carry is unconstrained (CAS §7
 * rule 1: "absent ceiling field: unconstrained"); a field the ceiling carries and the candidate omits
 * is not contained.
 *
 * <p>Where a type can say one thing two ways - {@code payment_initiation}'s amount as
 * {@code instructedAmount} or as a flat {@code amount} and {@code currency} - the ways are
 * <em>alternatives</em>: a group of spellings, each a set of fields. A detail uses at most one spelling
 * of a group, or it is malformed; a ceiling entry that uses a spelling holds the candidate to that
 * spelling, so a candidate that says the same thing the other way is not contained. Without this, the
 * ceiling constrains one spelling and leaves the other open, because a field the ceiling omits is
 * unconstrained - blocker B1 again, one level down.
 */
public final class TypeModel {

    private final String type;
    private final Map<String, FieldRule> fields;
    private final List<List<List<String>>> alternatives;
    /** Each field in a spelling, to its group and its spelling within the group. */
    private final Map<String, int[]> spelling;

    /** A type, or a nested object, with no alternatives. */
    TypeModel(String type, Map<String, FieldRule> fields) {
        this(type, fields, List.of());
    }

    /**
     * @param type         the type name, or {@code null} for the fields of a nested object
     * @param fields       the fields in declaration order
     * @param alternatives groups of two or more spellings of one thing, each spelling one or more of the
     *                     fields; no field in two spellings, and a limit in the same spelling as its unit
     */
    TypeModel(String type, Map<String, FieldRule> fields, List<List<List<String>>> alternatives) {
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
                if (unitRule == null || (unitRule.rule() != Rule.EQUAL && unitRule.rule() != Rule.STRING)) {
                    throw new IllegalArgumentException("field " + RarModelException.quote(name) + " names unit_field "
                            + RarModelException.quote(unit) + ", which must be a field of the same object with rule equal or string");
                }
            }
        }
        Map<String, int[]> where = new HashMap<>();
        List<List<List<String>>> groups = new ArrayList<>();
        for (int g = 0; g < alternatives.size(); g++) {
            List<List<String>> group = alternatives.get(g);
            if (group.size() < 2) {
                throw new IllegalArgumentException("alternatives need two spellings or more");
            }
            List<List<String>> spellings = new ArrayList<>();
            for (int k = 0; k < group.size(); k++) {
                List<String> names = group.get(k);
                if (names.isEmpty()) {
                    throw new IllegalArgumentException("a spelling names no field");
                }
                for (String name : names) {
                    if (!fields.containsKey(name)) {
                        throw new IllegalArgumentException("spelling field " + RarModelException.quote(name) + " is not a field of the object");
                    }
                    if (where.put(name, new int[] {g, k}) != null) {
                        throw new IllegalArgumentException("field " + RarModelException.quote(name) + " is in two spellings");
                    }
                }
                spellings.add(List.copyOf(names));
            }
            groups.add(Collections.unmodifiableList(spellings));
        }
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String unit = e.getValue().unitField();
            if (unit != null && !Arrays.equals(where.get(e.getKey()), where.get(unit))) {
                throw new IllegalArgumentException("field " + RarModelException.quote(e.getKey()) + " and its unit_field "
                        + RarModelException.quote(unit) + " must be in the same spelling");
            }
        }
        this.alternatives = Collections.unmodifiableList(groups);
        this.spelling = where;
    }

    /** The type name; {@code null} for a nested object's fields. */
    public String type() {
        return type;
    }

    /** The fields, in declaration order. */
    public Map<String, FieldRule> fields() {
        return fields;
    }

    /** The groups of alternative spellings, each spelling a list of fields; empty for most types. */
    public List<List<List<String>>> alternatives() {
        return alternatives;
    }

    /**
     * Refuses a detail (or nested object) that carries an undeclared field, a forbidden field, a
     * malformed value, two spellings of one thing, or a limit without its unit, at any depth.
     *
     * @param detail the object, with {@code type} allowed only at the top level
     * @param where  the detail, for the message
     */
    void check(Map<String, Object> detail, String where) throws RarModelException {
        check(detail, where, true);
    }

    /**
     * {@link #check} less the unit pairing, at every depth: no undeclared field, no forbidden field,
     * every value the shape its rule compares, one spelling per group. What {@link RarModels#authorize}
     * checks under {@link Omission#INHERIT} before inheritance, so that a malformed candidate is refused
     * as malformed whatever the ceiling holds, and a limit sent without its unit - in the detail or in an
     * object inside it - is not refused for a unit the ceiling is about to supply.
     */
    void checkValues(Map<String, Object> detail, String where) throws RarModelException {
        check(detail, where, false);
    }

    /**
     * @param units whether a limit must have its unit beside it, here and in every object below
     */
    void check(Map<String, Object> detail, String where, boolean units) throws RarModelException {
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
            rule.check(e.getValue(), where + "." + name, units);
        }
        for (int g = 0; g < alternatives.size(); g++) {
            String first = null;
            for (String name : detail.keySet()) {
                int[] at = spelling.get(name);
                if (at == null || at[0] != g) {
                    continue;
                }
                if (first == null) {
                    first = name;
                } else if (spelling.get(first)[1] != at[1]) {
                    throw RarModelException.malformed(where + " carries " + RarModelException.quote(first) + " and "
                            + RarModelException.quote(name) + ", two spellings of one thing; send one");
                }
            }
        }
        if (!units) {
            return;
        }
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String unit = e.getValue().unitField();
            if (unit != null && detail.containsKey(e.getKey()) && !detail.containsKey(unit)) {
                throw RarModelException.malformed(where + "." + e.getKey() + " needs " + unit + " beside it");
            }
        }
    }

    /**
     * Whether the candidate is within the ceiling: every field the ceiling carries, the candidate
     * carries too, within the ceiling's value. Both have passed {@link #check}, which is also what holds
     * the candidate to the ceiling's spelling: a candidate in another spelling of the group cannot carry
     * a field of the ceiling's (that would be two spellings), so it omits one the ceiling carries.
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
     * ceiling, and objects the ceiling constrains filled the same way - except a field of a spelling
     * other than the one the candidate uses, which would make it say one thing two ways; the candidate
     * stays in its own spelling and {@link #contains} then finds it outside this entry. The ceiling has
     * passed {@link #check}; the candidate has passed {@link #checkValues} - a value of the wrong shape
     * for inheritance is left as it is.
     */
    Map<String, Object> inherit(Map<String, Object> ceiling, Map<String, Object> candidate) {
        Map<String, Object> out = asMap(Json.copy(candidate));
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            String name = e.getKey();
            if (!ceiling.containsKey(name)) {
                continue;
            }
            if (!candidate.containsKey(name)) {
                int[] at = spelling.get(name);
                int used = at == null ? -1 : used(candidate, at[0]);
                if (used < 0 || used == at[1]) {
                    out.put(name, Json.copy(ceiling.get(name)));
                }
            } else if (e.getValue().rule() == Rule.OBJECT && candidate.get(name) instanceof Map<?, ?>) {
                out.put(name, e.getValue().nested().inherit(asMap(ceiling.get(name)), asMap(candidate.get(name))));
            }
        }
        return out;
    }

    /**
     * The largest object within both: a field one side omits takes the other's value (absent is
     * unconstrained), a field both carry takes the rule's meet, and a field with no meet - or a group
     * the two sides spell differently - means there is no object within both. Both have passed
     * {@link #check}. Fields come out in declaration order, with {@code type} first when this is a
     * type's model.
     */
    Optional<Map<String, Object>> meet(Map<String, Object> a, Map<String, Object> b) {
        for (int g = 0; g < alternatives.size(); g++) {
            if (disagree(a, b, g)) {
                return Optional.empty();
            }
        }
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

    /** Whether both objects use a spelling of the group and not the same one. */
    private boolean disagree(Map<String, Object> x, Map<String, Object> y, int group) {
        int ux = used(x, group);
        int uy = used(y, group);
        return ux >= 0 && uy >= 0 && ux != uy;
    }

    /** The spelling of the group a checked object uses, or -1 when it uses none. */
    private int used(Map<String, Object> object, int group) {
        List<List<String>> spellings = alternatives.get(group);
        for (int k = 0; k < spellings.size(); k++) {
            for (String name : spellings.get(k)) {
                if (object.containsKey(name)) {
                    return k;
                }
            }
        }
        return -1;
    }

    /**
     * The model as the fingerprint sees it: {@code fields} by name, rules described as a models document
     * writes them, and {@code alternatives} as declared when there are any.
     */
    Map<String, Object> describe() {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> described = new TreeMap<>();
        for (Map.Entry<String, FieldRule> e : fields.entrySet()) {
            described.put(e.getKey(), e.getValue().describe());
        }
        out.put("fields", described);
        if (!alternatives.isEmpty()) {
            out.put("alternatives", alternatives);
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
