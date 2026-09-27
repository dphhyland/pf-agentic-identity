/*
 * The models file: extra types, and fields added to the built-in ones.
 */
package com.pingidentity.ps.oidf.rar.model;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Reads a models document into {@link TypeModel}s on top of the built-ins. The document is one JSON
 * object:
 *
 * <pre>
 * { "types": {
 *     "https://scheme.example.org/files": {
 *       "fields": { "locations": "set",
 *                   "budget": { "rule": "limit", "unit_field": "budget_currency" },
 *                   "budget_currency": "equal",
 *                   "permissions": { "rule": "object", "fields": { "path": "equal", "access": "set" } } } },
 *     "payment_initiation": {
 *       "extends": "payment_initiation",
 *       "fields": { "remittanceInformationStructured": "equal" } } } }
 * </pre>
 *
 * <p>A field is a rule name, or an object with {@code rule} and that rule's options: {@code unit_field}
 * for {@code limit}, {@code fields} for {@code object}. {@code extends} names a built-in type or one
 * declared earlier in the document; the extension inherits the base's fields and alternatives, adds its
 * own fields, and may redefine an inherited field only as {@code forbidden} - a redefinition that
 * changes how an inherited field is compared would relax a rule somebody relies on. A document entry
 * named like a built-in must extend that built-in and nothing else: silently replacing a built-in model,
 * from scratch or with another type's fields, is the mistake this refuses. A document cannot declare
 * alternatives of its own; to say a built-in's thing a new way, an extension forbids the old spelling.
 * Anything the schema does not name - an unknown key, an unknown rule, an option on the wrong rule - is
 * {@link RarModelException.Reason#MODEL_INVALID}, never ignored.
 */
final class ModelSchema {

    private static final Set<String> ROOT_KEYS = Set.of("types");
    private static final Set<String> TYPE_KEYS = Set.of("extends", "fields");
    private static final Set<String> RULE_KEYS = Set.of("rule", "unit_field", "fields");

    private ModelSchema() {
    }

    /**
     * @param json    the document
     * @param builtIn the built-in models, which an entry may extend and may not replace
     * @return the built-ins followed by the loaded types, in document order
     */
    static Map<String, TypeModel> parse(String json, Map<String, TypeModel> builtIn) throws RarModelException {
        Object root;
        try {
            root = Json.parse(json);
        } catch (IllegalArgumentException e) {
            throw RarModelException.modelInvalid("models document: " + e.getMessage());
        }
        Map<String, Object> doc = object(root, "models document");
        onlyKeys(doc, ROOT_KEYS, "models document");
        if (!doc.containsKey("types")) {
            throw RarModelException.modelInvalid("models document has no 'types'");
        }
        Map<String, Object> types = object(doc.get("types"), "'types'");
        Map<String, TypeModel> out = new LinkedHashMap<>(builtIn);
        for (Map.Entry<String, Object> e : types.entrySet()) {
            String name = e.getKey();
            if (name.isBlank()) {
                throw RarModelException.modelInvalid("a type name is blank");
            }
            String where = "type " + RarModelException.quote(name);
            Map<String, Object> entry = object(e.getValue(), where);
            onlyKeys(entry, TYPE_KEYS, where);
            if (!entry.containsKey("fields")) {
                throw RarModelException.modelInvalid(where + " has no 'fields'");
            }
            Map<String, FieldRule> fields = new LinkedHashMap<>();
            List<List<List<String>>> alternatives = List.of();
            Object extendsValue = entry.get("extends");
            if (entry.containsKey("extends")) {
                if (!(extendsValue instanceof String base) || base.isBlank()) {
                    throw RarModelException.modelInvalid(where + ": 'extends' must name a type");
                }
                if (builtIn.containsKey(name) && !name.equals(base)) {
                    throw RarModelException.modelInvalid(where + " is built in and may extend only itself, not "
                            + RarModelException.quote(base));
                }
                TypeModel baseModel = out.get(base);
                if (baseModel == null) {
                    throw RarModelException.modelInvalid(where + " extends " + RarModelException.quote(base)
                            + ", which is neither built in nor declared before it");
                }
                fields.putAll(baseModel.fields());
                alternatives = baseModel.alternatives();
            } else if (builtIn.containsKey(name)) {
                throw RarModelException.modelInvalid(where + " is built in; add fields to it with \"extends\": \""
                        + name + "\" rather than redefining it");
            }
            Map<String, Object> declared = object(entry.get("fields"), where + " 'fields'");
            for (Map.Entry<String, Object> f : declared.entrySet()) {
                String field = f.getKey();
                FieldRule rule = fieldRule(f.getValue(), where + " field " + RarModelException.quote(field), 1);
                if (fields.containsKey(field) && rule.rule() != Rule.FORBIDDEN) {
                    throw RarModelException.modelInvalid(where + " redefines inherited field " + RarModelException.quote(field)
                            + "; an inherited field may only be made forbidden");
                }
                fields.put(field, rule);
            }
            out.put(name, typeModel(name, fields, alternatives, where));
        }
        return out;
    }

    private static FieldRule fieldRule(Object value, String where, int depth) throws RarModelException {
        if (value instanceof String name) {
            Rule rule = rule(name, where);
            if (rule == Rule.OBJECT) {
                throw RarModelException.modelInvalid(where + ": an object rule needs its 'fields'");
            }
            return FieldRule.of(rule);
        }
        Map<String, Object> spec = object(value, where);
        onlyKeys(spec, RULE_KEYS, where);
        if (!(spec.get("rule") instanceof String name)) {
            throw RarModelException.modelInvalid(where + " has no 'rule'");
        }
        Rule rule = rule(name, where);
        switch (rule) {
            case LIMIT: {
                if (spec.containsKey("fields")) {
                    throw RarModelException.modelInvalid(where + ": 'fields' belongs to the object rule");
                }
                if (!spec.containsKey("unit_field")) {
                    return FieldRule.of(rule);
                }
                if (!(spec.get("unit_field") instanceof String unit) || unit.isBlank()) {
                    throw RarModelException.modelInvalid(where + ": 'unit_field' must name a field");
                }
                return FieldRule.limit(unit);
            }
            case OBJECT: {
                if (spec.containsKey("unit_field")) {
                    throw RarModelException.modelInvalid(where + ": 'unit_field' belongs to the limit rule");
                }
                if (depth >= Limits.MAX_DEPTH - 1) {
                    throw RarModelException.modelInvalid(where + ": a models document nests objects at most "
                            + (Limits.MAX_DEPTH - 1) + " deep (the detail is depth 1), one short of the value depth limit");
                }
                Map<String, Object> declared = object(spec.get("fields"), where + " 'fields'");
                if (declared.isEmpty()) {
                    throw RarModelException.modelInvalid(where + ": an object rule needs at least one field");
                }
                Map<String, FieldRule> fields = new LinkedHashMap<>();
                for (Map.Entry<String, Object> f : declared.entrySet()) {
                    fields.put(f.getKey(), fieldRule(f.getValue(), where + " field " + RarModelException.quote(f.getKey()), depth + 1));
                }
                return FieldRule.object(typeModel(null, fields, List.of(), where));
            }
            default: {
                if (spec.size() != 1) {
                    throw RarModelException.modelInvalid(where + ": rule " + RarModelException.quote(name) + " takes no options");
                }
                return FieldRule.of(rule);
            }
        }
    }

    private static TypeModel typeModel(String name, Map<String, FieldRule> fields, List<List<List<String>>> alternatives,
                                       String where) throws RarModelException {
        try {
            return new TypeModel(name, fields, alternatives);
        } catch (IllegalArgumentException e) {
            throw RarModelException.modelInvalid(where + ": " + e.getMessage());
        }
    }

    private static Rule rule(String name, String where) throws RarModelException {
        try {
            return Rule.fromJson(name);
        } catch (RarModelException e) {
            throw RarModelException.modelInvalid(where + ": " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value, String where) throws RarModelException {
        if (!(value instanceof Map<?, ?>)) {
            throw RarModelException.modelInvalid(where + " must be a JSON object");
        }
        return (Map<String, Object>) value;
    }

    private static void onlyKeys(Map<String, Object> object, Set<String> allowed, String where) throws RarModelException {
        for (String key : object.keySet()) {
            if (!allowed.contains(key)) {
                throw RarModelException.modelInvalid(where + " has unknown key " + RarModelException.quote(key) + " (allowed: "
                        + String.join(", ", new TreeSet<>(allowed)) + ")");
            }
        }
    }
}
