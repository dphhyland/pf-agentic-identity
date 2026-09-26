/*
 * OpenID Federation metadata_policy: composition down a trust chain, and application to metadata.
 */
package com.pingidentity.ps.oidf.federation;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An OpenID Federation 1.0 {@code metadata_policy} for one Entity Type, composed down a trust chain and
 * applied to an entity's metadata.
 *
 * <p>Everything here follows the Final text (17 February 2026), §6.1.3 to §6.1.4, read verbatim:
 *
 * <ul>
 *   <li><b>Operators</b> (§6.1.3.1): {@code value}, {@code add}, {@code default}, {@code one_of},
 *       {@code subset_of}, {@code superset_of}, {@code essential}. Each operator's definition gives its
 *       "Order of application", and they chain: {@code value} "First", {@code add} "After value",
 *       {@code default} "After add", {@code one_of} "After default", {@code subset_of} "After one_of",
 *       {@code superset_of} "After subset_of", {@code essential} "Last".</li>
 *   <li><b>Merge</b> (each operator's "Operator value merge"): {@code value} and {@code default} must be
 *       equal; {@code add} and {@code superset_of} take the union; {@code one_of} and {@code subset_of}
 *       the intersection, which is an error for {@code one_of} when empty and allowed to be {@code []} for
 *       {@code subset_of}; {@code essential} is the logical OR.</li>
 *   <li><b>Combinations</b> (each operator's "Combination with other operators"): checked on every parsed
 *       and every merged parameter policy (§6.1.4.1), for example {@code add} ⊆ {@code value},
 *       {@code subset_of} ⊇ {@code superset_of}, and {@code one_of} alongside nothing but {@code value},
 *       {@code default} and {@code essential}. A combination that is not allowed is a policy error.</li>
 *   <li><b>Types</b>: the JSON types each operator is "Mandatory to support", plus numbers where they are
 *       "Optional to support". So {@code add}, {@code one_of}, {@code subset_of} and {@code superset_of}
 *       take arrays of strings or of numbers, and {@code one_of} checks a string or a number. Objects are
 *       optional everywhere but {@code essential} and are refused, as is any type an operator does not
 *       list - §6.1.3 makes an unsupported type a policy error, for the operand and the parameter alike.
 *       Numbers compare by value, so {@code 1} equals {@code 1.0}.</li>
 *   <li><b>{@code null}</b> is a value, not an absence: {@code value: null} removes the parameter, and
 *       no operator outputs a {@code null} parameter (§6.1.3).</li>
 *   <li><b>{@code scope}</b> is "regarded and processed as a string array" and written back as a
 *       space-separated string (§6.1.3.1.8).</li>
 *   <li><b>Additional operators</b> (§6.1.3.2) are ignored unless declared critical; this
 *       implementation understands none, so a non-empty {@code metadata_policy_crit} is always a policy
 *       error (§3.1.3).</li>
 * </ul>
 *
 * <p>Earlier revisions of this class quoted a sentence from §6.1.4.1 ordering the operators
 * {@code value, default, one_of, subset_of, superset_of, add, essential}. The Final text has no such
 * sentence; the order above is the one its operator definitions give. The two differ observably when
 * {@code default} and {@code add} both apply to an absent parameter.
 */
public final class MetadataPolicy {

    /** The standard operators. Anything else is an additional operator (§6.1.3.2). */
    public static final Set<String> KNOWN_OPERATORS =
            Set.of("value", "add", "default", "one_of", "subset_of", "superset_of", "essential");

    /** Application order, from each operator's "Order of application" in §6.1.3.1. */
    static final List<String> APPLICATION_ORDER =
            List.of("value", "add", "default", "one_of", "subset_of", "superset_of", "essential");

    /** The one metadata parameter operators treat as a string array although it is a string. */
    static final String SCOPE = "scope";

    /** An operator's configured value; {@code value} may be {@code null}, which is JSON null. */
    private record Operand(Object value) {
    }

    /** parameter name → (operator → operand), operators in the order they were declared */
    private final Map<String, Map<String, Operand>> byParameter;

    private MetadataPolicy(Map<String, Map<String, Operand>> byParameter) {
        this.byParameter = byParameter;
    }

    public static MetadataPolicy empty() {
        return new MetadataPolicy(Map.of());
    }

    /**
     * Reads a {@code metadata_policy} for one Entity Type.
     *
     * @param policy   the raw policy object, e.g. the value of {@code metadata_policy.openid_provider}
     * @param critical the additional operators declared critical anywhere in the chain
     *                 ({@code metadata_policy_crit}, collected first per §6.1.4.1), or null
     * @throws PolicyException when a critical operator is named (this implementation understands no
     *                         additional operators, and a standard one may not be listed), an operand has a
     *                         type the operator does not support, or the operators may not be combined
     */
    @SuppressWarnings("unchecked")
    public static MetadataPolicy parse(Map<String, Object> policy, Collection<String> critical)
            throws PolicyException {
        if (critical != null) {
            for (String operator : critical) {
                if (KNOWN_OPERATORS.contains(operator)) {
                    throw new PolicyException("metadata_policy_crit names the standard operator '" + operator
                            + "'; it may list only additional operators (OpenID Federation 1.0 §3.1.3)");
                }
                throw new PolicyException("metadata_policy_crit names an operator this implementation does not"
                        + " understand: " + operator + " - the statement and its trust chain are invalid (§3.1.3)");
            }
        }
        if (policy == null || policy.isEmpty()) {
            return empty();
        }
        Map<String, Map<String, Operand>> parsed = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : policy.entrySet()) {
            String parameter = entry.getKey();
            if (!(entry.getValue() instanceof Map)) {
                throw new PolicyException("metadata_policy entry '" + parameter + "' is not an object");
            }
            Map<String, Operand> operators = new LinkedHashMap<>();
            for (Map.Entry<String, Object> op : ((Map<String, Object>) entry.getValue()).entrySet()) {
                if (!KNOWN_OPERATORS.contains(op.getKey())) {
                    // §6.1.3.2: an additional operator that is not critical MUST be ignored.
                    continue;
                }
                Object operand = normalizeOperand(parameter, op.getKey(), op.getValue());
                checkOperandType(parameter, op.getKey(), operand);
                operators.put(op.getKey(), new Operand(operand));
            }
            checkCombinations(parameter, operators);
            if (!operators.isEmpty()) {
                parsed.put(parameter, operators);
            }
        }
        return new MetadataPolicy(parsed);
    }

    /**
     * Merges a subordinate's policy into this (superior) one, per §6.1.4.1: parameters only one side has
     * are copied; operators both sides have are merged by the operator's own rule; the result is checked
     * for allowed combinations.
     *
     * @throws PolicyException when an operator value merge is not allowed or the merged combination is not
     */
    public MetadataPolicy composeWith(MetadataPolicy subordinate) throws PolicyException {
        Objects.requireNonNull(subordinate, "subordinate");
        Map<String, Map<String, Operand>> composed = new LinkedHashMap<>();
        Set<String> parameters = new LinkedHashSet<>(this.byParameter.keySet());
        parameters.addAll(subordinate.byParameter.keySet());
        for (String parameter : parameters) {
            Map<String, Operand> superior = this.byParameter.get(parameter);
            Map<String, Operand> sub = subordinate.byParameter.get(parameter);
            if (superior == null) {
                composed.put(parameter, sub);
            } else if (sub == null) {
                composed.put(parameter, superior);
            } else {
                Map<String, Operand> merged = mergeOperators(parameter, superior, sub);
                checkCombinations(parameter, merged);
                composed.put(parameter, merged);
            }
        }
        return new MetadataPolicy(composed);
    }

    private static Map<String, Operand> mergeOperators(String parameter, Map<String, Operand> superior,
                                                       Map<String, Operand> subordinate) throws PolicyException {
        Map<String, Operand> out = new LinkedHashMap<>(superior);
        for (Map.Entry<String, Operand> entry : subordinate.entrySet()) {
            String operator = entry.getKey();
            Operand sub = entry.getValue();
            Operand sup = superior.get(operator);
            if (sup == null) {
                out.put(operator, sub);
                continue;
            }
            switch (operator) {
                case "value", "default" -> {
                    if (!jsonEquals(sup.value(), sub.value())) {
                        throw new PolicyException("policy conflict on '" + parameter + "." + operator
                                + "': the superior says " + sup.value() + ", the subordinate says " + sub.value()
                                + " (the values MUST be equal)");
                    }
                }
                case "add", "superset_of" -> out.put(operator, new Operand(union(list(sup), list(sub))));
                case "one_of" -> {
                    List<Object> intersection = intersect(list(sup), list(sub));
                    if (intersection.isEmpty()) {
                        throw new PolicyException("policy conflict on '" + parameter + ".one_of': the superior's and"
                                + " the subordinate's values do not overlap (an empty intersection MUST be an error)");
                    }
                    out.put(operator, new Operand(intersection));
                }
                case "subset_of" -> out.put(operator, new Operand(intersect(list(sup), list(sub))));
                default -> out.put(operator, new Operand((Boolean) sup.value() || (Boolean) sub.value()));
            }
        }
        return out;
    }

    /**
     * Applies this policy to an entity's metadata for its Entity Type (§6.1.4.2), operator by operator in
     * {@link #APPLICATION_ORDER}.
     *
     * @return the resolved metadata a relying party may act on
     * @throws PolicyException when the metadata violates the policy or has a type an operator does not
     *                         support - resolved metadata that is "illegal or otherwise incorrect ... MUST
     *                         NOT be used"
     */
    public Map<String, Object> apply(Map<String, Object> metadata) throws PolicyException {
        Map<String, Object> resolved = new LinkedHashMap<>(metadata == null ? Map.of() : metadata);
        for (Map.Entry<String, Map<String, Operand>> entry : this.byParameter.entrySet()) {
            String parameter = entry.getKey();
            Map<String, Operand> operators = entry.getValue();
            boolean scope = SCOPE.equals(parameter);
            boolean present = resolved.containsKey(parameter);
            if (present && resolved.get(parameter) == null) {
                throw new PolicyException("'" + parameter + "' is null, which no operator supports and metadata"
                        + " may not use (§5)");
            }
            Object current = present ? metadataValue(parameter, resolved.get(parameter)) : null;
            for (String operator : APPLICATION_ORDER) {
                Operand operand = operators.get(operator);
                if (operand == null) {
                    continue;
                }
                Object value = operand.value();
                switch (operator) {
                    case "value" -> {
                        requireScalarOrArray(parameter, operator, present, current);
                        if (value == null) {
                            present = false;
                            current = null;
                        } else {
                            present = true;
                            current = value;
                        }
                    }
                    case "add" -> {
                        if (!present) {
                            present = true;
                            current = new ArrayList<>(list(operand));
                        } else {
                            List<Object> values = requireArray(parameter, operator, current);
                            for (Object v : list(operand)) {
                                if (!containsJson(values, v)) {
                                    values.add(v);
                                }
                            }
                            current = values;
                        }
                    }
                    case "default" -> {
                        requireScalarOrArray(parameter, operator, present, current);
                        if (!present) {
                            present = true;
                            current = value;
                        }
                    }
                    case "one_of" -> {
                        if (present) {
                            if (!(current instanceof String) && !(current instanceof Number)) {
                                throw new PolicyException("'" + parameter + "' is not a string or a number, so one_of"
                                        + " cannot check it");
                            }
                            if (!containsJson(list(operand), current)) {
                                throw new PolicyException("'" + parameter + "' is " + current + ", which is not one_of "
                                        + value);
                            }
                        }
                    }
                    case "subset_of" -> {
                        if (present) {
                            current = intersect(requireArray(parameter, operator, current), list(operand));
                        }
                    }
                    case "superset_of" -> {
                        if (present && !containsAllJson(requireArray(parameter, operator, current), list(operand))) {
                            throw new PolicyException("'" + parameter + "' does not contain every value required by"
                                    + " superset_of " + value);
                        }
                    }
                    default -> {
                        if (Boolean.TRUE.equals(value) && !present) {
                            throw new PolicyException("'" + parameter + "' is essential but absent from the resolved"
                                    + " metadata");
                        }
                    }
                }
            }
            if (present) {
                resolved.put(parameter, scope ? joinScope(current) : current);
            } else {
                resolved.remove(parameter);
            }
        }
        return resolved;
    }

    /** The parameters this policy constrains. */
    public Set<String> parameters() {
        return Collections.unmodifiableSet(new LinkedHashSet<>(this.byParameter.keySet()));
    }

    /** The operators applying to one parameter, as JSON values ({@code null} for a {@code value: null}). */
    public Map<String, Object> operatorsFor(String parameter) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<String, Operand> op : this.byParameter.getOrDefault(parameter, Map.of()).entrySet()) {
            out.put(op.getKey(), op.getValue().value());
        }
        return Collections.unmodifiableMap(out);
    }

    /** The policy as the raw {@code metadata_policy.<type>} JSON structure. */
    public Map<String, Object> toRawMap() {
        Map<String, Object> out = new LinkedHashMap<>();
        for (String parameter : this.byParameter.keySet()) {
            out.put(parameter, this.operatorsFor(parameter));
        }
        return Collections.unmodifiableMap(out);
    }

    public boolean isEmpty() {
        return this.byParameter.isEmpty();
    }

    // ---- validation -----------------------------------------------------------------------------

    /** {@code scope} operands written as space-separated strings are read as arrays (§6.1.3.1.8). */
    private static Object normalizeOperand(String parameter, String operator, Object operand) {
        if (SCOPE.equals(parameter) && operand instanceof String s && !"essential".equals(operator)) {
            return splitScope(s);
        }
        return operand;
    }

    private static void checkOperandType(String parameter, String operator, Object operand) throws PolicyException {
        String at = "'" + parameter + "." + operator + "'";
        switch (operator) {
            case "value" -> {
                if (operand != null && !isScalar(operand) && !isScalarArray(operand)) {
                    throw new PolicyException(at + " must be a string, number, boolean, array or null");
                }
            }
            case "default" -> {
                if (operand == null || !isScalar(operand) && !isScalarArray(operand)) {
                    throw new PolicyException(at + " must be a string, number, boolean or array");
                }
            }
            case "essential" -> {
                if (!(operand instanceof Boolean)) {
                    throw new PolicyException(at + " must be a boolean");
                }
            }
            default -> {
                if (!isStringOrNumberArray(operand)) {
                    throw new PolicyException(at + " must be an array of strings or an array of numbers");
                }
            }
        }
    }

    /** The "Combination with other operators" rules of §6.1.3.1, on one parameter policy. */
    private static void checkCombinations(String parameter, Map<String, Operand> operators) throws PolicyException {
        Operand value = operators.get("value");
        Operand add = operators.get("add");
        Operand def = operators.get("default");
        Operand oneOf = operators.get("one_of");
        Operand subsetOf = operators.get("subset_of");
        Operand supersetOf = operators.get("superset_of");
        Operand essential = operators.get("essential");
        String at = "'" + parameter + "': ";
        if (oneOf != null && (add != null || subsetOf != null || supersetOf != null)) {
            throw new PolicyException(at + "one_of may be combined only with value, default and essential");
        }
        if (value != null) {
            if (add != null && (value.value() == null || !containsAllJson(valuesOf(value), list(add)))) {
                throw new PolicyException(at + "the values of add MUST be a subset of the values of value");
            }
            if (def != null && value.value() == null) {
                throw new PolicyException(at + "default may be combined with value only if value is not null");
            }
            if (oneOf != null && (value.value() == null || value.value() instanceof List
                    || !containsJson(list(oneOf), value.value()))) {
                throw new PolicyException(at + "the value of value MUST be among the one_of values");
            }
            if (subsetOf != null && (value.value() == null || !containsAllJson(list(subsetOf), valuesOf(value)))) {
                throw new PolicyException(at + "the values of value MUST be a subset of the values of subset_of");
            }
            if (supersetOf != null && (value.value() == null || !containsAllJson(valuesOf(value), list(supersetOf)))) {
                throw new PolicyException(at + "the values of value MUST be a superset of the values of superset_of");
            }
            if (essential != null && value.value() == null && Boolean.TRUE.equals(essential.value())) {
                throw new PolicyException(at + "value null may not be combined with essential true");
            }
        }
        if (add != null && subsetOf != null && !containsAllJson(list(subsetOf), list(add))) {
            throw new PolicyException(at + "the values of add MUST be a subset of the values of subset_of");
        }
        if (subsetOf != null && supersetOf != null && !containsAllJson(list(subsetOf), list(supersetOf))) {
            throw new PolicyException(at + "the values of subset_of MUST be a superset of the values of superset_of");
        }
    }

    // ---- helpers ------------------------------------------------------------------------------

    /** The metadata parameter as operators see it: {@code scope} split into an array. */
    private static Object metadataValue(String parameter, Object raw) {
        if (SCOPE.equals(parameter) && raw instanceof String s) {
            return splitScope(s);
        }
        return raw;
    }

    private static List<Object> splitScope(String scope) {
        List<Object> values = new ArrayList<>();
        for (String s : scope.trim().split("\\s+")) {
            if (!s.isEmpty() && !values.contains(s)) {
                values.add(s);
            }
        }
        return values;
    }

    private static Object joinScope(Object value) {
        if (!(value instanceof List<?> values)) {
            return value;
        }
        StringBuilder joined = new StringBuilder();
        for (Object v : values) {
            if (joined.length() > 0) {
                joined.append(' ');
            }
            joined.append(v);
        }
        return joined.toString();
    }

    private static List<Object> requireArray(String parameter, String operator, Object current) throws PolicyException {
        if (!isStringOrNumberArray(current)) {
            throw new PolicyException("'" + parameter + "' is not an array of strings or an array of numbers, which "
                    + operator + " requires");
        }
        return new ArrayList<>((List<?>) current);
    }

    /** {@code value} and {@code default} support a string, number, boolean or array parameter. */
    private static void requireScalarOrArray(String parameter, String operator, boolean present, Object current)
            throws PolicyException {
        if (present && !isScalar(current) && !(current instanceof List)) {
            throw new PolicyException("'" + parameter + "' is an object, which " + operator + " does not support");
        }
    }

    /** An array operator's operand, which {@link #checkOperandType} has already proved is an array. */
    @SuppressWarnings("unchecked")
    private static List<Object> list(Operand operand) {
        return (List<Object>) operand.value();
    }

    /** The values of a non-null {@code value} operand as a set: an array's members, or the scalar itself. */
    @SuppressWarnings("unchecked")
    private static List<Object> valuesOf(Operand operand) {
        return operand.value() instanceof List ? (List<Object>) operand.value() : List.of(operand.value());
    }

    private static boolean isScalar(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    private static boolean isScalarArray(Object value) {
        if (!(value instanceof List<?> values)) {
            return false;
        }
        for (Object v : values) {
            if (!(v instanceof String) && !(v instanceof Number) && !(v instanceof Boolean)) {
                return false;
            }
        }
        return true;
    }

    /** An array of strings or an array of numbers - the array types §6.1.3.1 lists; {@code []} is both. */
    private static boolean isStringOrNumberArray(Object value) {
        if (!(value instanceof List<?> values)) {
            return false;
        }
        boolean strings = true;
        boolean numbers = true;
        for (Object v : values) {
            strings &= v instanceof String;
            numbers &= v instanceof Number;
        }
        return strings || numbers;
    }

    private static List<Object> intersect(List<Object> a, List<Object> b) {
        List<Object> out = new ArrayList<>();
        for (Object v : a) {
            if (containsJson(b, v) && !containsJson(out, v)) {
                out.add(v);
            }
        }
        return out;
    }

    private static List<Object> union(List<Object> a, List<Object> b) {
        List<Object> out = new ArrayList<>();
        for (Object value : a) {
            if (!containsJson(out, value)) {
                out.add(value);
            }
        }
        for (Object value : b) {
            if (!containsJson(out, value)) {
                out.add(value);
            }
        }
        return out;
    }

    private static boolean containsJson(List<?> values, Object candidate) {
        for (Object v : values) {
            if (jsonEquals(v, candidate)) {
                return true;
            }
        }
        return false;
    }

    private static boolean containsAllJson(List<?> values, List<?> candidates) {
        for (Object candidate : candidates) {
            if (!containsJson(values, candidate)) {
                return false;
            }
        }
        return true;
    }

    /** JSON equality: numbers by value (a parser may give {@code 1} and {@code 1.0} different classes). */
    private static boolean jsonEquals(Object a, Object b) {
        if (a instanceof Number x && b instanceof Number y) {
            try {
                return new BigDecimal(x.toString()).compareTo(new BigDecimal(y.toString())) == 0;
            } catch (NumberFormatException notJson) {
                return x.equals(y); // NaN or an infinity, which no JSON document can carry
            }
        }
        if (a instanceof List<?> x && b instanceof List<?> y) {
            if (x.size() != y.size()) {
                return false;
            }
            for (int i = 0; i < x.size(); i++) {
                if (!jsonEquals(x.get(i), y.get(i))) {
                    return false;
                }
            }
            return true;
        }
        return Objects.equals(a, b);
    }

    /** A policy could not be composed, or metadata did not satisfy it. Always fail closed. */
    public static class PolicyException extends Exception {
        private static final long serialVersionUID = 1L;

        public PolicyException(String message) {
            super(message);
        }
    }
}
