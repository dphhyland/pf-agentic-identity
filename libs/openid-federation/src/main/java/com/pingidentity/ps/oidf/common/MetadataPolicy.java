/*
 * OpenID Federation metadata_policy: composition down a trust chain, and application to metadata.
 */
package com.pingidentity.ps.oidf.common;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * An OpenID Federation 1.0 {@code metadata_policy}, composed down a trust chain and applied to an
 * entity's metadata.
 *
 * <p>A policy narrows what a subordinate may be. Composition runs from the trust anchor downwards, and
 * the resulting policy is applied to the leaf's own metadata to produce the metadata a relying party
 * may actually act on. A bug that silently <em>widens</em> scope here is the worst outcome in this
 * subsystem, so every ambiguous case refuses instead.
 *
 * <h2>What is verified, and what is not</h2>
 *
 * <p>Verified against OpenID Federation 1.0 Final:
 * <ul>
 *   <li>the operator set — {@code value}, {@code add}, {@code default}, {@code one_of},
 *       {@code subset_of}, {@code superset_of}, {@code essential} (§6.1.3.1);</li>
 *   <li>the application order, quoted: <em>"The operators MUST be applied in this order: value,
 *       default, one_of, subset_of, superset_of, add, essential"</em> (§6.1.4.1) — note {@code add}
 *       runs near the end, not second;</li>
 *   <li>{@code metadata_policy_crit}: an unrecognised critical operator makes the subordinate
 *       statement invalid (§3.1.3).</li>
 * </ul>
 *
 * <p><strong>Not verified:</strong> the normative per-operator merge table in §6.1.4. Both published
 * renderings of the specification truncate before that section, so it could not be read. Rather than
 * guess it, {@link #composeWith} implements rules chosen to be <em>no more permissive than any
 * plausible reading</em>:
 *
 * <ul>
 *   <li>{@code one_of} and {@code subset_of} intersect — the only merge of two restrictions that
 *       narrows;</li>
 *   <li>{@code superset_of} unions — demanding more required values is stricter, not looser;</li>
 *   <li>{@code essential} is a logical OR — once a superior requires a parameter, a subordinate cannot
 *       drop it;</li>
 *   <li>{@code value} and {@code default} must be identical or the composition is refused;</li>
 *   <li>{@code add} is the genuinely ambiguous one: adding values to {@code grant_types} would widen
 *       while adding to {@code contacts} would not. A subordinate {@code add} is therefore accepted
 *       only when it is a subset of the superior's, and refused otherwise.</li>
 * </ul>
 *
 * <p>Where these are stricter than the specification the cost is availability — a chain is refused
 * that ought to resolve — which is recoverable. The opposite error is not. See
 * {@code docs/unverified.md}.
 */
public final class MetadataPolicy {

    /** Operators this implementation understands. Anything else is unknown. */
    public static final Set<String> KNOWN_OPERATORS =
            Set.of("value", "add", "default", "one_of", "subset_of", "superset_of", "essential");

    /**
     * Application order, quoted from §6.1.4.1. Deliberately a list rather than the declaration order of
     * a map: applying {@code add} before {@code subset_of} would let an added value escape the subset
     * check.
     */
    static final List<String> APPLICATION_ORDER =
            List.of("value", "default", "one_of", "subset_of", "superset_of", "add", "essential");

    /** parameter name → (operator → operand) */
    private final Map<String, Map<String, Object>> byParameter;

    private MetadataPolicy(Map<String, Map<String, Object>> byParameter) {
        this.byParameter = byParameter;
    }

    public static MetadataPolicy empty() {
        return new MetadataPolicy(Map.of());
    }

    /**
     * Reads a {@code metadata_policy} for one entity type.
     *
     * @param policy the raw policy object, e.g. the value of {@code metadata_policy.openid_provider}
     * @param critical the statement's {@code metadata_policy_crit}, or null
     * @throws PolicyException when a critical operator is not understood — §3.1.3 makes the statement
     *                         invalid, so this refuses rather than ignoring it
     */
    @SuppressWarnings("unchecked")
    public static MetadataPolicy parse(Map<String, Object> policy, Collection<String> critical)
            throws PolicyException {
        if (critical != null) {
            for (String operator : critical) {
                if (!KNOWN_OPERATORS.contains(operator)) {
                    throw new PolicyException("metadata_policy_crit names an operator this "
                            + "implementation does not understand: " + operator
                            + " — the subordinate statement is invalid");
                }
            }
        }
        if (policy == null || policy.isEmpty()) {
            return empty();
        }
        Map<String, Map<String, Object>> parsed = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : policy.entrySet()) {
            if (!(entry.getValue() instanceof Map)) {
                throw new PolicyException("metadata_policy entry '" + entry.getKey()
                        + "' is not an object");
            }
            parsed.put(entry.getKey(), new LinkedHashMap<>((Map<String, Object>) entry.getValue()));
        }
        return new MetadataPolicy(parsed);
    }

    /**
     * Composes this policy (from a superior) with a subordinate's, producing the policy that applies
     * further down the chain.
     *
     * <p>Composition can only narrow. Every rule below is chosen so the result constrains at least as
     * much as this policy does — see the class javadoc for which of them are verified.
     *
     * @throws PolicyException on any conflict, or any attempt by the subordinate to widen
     */
    public MetadataPolicy composeWith(MetadataPolicy subordinate) throws PolicyException {
        Objects.requireNonNull(subordinate, "subordinate");
        Map<String, Map<String, Object>> composed = new LinkedHashMap<>();
        Set<String> parameters = new LinkedHashSet<>(this.byParameter.keySet());
        parameters.addAll(subordinate.byParameter.keySet());

        for (String parameter : parameters) {
            Map<String, Object> superiorOps = this.byParameter.getOrDefault(parameter, Map.of());
            Map<String, Object> subordinateOps = subordinate.byParameter.getOrDefault(parameter, Map.of());
            composed.put(parameter, composeOperators(parameter, superiorOps, subordinateOps));
        }
        return new MetadataPolicy(composed);
    }

    private static Map<String, Object> composeOperators(String parameter, Map<String, Object> superior,
                                                        Map<String, Object> subordinate)
            throws PolicyException {
        Map<String, Object> out = new LinkedHashMap<>();
        Set<String> operators = new LinkedHashSet<>(superior.keySet());
        operators.addAll(subordinate.keySet());

        for (String operator : operators) {
            Object sup = superior.get(operator);
            Object sub = subordinate.get(operator);
            if (sup == null) {
                out.put(operator, sub);
                continue;
            }
            if (sub == null) {
                out.put(operator, sup);
                continue;
            }
            switch (operator) {
                case "value", "default" -> {
                    // A differing value from a subordinate is not a narrowing, it is a disagreement.
                    if (!Objects.equals(sup, sub)) {
                        throw new PolicyException("policy conflict on '" + parameter + "." + operator
                                + "': superior says " + sup + ", subordinate says " + sub);
                    }
                    out.put(operator, sup);
                }
                case "one_of", "subset_of" -> {
                    List<Object> intersection = intersect(asList(parameter, operator, sup),
                            asList(parameter, operator, sub));
                    if (intersection.isEmpty()) {
                        // Nothing satisfies both, so nothing may pass. Refuse rather than resolve to
                        // an empty restriction that some readings would treat as "unrestricted".
                        throw new PolicyException("policy conflict on '" + parameter + "." + operator
                                + "': the superior and subordinate restrictions do not overlap");
                    }
                    out.put(operator, intersection);
                }
                case "superset_of" -> out.put(operator, union(asList(parameter, operator, sup),
                        asList(parameter, operator, sub)));
                case "essential" -> out.put(operator, truthy(sup) || truthy(sub));
                case "add" -> {
                    // The ambiguous case. Adding to grant_types widens; adding to contacts does not.
                    // Accept a subordinate add only when it introduces nothing new.
                    List<Object> supValues = asList(parameter, operator, sup);
                    List<Object> subValues = asList(parameter, operator, sub);
                    if (!supValues.containsAll(subValues)) {
                        List<Object> extra = new ArrayList<>(subValues);
                        extra.removeAll(supValues);
                        throw new PolicyException("subordinate policy adds values to '" + parameter
                                + "' that the superior does not: " + extra
                                + " — a subordinate cannot widen a superior's policy");
                    }
                    out.put(operator, supValues);
                }
                default -> throw new PolicyException(
                        "unknown policy operator '" + operator + "' on '" + parameter + "'");
            }
        }
        return out;
    }

    /**
     * Applies the composed policy to an entity's metadata.
     *
     * @return the resolved metadata a relying party may act on
     * @throws PolicyException when the metadata violates the policy — an unmet policy must refuse,
     *                         never fall through with the offending value intact
     */
    public Map<String, Object> apply(Map<String, Object> metadata) throws PolicyException {
        Map<String, Object> resolved = new LinkedHashMap<>(metadata == null ? Map.of() : metadata);

        for (Map.Entry<String, Map<String, Object>> entry : this.byParameter.entrySet()) {
            String parameter = entry.getKey();
            Map<String, Object> operators = entry.getValue();

            for (String operator : APPLICATION_ORDER) {
                if (!operators.containsKey(operator)) {
                    continue;
                }
                Object operand = operators.get(operator);
                switch (operator) {
                    case "value" -> resolved.put(parameter, operand);
                    case "default" -> {
                        if (resolved.get(parameter) == null) {
                            resolved.put(parameter, operand);
                        }
                    }
                    case "one_of" -> {
                        Object current = resolved.get(parameter);
                        if (current != null && !asList(parameter, operator, operand).contains(current)) {
                            throw new PolicyException("'" + parameter + "' is " + current
                                    + ", which is not one_of " + operand);
                        }
                    }
                    case "subset_of" -> {
                        Object current = resolved.get(parameter);
                        if (current != null) {
                            List<Object> allowed = asList(parameter, operator, operand);
                            List<Object> present = asList(parameter, parameter, current);
                            List<Object> kept = new ArrayList<>(present);
                            kept.retainAll(allowed);
                            if (kept.isEmpty()) {
                                // Every value was disallowed. Leaving an empty array would let a caller
                                // read "no restrictions" from what is actually "nothing permitted".
                                throw new PolicyException("'" + parameter + "' retains no values after "
                                        + "subset_of " + operand);
                            }
                            resolved.put(parameter, kept);
                        }
                    }
                    case "superset_of" -> {
                        List<Object> required = asList(parameter, operator, operand);
                        Object current = resolved.get(parameter);
                        List<Object> present = current == null
                                ? List.of() : asList(parameter, parameter, current);
                        if (!present.containsAll(required)) {
                            throw new PolicyException("'" + parameter + "' does not contain every value "
                                    + "required by superset_of " + operand);
                        }
                    }
                    case "add" -> {
                        Object current = resolved.get(parameter);
                        List<Object> merged = new ArrayList<>(current == null
                                ? List.of() : asList(parameter, parameter, current));
                        for (Object value : asList(parameter, operator, operand)) {
                            if (!merged.contains(value)) {
                                merged.add(value);
                            }
                        }
                        resolved.put(parameter, merged);
                    }
                    case "essential" -> {
                        if (truthy(operand) && resolved.get(parameter) == null) {
                            throw new PolicyException("'" + parameter
                                    + "' is essential but absent from the resolved metadata");
                        }
                    }
                    default -> throw new PolicyException("unknown policy operator: " + operator);
                }
            }
        }
        return resolved;
    }

    /** The parameters this policy constrains. */
    public Set<String> parameters() {
        return Set.copyOf(this.byParameter.keySet());
    }

    /** The operators applying to one parameter, for inspection and tests. */
    public Map<String, Object> operatorsFor(String parameter) {
        return Map.copyOf(this.byParameter.getOrDefault(parameter, Map.of()));
    }

    public boolean isEmpty() {
        return this.byParameter.isEmpty();
    }

    // ---- helpers ------------------------------------------------------------------------------

    private static List<Object> asList(String parameter, String operator, Object value)
            throws PolicyException {
        if (value instanceof List) {
            return List.copyOf((List<?>) value);
        }
        if (value == null) {
            return List.of();
        }
        // A scalar where an array belongs: treat as a single value rather than rejecting, since
        // metadata frequently carries a lone string where the policy expects a list.
        if (!(value instanceof Map)) {
            return List.of(value);
        }
        throw new PolicyException("'" + parameter + "." + operator + "' expects an array, got an object");
    }

    private static List<Object> intersect(List<Object> a, List<Object> b) {
        List<Object> out = new ArrayList<>(a);
        out.retainAll(b);
        return out;
    }

    private static List<Object> union(List<Object> a, List<Object> b) {
        List<Object> out = new ArrayList<>(a);
        for (Object value : b) {
            if (!out.contains(value)) {
                out.add(value);
            }
        }
        return out;
    }

    private static boolean truthy(Object value) {
        return value instanceof Boolean b ? b : Boolean.parseBoolean(String.valueOf(value));
    }

    /** A policy could not be composed, or metadata did not satisfy it. Always fail closed. */
    public static class PolicyException extends Exception {
        private static final long serialVersionUID = 1L;

        public PolicyException(String message) {
            super(message);
        }
    }
}
